-- =============================================================================
-- MithraVPN database schema (MySQL 8.0.19+)
-- Edit with:   vi mithravpn_schema_mysql.sql
-- Load with:   mysql -u root -p < mithravpn_schema_mysql.sql
-- Events need: SET GLOBAL event_scheduler = ON;   (also set it in my.cnf)
-- All timestamps are stored in UTC.
--
-- Built from the MithraDNS database (accounts, credentials, sessions, devices,
-- app messages, app versions, Telegram bot tables) plus what a VPN needs:
--   * vpn_servers       one row per node; WireGuard API and/or Outline API
--   * vpn_clients       one WireGuard peer or one Outline key per account/server
--   * traffic           per-client byte counters, a daily rollup, per-account
--                       quota, and procedures that record and enforce usage
--   * countries         the country list the app shows (flag, Persian name)
--   * client_country_policy + connection_attempts
--                       how the app/backend picks WireGuard or Outline for a
--                       user's country and network (see sp_pick_protocol)
--
-- SECRETS: every *_enc column holds a value ENCRYPTED by the backend (never
-- plaintext, never a hash: the backend must decrypt it to call the node API or
-- to hand a config to the app). Never put real tokens in this file.
-- Passwords: only hashes are stored (account_credentials).
-- =============================================================================

SET NAMES utf8mb4;

CREATE DATABASE IF NOT EXISTS MithraVPN
    CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE MithraVPN;

SET time_zone = '+00:00';

-- =============================================================================
-- ACCOUNTS AND LOGIN
-- =============================================================================

-- -----------------------------------------------------------------------------
-- accounts: one row per customer (Telegram ID is optional: app-only accounts
-- are allowed). Subscription = access_until. Traffic quota = data_limit_bytes
-- per cycle; cycle_used_bytes is the usage in the current cycle.
-- -----------------------------------------------------------------------------
CREATE TABLE accounts (
    id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    telegram_id        BIGINT          NULL,
    username           VARCHAR(64)     NULL,
    email              VARCHAR(255)    NULL,
    status             ENUM('active','suspended','deleted') NOT NULL DEFAULT 'active',
    max_devices        INT UNSIGNED    NOT NULL DEFAULT 5,
    access_until       DATETIME        NULL,                -- subscription end; NULL = no expiry
    expiry_warned_for  DATETIME        NULL,                -- the access_until the "ends soon" notice was sent for
    expiry_ended_for   DATETIME        NULL,                -- the access_until the "ended" notice was sent for
    data_limit_bytes   BIGINT UNSIGNED NULL,                -- quota per cycle; NULL = unlimited
    cycle_days         INT UNSIGNED    NULL,                -- length of a cycle; NULL = reset only on renewal
    cycle_started_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cycle_used_bytes   BIGINT UNSIGNED NOT NULL DEFAULT 0,  -- bytes used in this cycle (rx + tx, all clients)
    total_used_bytes   BIGINT UNSIGNED NOT NULL DEFAULT 0,  -- lifetime bytes
    notes              TEXT            NULL,
    created_at         DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
                                       ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_accounts_telegram (telegram_id),
    UNIQUE KEY uq_accounts_email (email),
    UNIQUE KEY uq_accounts_username (username),
    CONSTRAINT chk_accounts_devices CHECK (max_devices > 0)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- account_credentials: one password hash per account
-- -----------------------------------------------------------------------------
CREATE TABLE account_credentials (
    account_id          BIGINT UNSIGNED NOT NULL,
    password_hash       VARCHAR(255)    NOT NULL,            -- full encoded hash string
    hash_algo           VARCHAR(16)     NOT NULL DEFAULT 'argon2id',
    must_change         TINYINT(1)      NOT NULL DEFAULT 0,  -- force reset at next login
    failed_attempts     INT UNSIGNED    NOT NULL DEFAULT 0,
    locked_until        DATETIME        NULL,
    last_login_at       DATETIME        NULL,
    password_changed_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id),
    CONSTRAINT fk_creds_account FOREIGN KEY (account_id)
        REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- countries: the list the app shows. code = ISO 3166-1 alpha-2 ('IR', 'TH').
-- Used twice: server location, and "where are you?" (client_country) which
-- decides the protocol. Edit the seed rows at the bottom of this file.
-- -----------------------------------------------------------------------------
CREATE TABLE countries (
    code        CHAR(2)      NOT NULL,
    name        VARCHAR(100) NOT NULL,
    name_fa     VARCHAR(100) NULL,
    flag_emoji  VARCHAR(16)  NULL,
    continent   VARCHAR(32)  NULL,
    sort_order  INT          NOT NULL DEFAULT 100,           -- lower = higher in the app list
    is_active   TINYINT(1)   NOT NULL DEFAULT 1,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (code)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- devices: phones/PCs that signed in. client_country = the country the user
-- picked in the app as "my location" (e.g. 'IR'); it drives protocol choice.
-- last_ip is stored packed (INET6_ATON); read it with INET6_NTOA(last_ip).
-- -----------------------------------------------------------------------------
CREATE TABLE devices (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    account_id      BIGINT UNSIGNED NOT NULL,
    name            VARCHAR(100)    NULL,                    -- 'Pixel 8'
    platform        ENUM('android','ios','windows','macos','linux','ubuntu') NULL,   -- same list as app_versions
    fingerprint     VARCHAR(128)    NOT NULL,                -- the app's install id
    client_country  CHAR(2)         NULL,
    last_ip         VARBINARY(16)   NULL,
    first_seen_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_devices_fp (account_id, fingerprint),
    KEY idx_devices_last_seen (last_seen_at),
    CONSTRAINT fk_devices_account FOREIGN KEY (account_id)
        REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT fk_devices_country FOREIGN KEY (client_country)
        REFERENCES countries(code) ON DELETE SET NULL
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- sessions: one app login. Only a hash of the token is stored.
-- -----------------------------------------------------------------------------
CREATE TABLE sessions (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    account_id    BIGINT UNSIGNED NOT NULL,
    device_id     BIGINT UNSIGNED NOT NULL,
    token_hash    BINARY(32)      NOT NULL,                  -- SHA-256 of the bearer token
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    DATETIME        NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_sessions_token (token_hash),
    KEY idx_sessions_account (account_id),
    KEY idx_sessions_device (device_id),
    KEY idx_sessions_expires (expires_at),
    CONSTRAINT fk_sessions_account FOREIGN KEY (account_id)
        REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT fk_sessions_device FOREIGN KEY (device_id)
        REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- =============================================================================
-- VPN SERVERS AND CLIENTS
-- =============================================================================

-- -----------------------------------------------------------------------------
-- vpn_servers: one node. A node can offer WireGuard, Outline, or both.
--
-- WireGuard node (the "secure WireGuard API"):
--     wg_api_url   = https://th.thai02dir.mithracorp.com   (POST /create, /remove)
--     wg_port      = 36102                                 (UDP port clients use)
--     wg_token_enc = the API bearer token, ENCRYPTED
-- Outline node (Outline Manager "apiUrl" + "certSha256"):
--     outline_api_url_enc = the apiUrl, ENCRYPTED (its path is a secret)
--     outline_cert_sha256 = pin for the node's self-signed certificate
--
-- public_host     = host or IP the tunnel/key connects to.
-- alt_public_host = optional second address (relay/CDN host) used when the
--                   user's country policy says use_alt_endpoint.
-- Never expose this table to the app: use v_app_servers.
-- -----------------------------------------------------------------------------
CREATE TABLE vpn_servers (
    id                   INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name                 VARCHAR(64)  NOT NULL,              -- internal, e.g. 'thai02dir'
    alias                VARCHAR(100) NULL,                  -- shown in the app, e.g. 'Bangkok 2'
    country_code         CHAR(2)      NOT NULL,
    city                 VARCHAR(64)  NULL,
    public_host          VARCHAR(255) NOT NULL,
    alt_public_host      VARCHAR(255) NULL,
    ip_address           VARBINARY(16) NULL,                 -- INET6_ATON
    dns                  VARCHAR(100) NOT NULL DEFAULT '1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4',

    wg_enabled           TINYINT(1)   NOT NULL DEFAULT 0,
    wg_api_url           VARCHAR(255) NULL,
    wg_port              SMALLINT UNSIGNED NULL,
    wg_token_enc         VARBINARY(512) NULL,

    outline_enabled      TINYINT(1)   NOT NULL DEFAULT 0,
    outline_api_url_enc  VARBINARY(1024) NULL,
    outline_cert_sha256  CHAR(64)     NULL,

    max_clients          INT UNSIGNED NULL,                  -- NULL = no cap
    status               ENUM('active','maintenance','full','disabled') NOT NULL DEFAULT 'active',
    last_seen_at         DATETIME     NULL,
    created_at           DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                      ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_vpn_servers_name (name),
    KEY idx_vpn_servers_country_status (country_code, status),
    CONSTRAINT fk_vpn_servers_country FOREIGN KEY (country_code)
        REFERENCES countries(code) ON DELETE RESTRICT,
    CONSTRAINT chk_vpn_servers_proto CHECK (wg_enabled = 1 OR outline_enabled = 1),
    CONSTRAINT chk_vpn_servers_wg CHECK (wg_enabled = 0 OR
        (wg_api_url IS NOT NULL AND wg_port IS NOT NULL AND wg_token_enc IS NOT NULL)),
    CONSTRAINT chk_vpn_servers_outline CHECK (outline_enabled = 0 OR
        (outline_api_url_enc IS NOT NULL AND outline_cert_sha256 IS NOT NULL))
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- vpn_clients: what the backend created on a node for an account:
-- one WireGuard peer (POST /create) or one Outline access key.
--
-- Traffic columns (the "usage" part):
--   rx_bytes / tx_bytes     bytes counted so far (rx = client -> server = upload,
--                           tx = server -> client = download). Only sp_record_usage
--                           should change them.
--   last_rx_snapshot / last_tx_snapshot
--                           the raw counter the node reported at the last poll.
--                           WireGuard counters restart from 0 when the interface
--                           restarts; the snapshot lets sp_record_usage add only
--                           the new bytes and survive that reset.
--   cycle_rx_bytes / cycle_tx_bytes
--                           the same counting, but only for the account's current
--                           traffic cycle. Adding them up over an account's clients
--                           equals accounts.cycle_used_bytes, which is what makes the
--                           "20 GB = 2 GB USA + 17 GB Sweden + 1 GB ..." breakdown
--                           (v_account_usage_by_server / _by_country) add up exactly.
--   max_data_limit          optional cap on this one client (lifetime bytes).
-- The account-wide quota lives on accounts (data_limit_bytes).
--
-- Protocol-specific data:
--   wireguard: wg_public_key, wg_address (client tunnel IP, also what /remove
--              needs as "ipAddress"), wg_config_enc (full client config incl.
--              private key, encrypted, so the app can fetch it again)
--   outline:   outline_key_id, outline_access_url_enc (the ss:// URL, encrypted)
-- -----------------------------------------------------------------------------
CREATE TABLE vpn_clients (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    account_id              BIGINT UNSIGNED NOT NULL,
    device_id               BIGINT UNSIGNED NULL,
    server_id               INT UNSIGNED    NOT NULL,
    protocol                ENUM('wireguard','outline') NOT NULL,
    label                   VARCHAR(100)    NULL,
    status                  ENUM('active','suspended','expired','revoked') NOT NULL DEFAULT 'active',
    suspend_reason          ENUM('admin','quota') NULL,       -- set while status = 'suspended'

    wg_public_key           CHAR(44)        NULL,
    wg_address              VARCHAR(45)     NULL,
    wg_config_enc           VARBINARY(4096) NULL,
    outline_key_id          VARCHAR(64)     NULL,
    outline_access_url_enc  VARBINARY(1024) NULL,

    rx_bytes                BIGINT UNSIGNED NOT NULL DEFAULT 0,
    tx_bytes                BIGINT UNSIGNED NOT NULL DEFAULT 0,
    total_bytes             BIGINT UNSIGNED GENERATED ALWAYS AS (rx_bytes + tx_bytes) STORED,
    cycle_rx_bytes          BIGINT UNSIGNED NOT NULL DEFAULT 0,   -- same, but only the current cycle
    cycle_tx_bytes          BIGINT UNSIGNED NOT NULL DEFAULT 0,   -- (reset with the account's cycle)
    last_rx_snapshot        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    last_tx_snapshot        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    max_data_limit          BIGINT UNSIGNED NULL,
    speed_limit_kbps        INT UNSIGNED    NULL,

    last_handshake          DATETIME        NULL,             -- WireGuard only
    last_poll_at            DATETIME        NULL,
    created_at              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at              DATETIME        NULL,             -- NULL = follows accounts.access_until
    revoked_at              DATETIME        NULL,
    notes                   TEXT            NULL,
    -- 1 while the client is in use (active/suspended/expired), NULL once revoked.
    -- Together with uq_clients_one_per_device it allows ONE live client per device,
    -- server and protocol: a WireGuard peer cannot be shared by two devices, so each
    -- Android / Windows / Ubuntu / Linux device of an account gets its own.
    is_live                 TINYINT(1)      GENERATED ALWAYS AS (IF(status = 'revoked', NULL, 1)) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_clients_one_per_device (device_id, server_id, protocol, is_live),
    UNIQUE KEY uq_clients_wg_key (wg_public_key),
    UNIQUE KEY uq_clients_wg_addr (server_id, wg_address),
    UNIQUE KEY uq_clients_outline_key (server_id, outline_key_id),
    KEY idx_clients_account (account_id),
    KEY idx_clients_device (device_id),
    KEY idx_clients_status_expiry (status, expires_at),
    KEY idx_clients_last_poll (last_poll_at),
    CONSTRAINT fk_clients_account FOREIGN KEY (account_id)
        REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT fk_clients_device FOREIGN KEY (device_id)
        REFERENCES devices(id) ON DELETE SET NULL,
    CONSTRAINT fk_clients_server FOREIGN KEY (server_id)
        REFERENCES vpn_servers(id) ON DELETE RESTRICT,
    CONSTRAINT chk_clients_protocol CHECK (
        (protocol = 'wireguard' AND wg_public_key IS NOT NULL AND wg_address IS NOT NULL)
     OR (protocol = 'outline'   AND outline_key_id IS NOT NULL))
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- traffic_daily: bytes per client per UTC day (kept; it is small). Written by
-- sp_record_usage. account_id is repeated here so per-account reports are cheap.
-- -----------------------------------------------------------------------------
CREATE TABLE traffic_daily (
    day         DATE            NOT NULL,
    client_id   BIGINT UNSIGNED NOT NULL,
    account_id  BIGINT UNSIGNED NOT NULL,
    server_id   INT UNSIGNED    NOT NULL,
    rx_bytes    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    tx_bytes    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (day, client_id),
    KEY idx_traffic_account_day (account_id, day),
    KEY idx_traffic_server_day (server_id, day),
    CONSTRAINT fk_traffic_client FOREIGN KEY (client_id)
        REFERENCES vpn_clients(id) ON DELETE CASCADE,
    CONSTRAINT fk_traffic_account FOREIGN KEY (account_id)
        REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT fk_traffic_server FOREIGN KEY (server_id)
        REFERENCES vpn_servers(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- client_country_policy: starting preference per user country (the country the
-- user picked in the app). preferred_protocol is tried first, fallback_protocol
-- is offered if it fails. use_alt_endpoint = connect to vpn_servers.alt_public_host
-- when the server has one. No row for a country = WireGuard first, Outline second.
-- sp_pick_protocol overrides this once connection_attempts has enough data.
-- -----------------------------------------------------------------------------
CREATE TABLE client_country_policy (
    country_code        CHAR(2)  NOT NULL,
    preferred_protocol  ENUM('wireguard','outline') NOT NULL,
    fallback_protocol   ENUM('wireguard','outline') NULL,
    use_alt_endpoint    TINYINT(1) NOT NULL DEFAULT 0,
    notes               VARCHAR(255) NULL,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                                 ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (country_code),
    CONSTRAINT fk_policy_country FOREIGN KEY (country_code)
        REFERENCES countries(code) ON DELETE CASCADE
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- connection_attempts: the app reports every connect try (worked or not). This
-- is how the system learns which protocol works from which country/network.
-- Kept 30 days (ev_nightly_cleanup).
-- -----------------------------------------------------------------------------
CREATE TABLE connection_attempts (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    account_id      BIGINT UNSIGNED NOT NULL,
    device_id       BIGINT UNSIGNED NULL,
    server_id       INT UNSIGNED    NOT NULL,
    protocol        ENUM('wireguard','outline') NOT NULL,
    client_country  CHAR(2)         NULL,
    platform        ENUM('android','ios','windows','macos','linux','ubuntu') NULL,   -- OS of the device that tried
    network_type    ENUM('wifi','mobile','ethernet','other') NULL,
    ok              TINYINT(1)      NOT NULL,
    error_code      VARCHAR(32)     NULL,                    -- 'timeout', 'handshake_failed', ...
    connect_ms      INT UNSIGNED    NULL,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_attempts_country_proto (client_country, protocol, created_at),
    KEY idx_attempts_server (server_id, created_at),
    KEY idx_attempts_created (created_at),
    CONSTRAINT fk_attempts_account FOREIGN KEY (account_id)
        REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT fk_attempts_device FOREIGN KEY (device_id)
        REFERENCES devices(id) ON DELETE SET NULL,
    CONSTRAINT fk_attempts_server FOREIGN KEY (server_id)
        REFERENCES vpn_servers(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- server_sync_log: audit AND work queue for calls to node APIs.
-- 'pending' rows are work for the backend:
--   create / remove   WireGuard: POST /create, POST /remove {"ipAddress"}
--                     Outline: create / delete access key
--   suspend / resume  written by sp_enforce_quota, sp_reset_cycle, sp_renew_account:
--                     the backend cuts or restores that client on the node
--                     (how is up to the backend: remove the peer, or set an
--                     Outline data limit of 0)
--   usage             poll of the node's counters -> sp_record_usage
-- -----------------------------------------------------------------------------
CREATE TABLE server_sync_log (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    server_id    INT UNSIGNED    NOT NULL,
    client_id    BIGINT UNSIGNED NULL,
    action       ENUM('create','remove','list','usage','suspend','resume') NOT NULL,
    result       ENUM('ok','failed','pending') NOT NULL DEFAULT 'pending',
    http_status  SMALLINT UNSIGNED NULL,
    error        TEXT            NULL,
    created_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_sync_server_ts (server_id, created_at),
    KEY idx_sync_pending (result, created_at),
    CONSTRAINT fk_sync_server FOREIGN KEY (server_id)
        REFERENCES vpn_servers(id) ON DELETE CASCADE,
    CONSTRAINT fk_sync_client FOREIGN KEY (client_id)
        REFERENCES vpn_clients(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- =============================================================================
-- APP MESSAGES AND VERSIONS (same as MithraDNS)
-- =============================================================================

-- app_messages: announcements shown in the app (pop-up / notification)
CREATE TABLE app_messages (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    title       VARCHAR(200)    NOT NULL,
    body        VARCHAR(2000)   NOT NULL,
    created_by  BIGINT UNSIGNED NULL,                        -- Telegram ID of the admin
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME        NOT NULL,
    PRIMARY KEY (id),
    KEY idx_app_messages_expires (expires_at)
) ENGINE=InnoDB;

-- app_message_receipts: which device already showed which message
CREATE TABLE app_message_receipts (
    message_id    BIGINT UNSIGNED NOT NULL,
    device_id     BIGINT UNSIGNED NOT NULL,
    channel       ENUM('popup','notification') NOT NULL,
    delivered_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (message_id, device_id),
    CONSTRAINT fk_receipts_message FOREIGN KEY (message_id)
        REFERENCES app_messages(id) ON DELETE CASCADE,
    CONSTRAINT fk_receipts_device FOREIGN KEY (device_id)
        REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- app_versions: newest app version per platform (drives "update available")
CREATE TABLE app_versions (
    platform      ENUM('android','ios','windows','macos','linux','ubuntu') NOT NULL,
    version       VARCHAR(32)     NOT NULL,
    download_url  VARCHAR(500)    NOT NULL DEFAULT '',
    notes         VARCHAR(1000)   NULL,
    updated_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
                                  ON UPDATE CURRENT_TIMESTAMP,
    updated_by    BIGINT UNSIGNED NULL,
    PRIMARY KEY (platform)
) ENGINE=InnoDB;

-- =============================================================================
-- TELEGRAM BOT TABLES (same shape as MithraDNS; telegram_payments adds DataGB)
-- =============================================================================

CREATE TABLE telegram_users (
    UserID        BIGINT UNSIGNED NOT NULL,
    FirstName     VARCHAR(100)    NULL,
    LastName      VARCHAR(100)    NULL,
    Username      VARCHAR(100)    NULL,
    LanguageCode  VARCHAR(10)     NULL,
    FirstSeenAt   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    LastSeenAt    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    IsBlocked     TINYINT(1)      NOT NULL DEFAULT 0,        -- the user blocked the bot
    BlockedAt     DATETIME        NULL,
    PRIMARY KEY (UserID),
    KEY idx_tgusers_blocked (IsBlocked)
) ENGINE=InnoDB;

CREATE TABLE telegram_admins (
    AdminID   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    UserID    BIGINT UNSIGNED NOT NULL,
    Username  VARCHAR(255)    NULL,
    Role      ENUM('superadmin','admin','moderator') NULL DEFAULT 'admin',
    AddedAt   TIMESTAMP       NULL DEFAULT CURRENT_TIMESTAMP,
    IsActive  TINYINT(1)      NULL DEFAULT 1,
    PRIMARY KEY (AdminID),
    UNIQUE KEY uq_tgadmins_user (UserID)
) ENGINE=InnoDB;

CREATE TABLE telegram_admin_log (
    LogID        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    AdminUserID  BIGINT UNSIGNED NOT NULL,
    Command      VARCHAR(64)     NOT NULL,
    Args         VARCHAR(1000)   NULL,
    CreatedAt    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (LogID),
    KEY idx_tgadminlog_created (CreatedAt)
) ENGINE=InnoDB;

CREATE TABLE telegram_broadcasts (
    BroadcastID   INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    AdminUserID   BIGINT UNSIGNED NOT NULL,
    Kind          ENUM('telegram','app','both') NOT NULL,
    Title         VARCHAR(200)    NULL,
    Message       TEXT            NOT NULL,
    Recipients    INT UNSIGNED    NOT NULL DEFAULT 0,
    Sent          INT UNSIGNED    NOT NULL DEFAULT 0,
    Unreachable   INT UNSIGNED    NOT NULL DEFAULT 0,
    Failed        INT UNSIGNED    NOT NULL DEFAULT 0,
    AppMessageID  BIGINT UNSIGNED NULL,
    CreatedAt     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FinishedAt    DATETIME        NULL,
    PRIMARY KEY (BroadcastID),
    KEY idx_tgbroadcasts_created (CreatedAt)
) ENGINE=InnoDB;

CREATE TABLE telegram_payments (
    PaymentID              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    UserID                 BIGINT UNSIGNED NULL,
    PaymentDate            DATE          NULL,
    PaymentMethod          VARCHAR(30)   NULL,
    DigitalCurrencyAmount  DECIMAL(20,8) NULL,
    Currency               VARCHAR(10)   NULL,
    AmountPaidInUSD        DECIMAL(10,2) NULL,
    CurrentRateToUSD       DECIMAL(20,8) NULL,
    Status                 TINYINT(1)    NULL,               -- 1 = successful, 0 = failed
    Comments               TEXT          NULL,
    OrderID                VARCHAR(64)   NULL,
    ProviderPaymentID      VARCHAR(64)   NULL,
    PayStatus              VARCHAR(20)   NOT NULL DEFAULT 'creating',
    Devices                TINYINT UNSIGNED NULL,
    Days                   INT UNSIGNED  NULL,
    DataGB                 INT UNSIGNED  NULL,               -- traffic bought per cycle; NULL = unlimited
    TelegramName           VARCHAR(100)  NULL,
    CreatedAt              DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt              DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
                                         ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (PaymentID),
    UNIQUE KEY uq_tgpay_order (OrderID),
    KEY idx_tgpay_user (UserID),
    KEY idx_tgpay_method (PaymentMethod),
    KEY idx_tgpay_provider (ProviderPaymentID)
) ENGINE=InnoDB;

-- =============================================================================
-- VIEWS
-- =============================================================================

-- v_app_servers: what the app may see (no tokens, no API addresses).
-- Usage: SELECT * FROM v_app_servers WHERE country_code = 'TH';
CREATE OR REPLACE VIEW v_app_servers AS
SELECT s.id, s.name, COALESCE(s.alias, s.name) AS display_name,
       s.country_code, c.name AS country_name, c.name_fa AS country_name_fa,
       c.flag_emoji, s.city, s.wg_enabled, s.outline_enabled, s.status
  FROM vpn_servers s
  JOIN countries   c ON c.code = s.country_code AND c.is_active = 1
 WHERE s.status IN ('active','full');

-- v_app_countries: the country list the app shows (only countries that have a
-- usable server). Usage: SELECT * FROM v_app_countries;
CREATE OR REPLACE VIEW v_app_countries AS
SELECT c.code, c.name, c.name_fa, c.flag_emoji, c.sort_order,
       COUNT(s.id) AS servers
  FROM countries c
  JOIN vpn_servers s ON s.country_code = c.code AND s.status = 'active'
 WHERE c.is_active = 1
 GROUP BY c.code, c.name, c.name_fa, c.flag_emoji, c.sort_order;

-- v_account_devices: "devices used of allowed" for the Profile page.
-- Usage: SELECT devices_used, max_devices FROM v_account_devices WHERE account_id = 1;
CREATE OR REPLACE VIEW v_account_devices AS
SELECT a.id AS account_id, a.username, a.status, a.max_devices,
       (SELECT COUNT(*) FROM devices d WHERE d.account_id = a.id) AS devices_used
  FROM accounts a;

-- v_account_usage: traffic numbers for the app and the bot.
-- Usage: SELECT * FROM v_account_usage WHERE account_id = 1;
CREATE OR REPLACE VIEW v_account_usage AS
SELECT a.id AS account_id, a.username, a.access_until,
       a.data_limit_bytes, a.cycle_used_bytes, a.total_used_bytes,
       a.cycle_started_at,
       IF(a.cycle_days IS NULL, NULL, a.cycle_started_at + INTERVAL a.cycle_days DAY) AS cycle_ends_at,
       IF(a.data_limit_bytes IS NULL, NULL,
          GREATEST(CAST(a.data_limit_bytes AS SIGNED) - CAST(a.cycle_used_bytes AS SIGNED), 0)) AS remaining_bytes,
       IF(a.data_limit_bytes IS NULL OR a.data_limit_bytes = 0, NULL,
          ROUND(a.cycle_used_bytes * 100 / a.data_limit_bytes, 1)) AS used_percent,
       (a.data_limit_bytes IS NOT NULL AND a.cycle_used_bytes >= a.data_limit_bytes) AS over_quota
  FROM accounts a;

-- v_account_usage_by_server: how much of an account's traffic went through each
-- server, this cycle and in total. The cycle numbers add up to
-- accounts.cycle_used_bytes.
-- Usage: SELECT server_name, country_name, cycle_bytes FROM v_account_usage_by_server
--         WHERE account_id = 1 ORDER BY cycle_bytes DESC;
CREATE OR REPLACE VIEW v_account_usage_by_server AS
SELECT c.account_id, s.id AS server_id, s.name AS server_name,
       COALESCE(s.alias, s.name) AS display_name,
       s.country_code, co.name AS country_name, co.name_fa AS country_name_fa, co.flag_emoji,
       SUM(c.cycle_rx_bytes) AS cycle_rx_bytes,
       SUM(c.cycle_tx_bytes) AS cycle_tx_bytes,
       SUM(c.cycle_rx_bytes + c.cycle_tx_bytes) AS cycle_bytes,
       SUM(c.rx_bytes + c.tx_bytes) AS lifetime_bytes
  FROM vpn_clients c
  JOIN vpn_servers s  ON s.id = c.server_id
  JOIN countries   co ON co.code = s.country_code
 GROUP BY c.account_id, s.id, s.name, s.alias, s.country_code, co.name, co.name_fa, co.flag_emoji;

-- v_account_usage_by_country: the same, summed per country (two servers in
-- Sweden show as one "Sweden" line) with each country's share of the cycle.
-- Usage: SELECT country_name, cycle_bytes, cycle_percent FROM v_account_usage_by_country
--         WHERE account_id = 1 ORDER BY cycle_bytes DESC;
CREATE OR REPLACE VIEW v_account_usage_by_country AS
SELECT u.account_id, u.country_code, u.country_name, u.country_name_fa, u.flag_emoji,
       SUM(u.cycle_bytes) AS cycle_bytes,
       SUM(u.lifetime_bytes) AS lifetime_bytes,
       IF(t.cycle_total = 0, 0, ROUND(SUM(u.cycle_bytes) * 100 / t.cycle_total, 1)) AS cycle_percent
  FROM v_account_usage_by_server u
  JOIN (SELECT account_id, SUM(cycle_bytes) AS cycle_total
          FROM v_account_usage_by_server GROUP BY account_id) t ON t.account_id = u.account_id
 GROUP BY u.account_id, u.country_code, u.country_name, u.country_name_fa, u.flag_emoji, t.cycle_total;

-- v_server_traffic_30d: total traffic per server over the last 30 days, all
-- customers (from traffic_daily). For capacity and cost planning.
-- Usage: SELECT * FROM v_server_traffic_30d ORDER BY total_bytes DESC;
CREATE OR REPLACE VIEW v_server_traffic_30d AS
SELECT s.id AS server_id, s.name, s.country_code,
       COALESCE(SUM(t.rx_bytes), 0) AS rx_bytes,
       COALESCE(SUM(t.tx_bytes), 0) AS tx_bytes,
       COALESCE(SUM(t.rx_bytes + t.tx_bytes), 0) AS total_bytes
  FROM vpn_servers s
  LEFT JOIN traffic_daily t ON t.server_id = s.id AND t.day >= UTC_DATE() - INTERVAL 29 DAY
 GROUP BY s.id, s.name, s.country_code;

-- v_server_load: clients and traffic per node (for admins and for "full" status).
-- Usage: SELECT * FROM v_server_load ORDER BY load_percent DESC;
CREATE OR REPLACE VIEW v_server_load AS
SELECT s.id AS server_id, s.name, s.country_code, s.city, s.status, s.max_clients,
       COUNT(c.id) AS clients,
       IF(s.max_clients IS NULL OR s.max_clients = 0, NULL, ROUND(COUNT(c.id) * 100 / s.max_clients, 1)) AS load_percent,
       COALESCE(SUM(c.rx_bytes), 0) AS rx_bytes,
       COALESCE(SUM(c.tx_bytes), 0) AS tx_bytes
  FROM vpn_servers s
  LEFT JOIN vpn_clients c ON c.server_id = s.id AND c.status = 'active'
 GROUP BY s.id, s.name, s.country_code, s.city, s.status, s.max_clients;

-- v_protocol_success: success rate of each protocol per user country, last 7 days.
-- Usage: SELECT * FROM v_protocol_success WHERE client_country = 'IR';
CREATE OR REPLACE VIEW v_protocol_success AS
SELECT client_country, protocol,
       COUNT(*) AS attempts,
       SUM(ok)  AS successes,
       ROUND(SUM(ok) * 100 / COUNT(*), 1) AS success_percent,
       ROUND(AVG(IF(ok = 1, connect_ms, NULL))) AS avg_connect_ms
  FROM connection_attempts
 WHERE created_at >= UTC_TIMESTAMP() - INTERVAL 7 DAY
   AND client_country IS NOT NULL
 GROUP BY client_country, protocol;

-- =============================================================================
-- FUNCTIONS AND PROCEDURES
-- =============================================================================
DELIMITER //

-- sp_touch_device(account_id, fingerprint, ip, platform, name, client_country)
-- Usage: CALL sp_touch_device(1, 'install_abc123', '203.0.113.7', 'android', 'Pixel 8', 'IR');
--        Upserts the device for the account (call it at login), bumps
--        last_seen_at, and stores the country the user picked. Returns the
--        device id; raises an error if the account is over its max_devices.
CREATE PROCEDURE sp_touch_device(IN p_account_id BIGINT UNSIGNED,
                                 IN p_fingerprint VARCHAR(128),
                                 IN p_ip VARCHAR(45),
                                 IN p_platform VARCHAR(16),
                                 IN p_name VARCHAR(100),
                                 IN p_client_country CHAR(2))
BEGIN
    DECLARE v_dev_id BIGINT UNSIGNED;
    DECLARE v_max    INT UNSIGNED;
    DECLARE v_count  INT;

    SELECT id INTO v_dev_id FROM devices
     WHERE account_id = p_account_id AND fingerprint = p_fingerprint;

    IF v_dev_id IS NULL THEN
        SELECT max_devices INTO v_max FROM accounts
         WHERE id = p_account_id AND status = 'active';
        IF v_max IS NULL THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Account not found or not active';
        END IF;
        SELECT COUNT(*) INTO v_count FROM devices WHERE account_id = p_account_id;
        IF v_count >= v_max THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Device limit reached';
        END IF;

        INSERT INTO devices (account_id, name, platform, fingerprint, client_country, last_ip)
        VALUES (p_account_id, p_name, p_platform, p_fingerprint, p_client_country, INET6_ATON(p_ip));
        SET v_dev_id = LAST_INSERT_ID();
    ELSE
        UPDATE devices
           SET last_seen_at   = UTC_TIMESTAMP(),
               last_ip        = INET6_ATON(p_ip),
               name           = COALESCE(p_name, name),
               client_country = COALESCE(p_client_country, client_country)
         WHERE id = v_dev_id;
    END IF;

    SELECT v_dev_id AS device_id;
END//

-- sp_pick_protocol(server_id, client_country)
-- Usage: CALL sp_pick_protocol(3, 'IR');
--        Decides WireGuard or Outline for a user in <client_country> on one
--        server. Order of rules:
--          1. the server offers only one protocol -> that one
--          2. the last 7 days of connection_attempts from that country have
--             >= 20 tries of BOTH protocols and the success rates differ by
--             >= 10 points -> the better one
--          3. client_country_policy.preferred_protocol
--          4. wireguard
--        Returns: protocol, fallback_protocol (the other one if the server has
--        it, else NULL), endpoint_host (alt_public_host when the policy says so
--        and the server has one), reason.
CREATE PROCEDURE sp_pick_protocol(IN p_server_id INT UNSIGNED, IN p_client_country CHAR(2))
BEGIN
    DECLARE v_wg      TINYINT;
    DECLARE v_ol      TINYINT;
    DECLARE v_host    VARCHAR(255);
    DECLARE v_alt     VARCHAR(255);
    DECLARE v_pref    VARCHAR(16);
    DECLARE v_use_alt TINYINT DEFAULT 0;
    DECLARE v_wg_n    INT DEFAULT 0;
    DECLARE v_ol_n    INT DEFAULT 0;
    DECLARE v_wg_rate DECIMAL(6,2) DEFAULT 0;
    DECLARE v_ol_rate DECIMAL(6,2) DEFAULT 0;
    DECLARE v_choice  VARCHAR(16);
    DECLARE v_reason  VARCHAR(32);

    SELECT wg_enabled, outline_enabled, public_host, alt_public_host
      INTO v_wg, v_ol, v_host, v_alt
      FROM vpn_servers WHERE id = p_server_id AND status = 'active';
    IF v_wg IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Server not found or not active';
    END IF;

    SELECT preferred_protocol, use_alt_endpoint INTO v_pref, v_use_alt
      FROM client_country_policy WHERE country_code = p_client_country;

    SELECT COUNT(*), COALESCE(SUM(ok) * 100 / COUNT(*), 0) INTO v_wg_n, v_wg_rate
      FROM connection_attempts
     WHERE client_country = p_client_country AND protocol = 'wireguard'
       AND created_at >= UTC_TIMESTAMP() - INTERVAL 7 DAY;
    SELECT COUNT(*), COALESCE(SUM(ok) * 100 / COUNT(*), 0) INTO v_ol_n, v_ol_rate
      FROM connection_attempts
     WHERE client_country = p_client_country AND protocol = 'outline'
       AND created_at >= UTC_TIMESTAMP() - INTERVAL 7 DAY;

    IF v_wg = 1 AND v_ol = 0 THEN
        SET v_choice = 'wireguard', v_reason = 'only_option';
    ELSEIF v_ol = 1 AND v_wg = 0 THEN
        SET v_choice = 'outline', v_reason = 'only_option';
    ELSEIF v_wg_n >= 20 AND v_ol_n >= 20 AND ABS(v_wg_rate - v_ol_rate) >= 10 THEN
        SET v_choice = IF(v_wg_rate > v_ol_rate, 'wireguard', 'outline'), v_reason = 'measured';
    ELSEIF v_pref IS NOT NULL THEN
        SET v_choice = v_pref, v_reason = 'country_policy';
    ELSE
        SET v_choice = 'wireguard', v_reason = 'default';
    END IF;

    SELECT v_choice AS protocol,
           IF(v_wg = 1 AND v_ol = 1, IF(v_choice = 'wireguard', 'outline', 'wireguard'), NULL) AS fallback_protocol,
           IF(v_use_alt = 1 AND v_alt IS NOT NULL, v_alt, v_host) AS endpoint_host,
           v_reason AS reason;
END//

-- sp_record_usage(client_id, raw_rx, raw_tx)
-- Usage: CALL sp_record_usage(42, 1830012, 99120334);
--        Call it every time the backend polls a node. Pass the node's CURRENT
--        cumulative counters for that client (WireGuard: transfer rx/tx from
--        `wg show`; Outline: the key's total bytes, passed as raw_tx with
--        raw_rx = 0). It adds only the new bytes since the previous poll
--        (a counter that went DOWN means the node restarted: the new value is
--        counted as new bytes), updates the client, today's traffic_daily row
--        and the account's cycle/lifetime totals, all in one transaction.
--        Returns: delta_rx, delta_tx, client_over_limit, account_over_quota.
--        When either flag is 1 the backend can call sp_enforce_quota() at once.
CREATE PROCEDURE sp_record_usage(IN p_client_id BIGINT UNSIGNED,
                                 IN p_raw_rx BIGINT UNSIGNED,
                                 IN p_raw_tx BIGINT UNSIGNED)
BEGIN
    DECLARE v_last_rx BIGINT UNSIGNED;
    DECLARE v_last_tx BIGINT UNSIGNED;
    DECLARE v_acc_id  BIGINT UNSIGNED;
    DECLARE v_srv_id  INT UNSIGNED;
    DECLARE v_d_rx    BIGINT UNSIGNED;
    DECLARE v_d_tx    BIGINT UNSIGNED;
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    START TRANSACTION;

    SELECT last_rx_snapshot, last_tx_snapshot, account_id, server_id
      INTO v_last_rx, v_last_tx, v_acc_id, v_srv_id
      FROM vpn_clients WHERE id = p_client_id FOR UPDATE;
    IF v_acc_id IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Client not found';
    END IF;

    IF p_raw_rx >= v_last_rx THEN SET v_d_rx = p_raw_rx - v_last_rx; ELSE SET v_d_rx = p_raw_rx; END IF;
    IF p_raw_tx >= v_last_tx THEN SET v_d_tx = p_raw_tx - v_last_tx; ELSE SET v_d_tx = p_raw_tx; END IF;

    UPDATE vpn_clients
       SET rx_bytes = rx_bytes + v_d_rx,
           tx_bytes = tx_bytes + v_d_tx,
           cycle_rx_bytes = cycle_rx_bytes + v_d_rx,
           cycle_tx_bytes = cycle_tx_bytes + v_d_tx,
           last_rx_snapshot = p_raw_rx,
           last_tx_snapshot = p_raw_tx,
           last_poll_at = UTC_TIMESTAMP()
     WHERE id = p_client_id;

    IF v_d_rx + v_d_tx > 0 THEN
        INSERT INTO traffic_daily (day, client_id, account_id, server_id, rx_bytes, tx_bytes)
        VALUES (UTC_DATE(), p_client_id, v_acc_id, v_srv_id, v_d_rx, v_d_tx)
        AS new
        ON DUPLICATE KEY UPDATE rx_bytes = traffic_daily.rx_bytes + new.rx_bytes,
                                tx_bytes = traffic_daily.tx_bytes + new.tx_bytes;

        UPDATE accounts
           SET cycle_used_bytes = cycle_used_bytes + v_d_rx + v_d_tx,
               total_used_bytes = total_used_bytes + v_d_rx + v_d_tx
         WHERE id = v_acc_id;
    END IF;

    COMMIT;

    SELECT v_d_rx AS delta_rx,
           v_d_tx AS delta_tx,
           (c.max_data_limit IS NOT NULL AND c.total_bytes >= c.max_data_limit) AS client_over_limit,
           (a.data_limit_bytes IS NOT NULL AND a.cycle_used_bytes >= a.data_limit_bytes) AS account_over_quota
      FROM vpn_clients c JOIN accounts a ON a.id = c.account_id
     WHERE c.id = p_client_id;
END//

-- sp_enforce_quota()
-- Usage: CALL sp_enforce_quota();   -- also runs every 5 minutes via ev_maintenance
--        Suspends every ACTIVE client whose account used up its cycle quota, or
--        that passed its own max_data_limit (status 'suspended', reason 'quota'),
--        and queues a 'suspend' row in server_sync_log for each so the backend
--        cuts it on the node. Returns how many clients were suspended.
CREATE PROCEDURE sp_enforce_quota()
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    START TRANSACTION;

    INSERT INTO server_sync_log (server_id, client_id, action)
    SELECT c.server_id, c.id, 'suspend'
      FROM vpn_clients c JOIN accounts a ON a.id = c.account_id
     WHERE c.status = 'active'
       AND ((a.data_limit_bytes IS NOT NULL AND a.cycle_used_bytes >= a.data_limit_bytes)
         OR (c.max_data_limit   IS NOT NULL AND c.total_bytes      >= c.max_data_limit));

    UPDATE vpn_clients c JOIN accounts a ON a.id = c.account_id
       SET c.status = 'suspended', c.suspend_reason = 'quota'
     WHERE c.status = 'active'
       AND ((a.data_limit_bytes IS NOT NULL AND a.cycle_used_bytes >= a.data_limit_bytes)
         OR (c.max_data_limit   IS NOT NULL AND c.total_bytes      >= c.max_data_limit));

    SELECT ROW_COUNT() AS suspended;
    COMMIT;
END//

-- sp_reset_cycle(account_id)
-- Usage: CALL sp_reset_cycle(1);
--        Starts a new traffic cycle: cycle_used_bytes = 0, and clients that were
--        suspended only because of quota are active again (a 'resume' row is
--        queued for the backend). Clients over their OWN max_data_limit stay
--        suspended. Returns how many clients were resumed.
CREATE PROCEDURE sp_reset_cycle(IN p_account_id BIGINT UNSIGNED)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    START TRANSACTION;

    UPDATE accounts
       SET cycle_used_bytes = 0, cycle_started_at = UTC_TIMESTAMP()
     WHERE id = p_account_id;
    UPDATE vpn_clients SET cycle_rx_bytes = 0, cycle_tx_bytes = 0 WHERE account_id = p_account_id;

    INSERT INTO server_sync_log (server_id, client_id, action)
    SELECT server_id, id, 'resume' FROM vpn_clients
     WHERE account_id = p_account_id AND status = 'suspended' AND suspend_reason = 'quota'
       AND (max_data_limit IS NULL OR total_bytes < max_data_limit);

    UPDATE vpn_clients
       SET status = 'active', suspend_reason = NULL
     WHERE account_id = p_account_id AND status = 'suspended' AND suspend_reason = 'quota'
       AND (max_data_limit IS NULL OR total_bytes < max_data_limit);

    SELECT ROW_COUNT() AS resumed;
    COMMIT;
END//

-- sp_roll_cycles()
-- Usage: CALL sp_roll_cycles();   -- also runs hourly via ev_roll_cycles
--        Resets every account whose cycle (cycle_days) has run out, the same
--        way sp_reset_cycle does. Returns how many accounts were reset.
CREATE PROCEDURE sp_roll_cycles()
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    START TRANSACTION;

    INSERT INTO server_sync_log (server_id, client_id, action)
    SELECT c.server_id, c.id, 'resume'
      FROM vpn_clients c JOIN accounts a ON a.id = c.account_id
     WHERE a.cycle_days IS NOT NULL
       AND a.cycle_started_at + INTERVAL a.cycle_days DAY <= UTC_TIMESTAMP()
       AND c.status = 'suspended' AND c.suspend_reason = 'quota'
       AND (c.max_data_limit IS NULL OR c.total_bytes < c.max_data_limit);

    UPDATE vpn_clients c JOIN accounts a ON a.id = c.account_id
       SET c.status = 'active', c.suspend_reason = NULL
     WHERE a.cycle_days IS NOT NULL
       AND a.cycle_started_at + INTERVAL a.cycle_days DAY <= UTC_TIMESTAMP()
       AND c.status = 'suspended' AND c.suspend_reason = 'quota'
       AND (c.max_data_limit IS NULL OR c.total_bytes < c.max_data_limit);

    UPDATE vpn_clients c JOIN accounts a ON a.id = c.account_id
       SET c.cycle_rx_bytes = 0, c.cycle_tx_bytes = 0
     WHERE a.cycle_days IS NOT NULL
       AND a.cycle_started_at + INTERVAL a.cycle_days DAY <= UTC_TIMESTAMP();

    UPDATE accounts
       SET cycle_used_bytes = 0, cycle_started_at = UTC_TIMESTAMP()
     WHERE cycle_days IS NOT NULL
       AND cycle_started_at + INTERVAL cycle_days DAY <= UTC_TIMESTAMP();

    SELECT ROW_COUNT() AS accounts_reset;
    COMMIT;
END//

-- sp_expire_clients()
-- Usage: CALL sp_expire_clients();   -- also runs every 5 minutes via ev_maintenance
--        Marks ACTIVE or SUSPENDED clients as 'expired' when their own
--        expires_at has passed, or (expires_at NULL) the account's access_until
--        has passed, and queues a 'suspend' row for the backend. Returns how many.
CREATE PROCEDURE sp_expire_clients()
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    START TRANSACTION;

    INSERT INTO server_sync_log (server_id, client_id, action)
    SELECT c.server_id, c.id, 'suspend'
      FROM vpn_clients c JOIN accounts a ON a.id = c.account_id
     WHERE c.status IN ('active','suspended')
       AND COALESCE(c.expires_at, a.access_until) IS NOT NULL
       AND COALESCE(c.expires_at, a.access_until) <= UTC_TIMESTAMP();

    UPDATE vpn_clients c JOIN accounts a ON a.id = c.account_id
       SET c.status = 'expired', c.suspend_reason = NULL
     WHERE c.status IN ('active','suspended')
       AND COALESCE(c.expires_at, a.access_until) IS NOT NULL
       AND COALESCE(c.expires_at, a.access_until) <= UTC_TIMESTAMP();

    SELECT ROW_COUNT() AS expired;
    COMMIT;
END//

-- sp_renew_account(account_id, days, data_limit_bytes)
-- Usage: CALL sp_renew_account(1, 30, 107374182400);   -- +30 days, 100 GiB
--        CALL sp_renew_account(1, 30, NULL);           -- +30 days, unlimited
--        What the bot runs after a successful payment: extends access_until
--        (from now, or from the current end if it is still in the future), sets
--        the quota, starts a fresh traffic cycle, and brings clients that were
--        'expired' (and not past their own expires_at) or quota-suspended back
--        to 'active' with a 'resume' row for the backend. Returns the new end date.
CREATE PROCEDURE sp_renew_account(IN p_account_id BIGINT UNSIGNED,
                                  IN p_days INT UNSIGNED,
                                  IN p_data_limit_bytes BIGINT UNSIGNED)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    IF NOT EXISTS (SELECT 1 FROM accounts WHERE id = p_account_id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Account not found';
    END IF;

    START TRANSACTION;

    UPDATE accounts
       SET access_until = GREATEST(COALESCE(access_until, UTC_TIMESTAMP()), UTC_TIMESTAMP())
                          + INTERVAL p_days DAY,
           data_limit_bytes = p_data_limit_bytes,
           cycle_days = p_days,
           cycle_used_bytes = 0,
           cycle_started_at = UTC_TIMESTAMP(),
           status = IF(status = 'deleted', status, 'active')
     WHERE id = p_account_id;
    UPDATE vpn_clients SET cycle_rx_bytes = 0, cycle_tx_bytes = 0 WHERE account_id = p_account_id;

    INSERT INTO server_sync_log (server_id, client_id, action)
    SELECT server_id, id, 'resume' FROM vpn_clients
     WHERE account_id = p_account_id
       AND ((status = 'expired' AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP()))
         OR (status = 'suspended' AND suspend_reason = 'quota'))
       AND (max_data_limit IS NULL OR total_bytes < max_data_limit);

    UPDATE vpn_clients
       SET status = 'active', suspend_reason = NULL
     WHERE account_id = p_account_id
       AND ((status = 'expired' AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP()))
         OR (status = 'suspended' AND suspend_reason = 'quota'))
       AND (max_data_limit IS NULL OR total_bytes < max_data_limit);

    COMMIT;

    SELECT access_until FROM accounts WHERE id = p_account_id;
END//

-- sp_set_password(account_id, hash, algo)
-- Usage: CALL sp_set_password(1, '$argon2id$v=19$m=65536,t=3,p=4$...', 'argon2id');
--        Creates or replaces the account's password hash, clears any lockout
--        and failed-attempt counter. The hash must be produced by the backend.
CREATE PROCEDURE sp_set_password(IN p_account_id BIGINT UNSIGNED,
                                 IN p_hash VARCHAR(255),
                                 IN p_algo VARCHAR(16))
BEGIN
    IF NOT EXISTS (SELECT 1 FROM accounts WHERE id = p_account_id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Account not found';
    END IF;

    INSERT INTO account_credentials (account_id, password_hash, hash_algo)
    VALUES (p_account_id, p_hash, COALESCE(p_algo, 'argon2id'))
    AS new
    ON DUPLICATE KEY UPDATE
        password_hash       = new.password_hash,
        hash_algo           = new.hash_algo,
        must_change         = 0,
        failed_attempts     = 0,
        locked_until        = NULL,
        password_changed_at = UTC_TIMESTAMP();

    SELECT ROW_COUNT() > 0 AS ok;
END//

-- sp_get_login(identifier)
-- Usage: CALL sp_get_login('test');   -- username or email
--        Returns account_id, status, password_hash, must_change and whether
--        the account is currently locked. Returns no rows if unknown, so the
--        backend should still run a dummy hash compare to avoid timing leaks.
CREATE PROCEDURE sp_get_login(IN p_identifier VARCHAR(255))
BEGIN
    SELECT a.id AS account_id,
           a.status,
           c.password_hash,
           c.hash_algo,
           c.must_change,
           (c.locked_until IS NOT NULL AND c.locked_until > UTC_TIMESTAMP()) AS is_locked
      FROM accounts a
      JOIN account_credentials c ON c.account_id = a.id
     WHERE (a.username = p_identifier OR a.email = p_identifier)
       AND a.status = 'active'
     LIMIT 1;
END//

-- sp_login_failed(account_id, max_attempts, lock_minutes)
-- Usage: CALL sp_login_failed(1, 5, 15);
--        Bumps the failed counter; once it reaches max_attempts the account is
--        locked for lock_minutes. Returns the new count and lock time.
CREATE PROCEDURE sp_login_failed(IN p_account_id BIGINT UNSIGNED,
                                 IN p_max_attempts INT,
                                 IN p_lock_minutes INT)
BEGIN
    UPDATE account_credentials
       SET failed_attempts = failed_attempts + 1,
           locked_until = IF(failed_attempts >= p_max_attempts,        -- MySQL applies SET left to right: this already sees the new count
                             UTC_TIMESTAMP() + INTERVAL p_lock_minutes MINUTE,
                             locked_until)
     WHERE account_id = p_account_id;

    SELECT failed_attempts, locked_until
      FROM account_credentials WHERE account_id = p_account_id;
END//

-- sp_login_ok(account_id)
-- Usage: CALL sp_login_ok(1);
--        Call after the backend verified the password. Resets the failed
--        counter and lock, and stamps last_login_at.
CREATE PROCEDURE sp_login_ok(IN p_account_id BIGINT UNSIGNED)
BEGIN
    UPDATE account_credentials
       SET failed_attempts = 0, locked_until = NULL,
           last_login_at = UTC_TIMESTAMP()
     WHERE account_id = p_account_id;
    SELECT ROW_COUNT() AS updated;
END//

-- =============================================================================
-- SCHEDULED EVENTS (require: SET GLOBAL event_scheduler = ON;)
-- =============================================================================

-- ev_maintenance: every 5 minutes, expire clients and enforce traffic quotas.
CREATE EVENT ev_maintenance
    ON SCHEDULE EVERY 5 MINUTE
    DO BEGIN
        CALL sp_expire_clients();
        CALL sp_enforce_quota();
    END//

-- ev_roll_cycles: hourly, start new traffic cycles that are due.
CREATE EVENT ev_roll_cycles
    ON SCHEDULE EVERY 1 HOUR
    DO CALL sp_roll_cycles()//

-- ev_nightly_cleanup: drops old sessions, connection attempts (30 days) and
-- finished sync rows (60 days).
CREATE EVENT ev_nightly_cleanup
    ON SCHEDULE EVERY 1 DAY STARTS (UTC_DATE() + INTERVAL 1 DAY + INTERVAL 5 MINUTE)
    DO BEGIN
        DELETE FROM sessions WHERE expires_at < UTC_TIMESTAMP();
        DELETE FROM connection_attempts WHERE created_at < UTC_TIMESTAMP() - INTERVAL 30 DAY;
        DELETE FROM server_sync_log
         WHERE result <> 'pending' AND created_at < UTC_TIMESTAMP() - INTERVAL 60 DAY;
    END//

DELIMITER ;

-- =============================================================================
-- STARTING DATA (edit freely)
-- =============================================================================

INSERT INTO countries (code, name, name_fa, flag_emoji, continent, sort_order) VALUES
('IR', 'Iran',           'ایران',      '🇮🇷', 'Asia',    10),
('TR', 'Turkey',         'ترکیه',      '🇹🇷', 'Asia',    20),
('TH', 'Thailand',       'تایلند',     '🇹🇭', 'Asia',    30),
('AE', 'United Arab Emirates', 'امارات', '🇦🇪', 'Asia',  40),
('DE', 'Germany',        'آلمان',      '🇩🇪', 'Europe',  50),
('NL', 'Netherlands',    'هلند',       '🇳🇱', 'Europe',  60),
('GB', 'United Kingdom', 'بریتانیا',   '🇬🇧', 'Europe',  70),
('FR', 'France',         'فرانسه',     '🇫🇷', 'Europe',  80),
('SE', 'Sweden',         'سوئد',       '🇸🇪', 'Europe',  90),
('FI', 'Finland',        'فنلاند',     '🇫🇮', 'Europe', 100),
('US', 'United States',  'آمریکا',     '🇺🇸', 'North America', 110),
('CA', 'Canada',         'کانادا',     '🇨🇦', 'North America', 120),
('JP', 'Japan',          'ژاپن',       '🇯🇵', 'Asia',   130),
('SG', 'Singapore',      'سنگاپور',    '🇸🇬', 'Asia',   140);

-- A starting guess only: users in Iran try Outline first and fall back to
-- WireGuard, and use the alternate endpoint when a server has one. Once
-- connection_attempts has data, sp_pick_protocol follows the measured results.
INSERT INTO client_country_policy (country_code, preferred_protocol, fallback_protocol, use_alt_endpoint, notes)
VALUES ('IR', 'outline', 'wireguard', 1, 'starting guess: tune from v_protocol_success');

INSERT INTO app_versions (platform, version) VALUES
('android', '1.0.0'), ('windows', '1.0.0'), ('ubuntu', '1.0.0'), ('linux', '1.0.0');

-- -----------------------------------------------------------------------------
-- Example: adding a node (run from your backend so it can ENCRYPT the secrets;
-- <encrypted ...> stands for the encrypted bytes, never the plain token).
--
-- INSERT INTO vpn_servers
--   (name, alias, country_code, city, public_host, wg_enabled, wg_api_url, wg_port, wg_token_enc,
--    outline_enabled, outline_api_url_enc, outline_cert_sha256, max_clients)
-- VALUES
--   ('thai02dir', 'Bangkok 2', 'TH', 'Bangkok', 'th.thai02dir.mithracorp.com',
--    1, 'https://th.thai02dir.mithracorp.com', 36102, <encrypted bearer token>,
--    1, <encrypted outline apiUrl>, '<64 hex chars, certSha256 from Outline>', 500);
-- -----------------------------------------------------------------------------
