-- =============================================================================
-- LAN Atlas — PostgreSQL Production Schema
-- Version : 2.0
-- Migrated from : SQLite schema v1.3
-- Authors  : Raul, D, Sam
-- Created  : 2026-05-06  |  PG migration: 2026-05-30
-- Standards: OWASP ASVS v4 (V2–V5), OWASP Top 10 2021, NIST SP 800-53 rev5
-- =============================================================================
-- Migration notes vs SQLite v1.3:
--   [FIX-6.1] Removed invalid self-referencing FK from alert_type
--   [FIX-6.2] Removed trailing comma from alerts
--   [FIX-6.3] Resolved agents.id / observations.agent_id type mismatch (both INT)
--   [FIX-6.4] Added FK enforcement for organization_id across all tables
--   [CHANGE]  TEXT → VARCHAR with explicit length limits (OWASP A03 / injection surface)
--   [CHANGE]  REAL confidence scores → SMALLINT 0–100 (eliminates float drift)
--   [CHANGE]  ENUM → VARCHAR + named CHECK constraints (portable, auditable)
--   [CHANGE]  password_hash removed; replaced by third-party OAuth provider fields
--   [CHANGE]  ON UPDATE CURRENT_TIMESTAMP removed (PG uses triggers — see bottom)
--   [ADD]     network_segments lookup table; observations.network_segment_id FK
--   [ADD]     device_mac_addresses table (from schema reference §4.7)
--   [ADD]     device_fingerprint_signals table (from schema reference §4.8)
--   [ADD]     sessions table (OWASP A07 — server-side session revocation)
--   [ADD]     services table preserved and renamed/aligned with schema reference
--   [ADD]     Partial indexes (open alerts, unresolved observations)
--   [ADD]     updated_at trigger function applied to all mutable tables
-- =============================================================================

-- ---------------------------------------------------------------------------
-- EXTENSIONS
-- ---------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid(), digest()
CREATE EXTENSION IF NOT EXISTS "citext";     -- case-insensitive email storage

-- ---------------------------------------------------------------------------
-- SHARED TRIGGER FUNCTION — maintains updated_at on every write
-- Replaces MySQL ON UPDATE CURRENT_TIMESTAMP (not available in PostgreSQL)
-- OWASP ASVS V1.2.1 — audit trail integrity
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION fn_set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

-- =============================================================================
-- TENANT & ACCESS GROUP
-- Tables: organization, users, sessions, sites
-- =============================================================================

-- ---------------------------------------------------------------------------
-- organization
-- Root tenant entity. Every operational table traces back here via organization_id.
-- Introduced in v1.2 to formalize multi-tenancy.
-- OWASP A01 — Broken Access Control: structural tenant isolation
-- ---------------------------------------------------------------------------

CREATE TABLE organization (
    id              SERIAL          PRIMARY KEY,
    slug            VARCHAR(100)    NOT NULL,
    is_active       BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_organization_slug UNIQUE (slug),
    CONSTRAINT ck_organization_slug_format
        CHECK (slug ~ '^[a-z0-9\-]+$')         -- URL-safe: lowercase, digits, hyphens only
);

CREATE TRIGGER trg_organization_updated_at
    BEFORE UPDATE ON organization
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

-- ---------------------------------------------------------------------------
-- users
-- Human operator within an organization. Third-party OAuth replaces password_hash.
-- The oauth_provider + oauth_subject pair is the authoritative identity anchor.
-- OWASP A02 — Cryptographic Failures: no secrets stored in this table
-- OWASP A07 — Auth Failures: roles enforced by named CHECK; lockout tracked
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id                  SERIAL          PRIMARY KEY,
    organization_id     INTEGER         NOT NULL,
    email               CITEXT          NOT NULL,           -- case-insensitive, normalized at write
    first_name          VARCHAR(100),
    last_name           VARCHAR(100),

    -- Third-party authentication (OAuth 2.0 / OIDC)
    -- provider examples: 'google', 'microsoft', 'github', 'okta'
    -- oauth_subject is the provider's stable 'sub' claim — never changes on re-auth
    oauth_provider      VARCHAR(50)     NOT NULL,
    oauth_subject       VARCHAR(255)    NOT NULL,           -- provider-issued stable ID

    user_role           VARCHAR(20)     NOT NULL DEFAULT 'viewer',
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,

    -- Audit / session hygiene
    last_login_at       TIMESTAMPTZ,
    failed_login_count  SMALLINT        NOT NULL DEFAULT 0, -- OWASP A07: brute-force tracking
    lockout_until       TIMESTAMPTZ,                        -- set by auth layer after N failures

    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_users_organization
        FOREIGN KEY (organization_id) REFERENCES organization(id)
        ON DELETE RESTRICT,

    CONSTRAINT uq_users_email_org
        UNIQUE (organization_id, email),                    -- email unique within tenant

    CONSTRAINT uq_users_oauth
        UNIQUE (oauth_provider, oauth_subject),             -- prevents duplicate identity linking

    CONSTRAINT ck_users_role
        CHECK (user_role IN ('admin', 'analyst', 'viewer')),

    CONSTRAINT ck_users_failed_login_count
        CHECK (failed_login_count >= 0)
);

CREATE INDEX idx_users_org ON users (organization_id);
CREATE INDEX idx_users_email ON users (email);

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

COMMENT ON COLUMN users.oauth_provider IS
    'Identity provider name: google | microsoft | github | okta. Never store passwords here.';
COMMENT ON COLUMN users.oauth_subject IS
    'Stable sub claim from the OAuth/OIDC provider. Survives email changes.';
COMMENT ON COLUMN users.failed_login_count IS
    'Incremented by the auth layer on failed attempts. Reset on successful login. OWASP A07.';

-- ---------------------------------------------------------------------------
-- sessions
-- Server-side session record enabling explicit revocation.
-- Satisfies OWASP ASVS V3.3 — session termination.
-- Tokens are stored as SHA-256 hashes only — plain tokens are never persisted.
-- ---------------------------------------------------------------------------

CREATE TABLE sessions (
    id              SERIAL          PRIMARY KEY,
    user_id         INTEGER         NOT NULL,
    token_hash      VARCHAR(64)     NOT NULL,   -- hex-encoded SHA-256 of the opaque bearer token
    expires_at      TIMESTAMPTZ     NOT NULL,
    revoked_at      TIMESTAMPTZ,                -- NULL = active; non-NULL = revoked
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_sessions_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_sessions_token_hash
        UNIQUE (token_hash)
);

CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_token ON sessions (token_hash);

COMMENT ON TABLE sessions IS
    'Server-side session store. Enables revocation on logout, role change, or deprovisioning. OWASP ASVS V3.3.';

-- ---------------------------------------------------------------------------
-- sites
-- Physical or logical network location within an organization.
-- Includes business-hours config for the missing-device alert engine.
-- ---------------------------------------------------------------------------

CREATE TABLE sites (
    id                      SERIAL          PRIMARY KEY,
    organization_id         INTEGER         NOT NULL,
    site_name               VARCHAR(150)    NOT NULL,
    site_location           VARCHAR(255),                   -- free-text description
    timezone                VARCHAR(64)     NOT NULL DEFAULT 'UTC',     -- IANA tz string
    business_hours_start    SMALLINT        NOT NULL DEFAULT 9,         -- 0–23 hour
    business_hours_end      SMALLINT        NOT NULL DEFAULT 17,        -- 0–23 hour
    business_days           VARCHAR(20)     NOT NULL DEFAULT '1,2,3,4,5', -- ISO weekdays
    is_active               BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_sites_organization
        FOREIGN KEY (organization_id) REFERENCES organization(id)
        ON DELETE RESTRICT,

    CONSTRAINT uq_sites_name_per_org
        UNIQUE (organization_id, site_name),

    CONSTRAINT ck_sites_biz_hours_start
        CHECK (business_hours_start BETWEEN 0 AND 23),

    CONSTRAINT ck_sites_biz_hours_end
        CHECK (business_hours_end BETWEEN 0 AND 23),

    CONSTRAINT ck_sites_biz_hours_order
        CHECK (business_hours_end > business_hours_start)
);

CREATE INDEX idx_sites_org ON sites (organization_id);

CREATE TRIGGER trg_sites_updated_at
    BEFORE UPDATE ON sites
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

-- =============================================================================
-- NETWORK TOPOLOGY GROUP
-- Tables: network_segments
-- New in v2.0 — lookup table for subnets and VLANs referenced by observations
-- =============================================================================

-- ---------------------------------------------------------------------------
-- network_segments
-- Authoritative lookup of known subnets and VLANs within a site.
-- observations.network_segment_id FK replaces the free-text network_segment column.
-- This enables structured queries ("show all devices on VLAN 20") and prevents
-- free-text drift across agent submissions.
-- OWASP A03 — Injection: structured FK prevents arbitrary strings entering the pipeline
-- ---------------------------------------------------------------------------

CREATE TABLE network_segments (
    id              SERIAL          PRIMARY KEY,
    organization_id INTEGER         NOT NULL,
    site_id         INTEGER         NOT NULL,
    cidr            VARCHAR(43)     NOT NULL,   -- e.g. '192.168.1.0/24' or 'fd00::/8'
    vlan_id         SMALLINT,                   -- 802.1Q VLAN tag (1–4094). NULL = untagged
    segment_name    VARCHAR(100),               -- human label, e.g. 'Corporate LAN', 'IoT VLAN'
    description     VARCHAR(300),
    is_active       BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_network_segments_organization
        FOREIGN KEY (organization_id) REFERENCES organization(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_network_segments_site
        FOREIGN KEY (site_id) REFERENCES sites(id)
        ON DELETE RESTRICT,

    CONSTRAINT uq_network_segments_cidr_per_site
        UNIQUE (site_id, cidr),

    CONSTRAINT ck_network_segments_vlan_range
        CHECK (vlan_id IS NULL OR vlan_id BETWEEN 1 AND 4094),

    CONSTRAINT ck_network_segments_cidr_format
        CHECK (cidr ~ '^[\da-fA-F:./]+$')      -- basic sanity; full validation in app layer
);

CREATE INDEX idx_network_segments_site ON network_segments (organization_id, site_id);

CREATE TRIGGER trg_network_segments_updated_at
    BEFORE UPDATE ON network_segments
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

COMMENT ON TABLE network_segments IS
    'Lookup table of known subnets and VLANs per site. Replaces free-text network_segment on observations.';
COMMENT ON COLUMN network_segments.vlan_id IS
    '802.1Q VLAN tag (1–4094). NULL indicates an untagged or unknown segment.';

-- =============================================================================
-- NETWORK AGENTS GROUP
-- Table: agents
-- =============================================================================

-- ---------------------------------------------------------------------------
-- agents
-- On-premises scanning agent installed at a site.
-- api_key_hash: SHA-256 of the secret API key — the plain-text key is never stored.
-- token_version: incremented on rotation to invalidate old keys without reissuing.
-- OWASP A02 — Cryptographic Failures: hashed credential storage only
-- ---------------------------------------------------------------------------

CREATE TABLE agents (
    id              SERIAL          PRIMARY KEY,
    site_id         INTEGER         NOT NULL,
    agent_name      VARCHAR(100),
    api_key_hash    VARCHAR(64)     NOT NULL,   -- hex SHA-256 of the secret API key
    token_version   SMALLINT        NOT NULL DEFAULT 1,
    last_seen       TIMESTAMPTZ,
    is_active       BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_agents_site
        FOREIGN KEY (site_id) REFERENCES sites(id)
        ON DELETE RESTRICT,

    CONSTRAINT ck_agents_token_version
        CHECK (token_version >= 1)
);

CREATE INDEX idx_agents_site ON agents (site_id);

CREATE TRIGGER trg_agents_updated_at
    BEFORE UPDATE ON agents
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

COMMENT ON COLUMN agents.api_key_hash IS
    'Hex-encoded SHA-256 of the secret API key. Plain-text keys are never stored. OWASP A02.';
COMMENT ON COLUMN agents.token_version IS
    'Incremented on rotation. The auth layer rejects tokens whose version is less than this value.';

-- =============================================================================
-- DEVICE IDENTITY GROUP
-- Tables: devices, device_mac_addresses, device_fingerprint_signals
-- =============================================================================

-- ---------------------------------------------------------------------------
-- devices
-- Represents a resolved physical device. One row per physical device per site.
-- Identity is anchored to fingerprint_hash, not IP or MAC — both change over time.
-- UNIQUE(organization_id, site_id, fingerprint_hash) prevents duplicate identity rows.
-- identity_strength: 0–100 integer replacing REAL to eliminate float drift.
-- ---------------------------------------------------------------------------

CREATE TABLE devices (
    id                          SERIAL          PRIMARY KEY,
    organization_id             INTEGER         NOT NULL,
    site_id                     INTEGER         NOT NULL,
    fingerprint_hash            VARCHAR(64),                -- SHA-256 of normalized identity signals
    primary_mac                 VARCHAR(17),                -- informational: most recent MAC seen
    vendor_name                 VARCHAR(100),               -- OUI lookup result
    friendly_name               VARCHAR(150),               -- user-assigned display name
    device_type                 VARCHAR(30)     NOT NULL DEFAULT 'unknown',
    classification_source       VARCHAR(20),
    first_seen                  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_seen                   TIMESTAMPTZ,
    seen_count                  INTEGER         NOT NULL DEFAULT 0,
    missing_threshold_hours     SMALLINT        NOT NULL DEFAULT 24,
    identity_strength           SMALLINT        NOT NULL DEFAULT 0,  -- 0–100; replaces REAL
    is_authorized               BOOLEAN         NOT NULL DEFAULT FALSE,
    created_at                  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_devices_organization
        FOREIGN KEY (organization_id) REFERENCES organization(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_devices_site
        FOREIGN KEY (site_id) REFERENCES sites(id)
        ON DELETE RESTRICT,

    CONSTRAINT uq_devices_fingerprint_per_site
        UNIQUE (organization_id, site_id, fingerprint_hash),

    CONSTRAINT ck_devices_identity_strength_range
        CHECK (identity_strength BETWEEN 0 AND 100),

    CONSTRAINT ck_devices_seen_count
        CHECK (seen_count >= 0),

    CONSTRAINT ck_devices_missing_threshold
        CHECK (missing_threshold_hours > 0),

    CONSTRAINT ck_devices_type
        CHECK (device_type IN (
            'router', 'switch', 'access_point', 'server',
            'workstation', 'mobile', 'printer', 'iot', 'unknown'
        )),

    CONSTRAINT ck_devices_classification_source
        CHECK (classification_source IS NULL OR classification_source IN (
            'MANUAL', 'OUI', 'PORT_PROFILE', 'SNMP', 'WMI'
        ))
);

CREATE INDEX idx_devices_org_site        ON devices (organization_id, site_id);
CREATE INDEX idx_devices_fingerprint     ON devices (fingerprint_hash);
CREATE INDEX idx_devices_last_seen       ON devices (site_id, last_seen DESC);

CREATE TRIGGER trg_devices_updated_at
    BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

COMMENT ON COLUMN devices.identity_strength IS
    'Aggregate signal confidence 0–100. SMALLINT replaces REAL to eliminate float comparison drift.';
COMMENT ON COLUMN devices.fingerprint_hash IS
    'SHA-256 of normalized identity signals at device creation. UNIQUE per (org, site).';

-- ---------------------------------------------------------------------------
-- device_mac_addresses
-- Full history of every MAC ever observed for a device.
-- primary_mac on devices is informational; this table is the authoritative record.
-- A device may accumulate MACs from NIC replacement, VM cloning, or dual NICs.
-- ---------------------------------------------------------------------------

CREATE TABLE device_mac_addresses (
    id          SERIAL          PRIMARY KEY,
    device_id   INTEGER         NOT NULL,
    mac_address VARCHAR(17)     NOT NULL,
    first_seen  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_device_mac_device
        FOREIGN KEY (device_id) REFERENCES devices(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_device_mac_per_device
        UNIQUE (device_id, mac_address),

    CONSTRAINT ck_device_mac_format
        CHECK (mac_address ~ '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
);

CREATE INDEX idx_device_mac_device  ON device_mac_addresses (device_id);
CREATE INDEX idx_device_mac_address ON device_mac_addresses (mac_address);

-- ---------------------------------------------------------------------------
-- device_fingerprint_signals
-- Raw identity signals collected per device. The identity engine uses this table
-- to compute and update fingerprint_hash and identity_strength on devices.
-- confidence: 0–100 integer replacing REAL.
-- ---------------------------------------------------------------------------

CREATE TABLE device_fingerprint_signals (
    id              SERIAL          PRIMARY KEY,
    device_id       INTEGER         NOT NULL,
    observation_id  INTEGER,                            -- NULL for manually-added signals
    signal_type     VARCHAR(30)     NOT NULL,
    signal_value    VARCHAR(500)    NOT NULL,
    confidence      SMALLINT        NOT NULL,           -- 0–100; replaces REAL weight
    source          VARCHAR(20)     NOT NULL,
    first_seen      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_signals_device
        FOREIGN KEY (device_id) REFERENCES devices(id)
        ON DELETE CASCADE,

    -- observation_id FK is deferred until observations table is created below
    -- application must enforce: if observation_id IS NOT NULL, it must exist

    CONSTRAINT ck_signals_type
        CHECK (signal_type IN (
            'HARDWARE_UUID', 'SERIAL', 'MAC', 'NETBIOS',
            'HOSTNAME', 'SNMP_SYSDESCR', 'TTL_PROFILE', 'OPEN_PORTS'
        )),

    CONSTRAINT ck_signals_confidence_range
        CHECK (confidence BETWEEN 0 AND 100),

    CONSTRAINT ck_signals_source
        CHECK (source IN ('ARP', 'PING', 'SNMP', 'MDNS', 'WMI', 'SSH', 'MANUAL'))
);

CREATE INDEX idx_signals_device         ON device_fingerprint_signals (device_id);
CREATE INDEX idx_signals_type_value     ON device_fingerprint_signals (signal_type, signal_value);

COMMENT ON COLUMN device_fingerprint_signals.confidence IS
    'Signal weight 0–100. Maps to: HARDWARE_UUID=70, SERIAL=65, MAC=50, NETBIOS=30, HOSTNAME=25, SNMP_SYSDESCR=20, TTL_PROFILE=15, OPEN_PORTS=10.';

-- =============================================================================
-- OBSERVATIONS GROUP
-- Table: observations
-- Append-only log. Rows are never deleted or mutated after insert except by the
-- identity engine setting device_id, match_confidence, and match_method.
-- =============================================================================

CREATE TABLE observations (
    id                  SERIAL          PRIMARY KEY,
    organization_id     INTEGER         NOT NULL,
    site_id             INTEGER         NOT NULL,
    agent_id            INTEGER         NOT NULL,
    device_id           INTEGER,                            -- NULL until identity engine resolves
    network_segment_id  INTEGER,                            -- FK to network_segments lookup table

    mac_address         VARCHAR(17),                        -- nullable: passive scans may miss MAC
    ip_address          VARCHAR(45),                        -- nullable: supports ARP-only scans; IPv6-ready
    hostname            VARCHAR(253),                       -- max DNS label length

    payload_hash        VARCHAR(64)     NOT NULL,           -- SHA-256 for deduplication / HMAC verify
    protocol_used       VARCHAR(20),
    scan_tier           VARCHAR(20)     NOT NULL DEFAULT 'UNAUTHENTICATED',

    match_confidence    SMALLINT,                           -- 0–100; replaces REAL
    match_method        VARCHAR(150),                       -- e.g. 'MAC+HOSTNAME'

    observed_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_observations_organization
        FOREIGN KEY (organization_id) REFERENCES organization(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_observations_site
        FOREIGN KEY (site_id) REFERENCES sites(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_observations_agent
        FOREIGN KEY (agent_id) REFERENCES agents(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_observations_device
        FOREIGN KEY (device_id) REFERENCES devices(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_observations_network_segment
        FOREIGN KEY (network_segment_id) REFERENCES network_segments(id)
        ON DELETE SET NULL,

    CONSTRAINT uq_observations_payload_hash
        UNIQUE (payload_hash),                              -- deduplication: reject retry duplicates

    CONSTRAINT ck_observations_protocol_used
        CHECK (protocol_used IS NULL OR protocol_used IN (
            'ARP', 'PING', 'SNMP', 'MDNS', 'MANUAL'
        )),

    CONSTRAINT ck_observations_scan_tier
        CHECK (scan_tier IN (
            'UNAUTHENTICATED', 'SNMP', 'WMI', 'SSH'
        )),

    CONSTRAINT ck_observations_match_confidence_range
        CHECK (match_confidence IS NULL OR match_confidence BETWEEN 0 AND 100),

    CONSTRAINT ck_observations_mac_format
        CHECK (mac_address IS NULL OR
               mac_address ~ '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
);

-- Observations is append-only and grows continuously — indexes are critical
CREATE INDEX idx_obs_device_time        ON observations (device_id, observed_at DESC);
CREATE INDEX idx_obs_org_site_time      ON observations (organization_id, site_id, observed_at DESC);
CREATE INDEX idx_obs_device_lookup      ON observations (device_id) WHERE device_id IS NULL;  -- unresolved
CREATE INDEX idx_obs_agent_time         ON observations (agent_id, observed_at);
CREATE INDEX idx_obs_network_segment    ON observations (network_segment_id);

-- Now add the deferred FK from device_fingerprint_signals
ALTER TABLE device_fingerprint_signals
    ADD CONSTRAINT fk_signals_observation
        FOREIGN KEY (observation_id) REFERENCES observations(id)
        ON DELETE SET NULL;

-- =============================================================================
-- PORT ENRICHMENT GROUP
-- Tables: device_ports, services
-- =============================================================================

-- ---------------------------------------------------------------------------
-- device_ports
-- Historical record of every (device, port, protocol) combination ever seen.
-- UNIQUE constraint prevents duplicates; INSERT OR IGNORE semantics in app layer.
-- is_expected suppresses new_port alerts for known-good services.
-- ---------------------------------------------------------------------------

CREATE TABLE device_ports (
    id              SERIAL          PRIMARY KEY,
    device_id       INTEGER         NOT NULL,
    observation_id  INTEGER,                            -- nullable for historical records
    port_number     INTEGER         NOT NULL,
    protocol        VARCHAR(5)      NOT NULL,
    service_name    VARCHAR(50),                        -- e.g. 'SSH', 'HTTPS'
    banner          VARCHAR(500),                       -- service banner for version fingerprinting
    is_expected     BOOLEAN         NOT NULL DEFAULT FALSE,
    first_seen      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_device_ports_device
        FOREIGN KEY (device_id) REFERENCES devices(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_device_ports_observation
        FOREIGN KEY (observation_id) REFERENCES observations(id)
        ON DELETE SET NULL,

    CONSTRAINT uq_device_ports_unique
        UNIQUE (device_id, port_number, protocol),

    CONSTRAINT ck_device_ports_port_range
        CHECK (port_number BETWEEN 0 AND 65535),

    CONSTRAINT ck_device_ports_protocol
        CHECK (protocol IN ('TCP', 'UDP'))
);

CREATE INDEX idx_ports_device ON device_ports (device_id);

-- ---------------------------------------------------------------------------
-- services
-- Active service records linked to observations and devices.
-- Complements device_ports (history) with per-observation service state.
-- ---------------------------------------------------------------------------

CREATE TABLE services (
    id              SERIAL          PRIMARY KEY,
    organization_id INTEGER         NOT NULL,
    site_id         INTEGER         NOT NULL,
    device_id       INTEGER         NOT NULL,
    observation_id  INTEGER         NOT NULL,
    port            INTEGER         NOT NULL,
    protocol        VARCHAR(5)      NOT NULL,
    service_name    VARCHAR(100),
    banner          VARCHAR(500),
    service_state   VARCHAR(10)     NOT NULL DEFAULT 'open',
    is_expected     BOOLEAN         NOT NULL DEFAULT FALSE,
    first_seen      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_services_organization
        FOREIGN KEY (organization_id) REFERENCES organization(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_services_site
        FOREIGN KEY (site_id) REFERENCES sites(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_services_device
        FOREIGN KEY (device_id) REFERENCES devices(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_services_observation
        FOREIGN KEY (observation_id) REFERENCES observations(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_services_unique
        UNIQUE (observation_id, port, protocol),

    CONSTRAINT ck_services_port_range
        CHECK (port BETWEEN 0 AND 65535),

    CONSTRAINT ck_services_protocol
        CHECK (protocol IN ('TCP', 'UDP')),

    CONSTRAINT ck_services_state
        CHECK (service_state IN ('open', 'closed', 'filtered'))
);

-- =============================================================================
-- ALERTING GROUP
-- Tables: alert_type, alerts, analyst_notes
-- =============================================================================

-- ---------------------------------------------------------------------------
-- alert_type
-- Lookup table seeded on DB init. New alert types are data changes, not code.
-- [FIX-6.1] Self-referencing FK removed — was invalid in original schema.
-- ---------------------------------------------------------------------------

CREATE TABLE alert_type (
    id                      SERIAL          PRIMARY KEY,
    alert_type_name         VARCHAR(60)     NOT NULL,
    alert_type_description  VARCHAR(300)    NOT NULL,
    default_severity        VARCHAR(10)     NOT NULL DEFAULT 'medium',
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_alert_type_name
        UNIQUE (alert_type_name),

    CONSTRAINT ck_alert_type_severity
        CHECK (default_severity IN ('low', 'medium', 'high', 'critical'))
);

-- Seed data — must exist before the alert engine can insert rows into alerts
INSERT INTO alert_type (alert_type_name, alert_type_description, default_severity) VALUES
    ('new_device',      'A device was seen for the first time',                        'medium'),
    ('missing_device',  'A known device has not been seen within its threshold window', 'high'),
    ('new_port',        'A new open port was detected on a known device',               'medium');

-- ---------------------------------------------------------------------------
-- alerts
-- Alert events produced by the alert engine. device_id and observation_id are
-- nullable — missing_device has no observation; new_device may fire before resolution.
-- metadata: JSON with alert-type-specific context. Stored as VARCHAR(1000) in PG;
-- application layer deserializes. Using JSONB is a post-MVP upgrade.
-- [FIX-6.2] Trailing comma removed. Duplicate created_at / updated_at removed.
-- ---------------------------------------------------------------------------

CREATE TABLE alerts (
    id              SERIAL          PRIMARY KEY,
    organization_id INTEGER         NOT NULL,
    site_id         INTEGER         NOT NULL,
    device_id       INTEGER,                            -- nullable: some alert types have no device
    observation_id  INTEGER,                            -- nullable: missing_device has no observation
    alert_type_id   INTEGER         NOT NULL,
    metadata        VARCHAR(1000),                      -- JSON: alert-type-specific context
    severity        VARCHAR(10)     NOT NULL DEFAULT 'medium',
    alert_status    VARCHAR(15)     NOT NULL DEFAULT 'open',
    alert_message   VARCHAR(500)    NOT NULL,
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_alerts_organization
        FOREIGN KEY (organization_id) REFERENCES organization(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_alerts_site
        FOREIGN KEY (site_id) REFERENCES sites(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_alerts_device
        FOREIGN KEY (device_id) REFERENCES devices(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_alerts_observation
        FOREIGN KEY (observation_id) REFERENCES observations(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_alerts_type
        FOREIGN KEY (alert_type_id) REFERENCES alert_type(id)
        ON DELETE RESTRICT,

    CONSTRAINT ck_alerts_severity
        CHECK (severity IN ('low', 'medium', 'high', 'critical')),

    CONSTRAINT ck_alerts_status
        CHECK (alert_status IN ('open', 'acknowledged', 'resolved')),

    CONSTRAINT ck_alerts_resolved_consistency
        CHECK (
            (alert_status = 'resolved' AND resolved_at IS NOT NULL) OR
            (alert_status <> 'resolved' AND resolved_at IS NULL)
        )
);

CREATE INDEX idx_alerts_org_unresolved  ON alerts (organization_id, resolved_at)
    WHERE resolved_at IS NULL;                          -- partial index: only open alerts

CREATE INDEX idx_alerts_device_active   ON alerts (device_id, resolved_at);
CREATE INDEX idx_alerts_site            ON alerts (site_id, created_at DESC);

CREATE TRIGGER trg_alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

COMMENT ON COLUMN alerts.metadata IS
    'JSON string with alert-type context. new_device: {mac, ip}. missing_device: {last_seen, threshold_hours}. new_port: {port, protocol, service}.';

-- ---------------------------------------------------------------------------
-- analyst_notes
-- Free-text notes attached to any combination of alert, device, or observation.
-- CHECK ensures a note is never orphaned (must reference at least one entity).
-- note is VARCHAR(300) per schema reference §4.12 — enforced at DB layer.
-- ---------------------------------------------------------------------------

CREATE TABLE analyst_notes (
    id              SERIAL          PRIMARY KEY,
    user_id         INTEGER         NOT NULL,
    alert_id        INTEGER,
    device_id       INTEGER,
    observation_id  INTEGER,
    note            VARCHAR(300)    NOT NULL,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_analyst_notes_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_analyst_notes_alert
        FOREIGN KEY (alert_id) REFERENCES alerts(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_analyst_notes_device
        FOREIGN KEY (device_id) REFERENCES devices(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_analyst_notes_observation
        FOREIGN KEY (observation_id) REFERENCES observations(id)
        ON DELETE SET NULL,

    CONSTRAINT ck_analyst_notes_has_context
        CHECK (
            alert_id IS NOT NULL OR
            device_id IS NOT NULL OR
            observation_id IS NOT NULL
        )
);

CREATE INDEX idx_analyst_notes_user     ON analyst_notes (user_id);
CREATE INDEX idx_analyst_notes_device   ON analyst_notes (device_id);

CREATE TRIGGER trg_analyst_notes_updated_at
    BEFORE UPDATE ON analyst_notes
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

-- =============================================================================
-- ROW-LEVEL SECURITY (post-MVP foundation)
-- Enable RLS on tenant-scoped tables so the DB enforces isolation
-- independent of application-layer filtering. App layer still passes
-- organization_id from the verified JWT — this is defense-in-depth.
-- OWASP A01 — Broken Access Control: structural enforcement
-- Uncomment when application has a per-connection role / current_setting approach.
-- =============================================================================

-- ALTER TABLE devices           ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE observations      ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE alerts            ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE analyst_notes     ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE network_segments  ENABLE ROW LEVEL SECURITY;

-- Example policy (replicate per table):
-- CREATE POLICY tenant_isolation ON devices
--     USING (organization_id = current_setting('app.current_org_id')::INTEGER);

-- =============================================================================
-- INDEX SUMMARY — all defined above inline with their tables
-- =============================================================================
-- organization       : uq_organization_slug
-- users              : idx_users_org, idx_users_email, uq_users_email_org, uq_users_oauth
-- sessions           : idx_sessions_user, idx_sessions_token
-- sites              : idx_sites_org
-- network_segments   : idx_network_segments_site
-- agents             : idx_agents_site
-- devices            : idx_devices_org_site, idx_devices_fingerprint, idx_devices_last_seen
-- device_mac_addresses    : idx_device_mac_device, idx_device_mac_address
-- device_fingerprint_signals: idx_signals_device, idx_signals_type_value
-- observations       : idx_obs_device_time, idx_obs_org_site_time, idx_obs_device_lookup,
--                      idx_obs_agent_time, idx_obs_network_segment
-- device_ports       : idx_ports_device
-- alerts             : idx_alerts_org_unresolved (partial), idx_alerts_device_active, idx_alerts_site
-- analyst_notes      : idx_analyst_notes_user, idx_analyst_notes_device
-- =============================================================================
