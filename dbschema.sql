CREATE TABLE organization (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    slug VARCHAR UNIQUE NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    email VARCHAR UNIQUE NOT NULL,
    password_hash VARCHAR NOT NULL,
    first_name VARCHAR,
    last_name VARCHAR,
    user_role TEXT NOT NULL DEFAULT 'viewer'
    CHECK (user_role IN ('admin', 'analyst', 'viewer')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (organization_id) REFERENCES organization (id)
);

CREATE TABLE sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    site_name VARCHAR UNIQUE NOT NULL,
    site_location VARCHAR,
    agent_token VARCHAR NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (organization_id) REFERENCES organization (id),
    UNIQUE (organization_id, site_name)
);

CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL, -- unique site id
    hostname VARCHAR(255),
    mac_address VARCHAR(17) NOT NULL,
    device_status TEXT NOT NULL DEFAULT 'unknown'
    CHECK (device_status IN ('active', 'inactive', 'unknown', 'missing')),
    os_version VARCHAR(50),
    friendly_name VARCHAR, -- User-assigned name
    device_type VARCHAR,

    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    identity_strength REAL DEFAULT 0,

    FOREIGN KEY (site_id) REFERENCES sites (id),
    UNIQUE (site_id, mac_address)
);

CREATE TABLE services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    site_id INTEGER NOT NULL,
    observation_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL
    CHECK (protocol IN ('tcp', 'udp')),
    services_name VARCHAR,
    banner VARCHAR,
    services_state VARCHAR NOT NULL DEFAULT 'open'
    CHECK (services_state IN ('open', 'closed', 'filtered')),
    is_expected BOOLEAN NOT NULL DEFAULT FALSE, -- Known good service
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (device_id) REFERENCES devices (id),
    FOREIGN KEY (observation_id) REFERENCES observations (id),
    UNIQUE (observation_id, port, protocol)
);

-- The Observations Table:
-- Records every time a device is spotted.
-- A single MAC can have many observation entries.

CREATE TABLE observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    site_id INTEGER NOT NULL,
    agent_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,

    mac_address VARCHAR NOT NULL,
    ip_address VARCHAR NOT NULL, -- The IP at the time of discovery
    hostname VARCHAR, -- DNS or mDNS name

    protocol_used VARCHAR, -- How it was found (ARP, Ping, SNMP)
    network_segment VARCHAR, -- Subnet or VLAN ID

    match_confidence REAL,
    match_method VARCHAR,
    matched_device_id INTEGER, -- Left for future device optimization
    observed_at TIMESTAMP NOT NULL,
    payload_hash VARCHAR NOT NULL,

    FOREIGN KEY (device_id) REFERENCES devices (id),
    FOREIGN KEY (site_id) REFERENCES sites (id),
    FOREIGN KEY (agent_id) REFERENCES agents (id)
);

CREATE TABLE device_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    device_id INTEGER NOT NULL,

    port_number INTEGER NOT NULL,
    protocol VARCHAR NOT NULL, -- SSH, HTTP, etc.

    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (device_id) REFERENCES devices (id),
    UNIQUE (device_id, port_number, protocol)
);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    site_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    observation_id INTEGER NOT NULL,

    alert_type_id INTEGER NOT NULL,
    severity VARCHAR NOT NULL DEFAULT 'medium'
    CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    alert_status VARCHAR NOT NULL DEFAULT 'open'
    CHECK (alert_status IN ('open', 'acknowledged', 'resolved')),
    alert_message VARCHAR NOT NULL,
    resolved_at TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE alert_type (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type_name VARCHAR NOT NULL UNIQUE,
    alert_type_description VARCHAR NOT NULL,
    default_severity VARCHAR NOT NULL DEFAULT 'medium'
    CHECK (default_severity IN ('low', 'medium', 'high', 'critical')),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE analyst_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    alert_id INTEGER,
    device_id INTEGER,
    observation_id INTEGER,
    note TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (device_id) REFERENCES devices (id),
    FOREIGN KEY (observation_id) REFERENCES observations (id),
    FOREIGN KEY (alert_id) REFERENCES alerts (id),

    CHECK (
        alert_id IS NOT NULL
        OR device_id IS NOT NULL
        OR observation_id IS NOT NULL
    )
);

CREATE TABLE agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    agents_name VARCHAR,
    api_key_hash VARCHAR NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 1,
    last_seen TIMESTAMP NULL DEFAULT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (site_id) REFERENCES sites (id)
);

-- devices
CREATE INDEX idx_devices_site ON devices (site_id);
CREATE INDEX idx_obs_agent_time ON observations (agent_id, observed_at);

-- observations
CREATE INDEX idx_obs_device_time ON observations (device_id, observed_at DESC);
CREATE INDEX idx_obs_org_site_time ON observations (
    organization_id, site_id, observed_at DESC
);
CREATE INDEX idx_obs_device_lookup ON observations (device_id);

-- ports
CREATE INDEX idx_ports_device ON device_ports (device_id);

-- alerts
CREATE INDEX idx_alerts_active ON alerts (device_id, resolved_at);
