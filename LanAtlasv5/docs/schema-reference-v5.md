# LAN Atlas — Database Schema Reference

> **Version:** 2.0
> **Database:** PostgreSQL (AWS RDS)
> **Status:** Active — MVP Development
> **Supersedes:** v1.3 (SQLite) — see Section 8 for full migration history

---

## Table of Contents

1. [Purpose](#1-purpose)
2. [Design Principles](#2-design-principles)
3. [Entity Relationship Overview](#3-entity-relationship-overview)
4. [Table Reference](#4-table-reference)
5. [Index Reference](#5-index-reference)
6. [Design Notes and Open Items](#6-design-notes-and-open-items)
7. [Planned Post-MVP Additions](#7-planned-post-mvp-additions)
8. [Version History](#8-version-history)

---

## 1. Purpose

This document is the authoritative reference for the LAN Atlas
PostgreSQL schema. It explains every table, every column, and the
reasoning behind design decisions. It is intended for developers
joining the project, teammates writing queries against the database,
and anyone extending the schema.

This is a **living document** — regenerate or amend it whenever the
schema changes. A stale schema reference is worse than none, since it
actively misleads rather than simply being unavailable. If you add a
migration under `cloud/app/migrations/versions/`, update this file in
the same pull request.

For how this schema's security properties map to OWASP controls, see
`docs/owasp-controls-mapping.md` — that document covers the
*security* rationale in depth; this document covers the *data model*.

---

## 2. Design Principles

### 2.1 Observations Are Append-Only

Every agent scan writes to `observations` and the row is never
mutated except by the identity resolution process setting `device_id`,
`match_confidence`, and `match_method`. Device state is derived from
observations, never stored as the primary source of truth.

### 2.2 Device Identity Is Computed, Not Assumed

A device is not identified by IP or MAC alone — both change over
time. `fingerprint_hash` is computed from a weighted combination of
identity signals (see `device_fingerprint_signals`), and
`identity_strength` (0–100) reflects how much corroborating evidence
exists for that identity.

### 2.3 Multi-Tenant Isolation Is Structural, Not Just Conventional

Unlike the earlier SQLite schema — where `organization_id` was an
unenforced TEXT column with no authoritative table behind it —
`organization` and `sites` are now real tables with enforced foreign
keys. Every tenant-scoped table has a `FOREIGN KEY ... REFERENCES
organization(id)` or `sites(id)` constraint the database itself
enforces, not just application-layer discipline.

### 2.4 Signal Quality Bounds Confidence

`scan_tier` on every observation records what kind of scan produced
it (`UNAUTHENTICATED`, `SNMP`, `WMI`, `SSH`). The identity resolution
logic caps how confident it's allowed to be based on this — an
unauthenticated ARP scan can never auto-link to an existing device,
regardless of how many signals happen to match.

### 2.5 OAuth-Only Authentication — No Credential Storage

`users` has no `password_hash` column. Identity is anchored to
`(oauth_provider, oauth_subject)` — the provider's stable `sub` claim.
LAN Atlas never handles, stores, or is responsible for password
security; that's delegated entirely to the OAuth provider (Google,
Microsoft, etc.).

### 2.6 The Audit Trail Is Database-Enforced, Not Just Logged

`audit_log` rows cannot be updated or deleted — not by convention, but
by a database trigger (`fn_prevent_audit_log_mutation`) that raises an
exception on any attempt. This holds even against a fully compromised
application server that still has valid database credentials.

### 2.7 Scores Are Integers, Not Floats

`identity_strength`, `device_fingerprint_signals.confidence`, and
`observations.match_confidence` are all `SMALLINT` on a 0–100 scale.
The original SQLite schema used `REAL` on a 0.0–1.0 scale, which
introduced float comparison drift in scoring logic. This was corrected
during the PostgreSQL migration.

---

## 3. Entity Relationship Overview

| Group | Tables |
|---|---|
| Tenant & Access | `organization`, `users`, `sessions`, `sites` |
| Network Topology | `network_segments` |
| Network Agents | `agents` |
| Device Identity | `devices`, `device_mac_addresses`, `device_fingerprint_signals` |
| Observations | `observations` |
| Port & Service Enrichment | `device_ports`, `services` |
| Alerting | `alert_type`, `alerts`, `analyst_notes` |
| Audit & Compliance | `audit_log` |

Key relationships:

- An **organization** has many **sites**, **users**, and **devices**.
- A **site** has many **agents**, **network_segments**, and **devices**.
- An **agent** sends **observations**. Each observation is scoped to
  one organization, site, and agent — all enforced by FK.
- The **identity resolution service** resolves each observation to a
  **device** by setting `observations.device_id`.
- A **device** accumulates fingerprint signals over time in
  **device_fingerprint_signals**, and MAC history in
  **device_mac_addresses**.
- **Alerts** reference devices, observations, and alert types.
  **Analyst notes** attach to any combination of alerts, devices, or
  observations.
- **audit_log** records human-initiated mutations to any tenant-owned
  entity — devices, alerts, users, sites, agents.
- **sessions** enables server-side revocation of a user's login
  independent of the OAuth provider's own session state.

---

## 4. Table Reference

---

### 4.1 organization

Root tenant entity. Every operational table traces back here.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `slug` | VARCHAR(100) | No | — | URL-safe unique tenant identifier. Must match `^[a-z0-9\-]+$`. |
| `is_active` | BOOLEAN | No | TRUE | Soft-delete flag. |
| `created_at` | TIMESTAMPTZ | No | NOW() | Row creation time. |
| `updated_at` | TIMESTAMPTZ | No | NOW() | Maintained automatically by `fn_set_updated_at()` trigger. |

---

### 4.2 users

A human operator within an organization. Authenticates exclusively via
OAuth — there is no password to compromise, phish, or leak.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `organization_id` | INTEGER | No | — | FK to `organization.id`. |
| `email` | CITEXT | No | — | Case-insensitive. Unique within an org (`uq_users_email_org`). |
| `first_name` / `last_name` | VARCHAR(100) | Yes | — | Display name. |
| `oauth_provider` | VARCHAR(50) | No | — | `google` \| `microsoft` \| `github` \| `okta`. Never store passwords here. |
| `oauth_subject` | VARCHAR(255) | No | — | Provider's stable `sub` claim. Survives email changes. |
| `user_role` | VARCHAR(20) | No | `'viewer'` | `admin` \| `analyst` \| `viewer`. |
| `is_active` | BOOLEAN | No | TRUE | Deactivated users cannot log in. |
| `last_login_at` | TIMESTAMPTZ | Yes | — | Set on successful authentication. |
| `failed_login_count` | SMALLINT | No | 0 | Incremented by the auth layer on failed attempts; reset on success. |
| `lockout_until` | TIMESTAMPTZ | Yes | — | Set by the auth layer after N consecutive failures. |
| `created_at` / `updated_at` | TIMESTAMPTZ | No | NOW() | `updated_at` trigger-maintained. |

`UNIQUE (oauth_provider, oauth_subject)` prevents the same external
identity from being linked to more than one LAN Atlas account.

---

### 4.3 sessions

Server-side session record enabling explicit revocation — independent
of whatever session state the OAuth provider maintains on its own
side.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `user_id` | INTEGER | No | — | FK to `users.id`, `ON DELETE CASCADE`. |
| `token_hash` | VARCHAR(64) | No | — | Hex SHA-256 of the opaque bearer token. Plain token never stored. |
| `expires_at` | TIMESTAMPTZ | No | — | Natural expiry. |
| `revoked_at` | TIMESTAMPTZ | Yes | — | NULL = active. Non-null = explicitly revoked (logout, deactivation, role change). |
| `created_at` | TIMESTAMPTZ | No | NOW() | Session start. |

---

### 4.4 sites

A physical or logical network location — branch office, warehouse,
data center, cloud VPC. Carries business-hours config used by the
alert engine to avoid firing missing-device alerts outside working
hours.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `organization_id` | INTEGER | No | — | FK to `organization.id`. |
| `site_name` | VARCHAR(150) | No | — | Unique within an org. |
| `site_location` | VARCHAR(255) | Yes | — | Free-text description. |
| `timezone` | VARCHAR(64) | No | `'UTC'` | IANA timezone string. |
| `business_hours_start` / `_end` | SMALLINT | No | 9 / 17 | 0–23 hour range. `_end` must be greater than `_start`. |
| `business_days` | VARCHAR(20) | No | `'1,2,3,4,5'` | Comma-separated ISO weekdays. |
| `is_active` | BOOLEAN | No | TRUE | Soft-delete. |
| `created_at` / `updated_at` | TIMESTAMPTZ | No | NOW() | `updated_at` trigger-maintained. |

---

### 4.5 network_segments

Authoritative lookup of known subnets and VLANs within a site.
Replaces the free-text `network_segment` column from the original
SQLite schema — `observations.network_segment_id` now points here,
which closes a minor injection surface (arbitrary strings could no
longer enter the observation pipeline through that field) and enables
structured queries like "show all devices on VLAN 20."

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `organization_id` | INTEGER | No | — | FK to `organization.id`. |
| `site_id` | INTEGER | No | — | FK to `sites.id`. |
| `cidr` | VARCHAR(43) | No | — | e.g. `192.168.1.0/24`. Unique per site. |
| `vlan_id` | SMALLINT | Yes | — | 802.1Q tag, 1–4094. NULL = untagged/unknown. |
| `segment_name` | VARCHAR(100) | Yes | — | Human label, e.g. "IoT VLAN". |
| `description` | VARCHAR(300) | Yes | — | Free text. |
| `is_active` | BOOLEAN | No | TRUE | Soft-delete. |
| `created_at` / `updated_at` | TIMESTAMPTZ | No | NOW() | `updated_at` trigger-maintained. |

---

### 4.6 agents

An on-premises scanning agent installed at a site.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `site_id` | INTEGER | No | — | FK to `sites.id`. |
| `agent_name` | VARCHAR(100) | Yes | — | Human-readable label. |
| `api_key_hash` | VARCHAR(64) | No | — | Hex SHA-256 of the agent's API key. Plain key never stored. |
| `token_version` | SMALLINT | No | 1 | Incremented on rotation to invalidate old keys without reissuing. |
| `last_seen` | TIMESTAMPTZ | Yes | — | Last heartbeat or observation submission. |
| `is_active` | BOOLEAN | No | TRUE | Inactive agents are rejected by the API. |
| `created_at` / `updated_at` | TIMESTAMPTZ | No | NOW() | `updated_at` trigger-maintained. |

---

### 4.7 devices

The resolved physical device — one row per physical device per site.
Identity anchors to `fingerprint_hash`, never to IP or MAC alone.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `organization_id` / `site_id` | INTEGER | No | — | FK to `organization.id` / `sites.id`. |
| `fingerprint_hash` | VARCHAR(64) | Yes | — | SHA-256 of normalized identity signals. Unique per `(organization_id, site_id)`. |
| `primary_mac` | VARCHAR(17) | Yes | — | Most recently observed MAC — informational only, not identity. |
| `vendor_name` | VARCHAR(100) | Yes | — | OUI lookup result. |
| `friendly_name` | VARCHAR(150) | Yes | — | User-assigned display name. |
| `device_type` | VARCHAR(30) | No | `'unknown'` | `router` \| `switch` \| `access_point` \| `server` \| `workstation` \| `mobile` \| `printer` \| `iot` \| `unknown`. |
| `classification_source` | VARCHAR(20) | Yes | — | `MANUAL` \| `OUI` \| `PORT_PROFILE` \| `SNMP` \| `WMI`. |
| `first_seen` | TIMESTAMPTZ | No | NOW() | First resolved observation. |
| `last_seen` | TIMESTAMPTZ | Yes | — | Most recent resolved observation. |
| `seen_count` | INTEGER | No | 0 | Times this device has been resolved. Missing-device alerts require a minimum before they can fire. |
| `missing_threshold_hours` | SMALLINT | No | 24 | Hours without an observation before a missing-device alert fires. Seeded from device type, overridable per device. |
| `identity_strength` | SMALLINT | No | 0 | Aggregate signal confidence, 0–100. |
| `is_authorized` | BOOLEAN | No | FALSE | Explicit human approval. New devices are never auto-authorized. |
| `created_at` / `updated_at` | TIMESTAMPTZ | No | NOW() | `updated_at` trigger-maintained. |

---

### 4.8 device_mac_addresses

Full history of every MAC ever observed for a device — `primary_mac`
on `devices` is informational; this table is the authoritative record.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `device_id` | INTEGER | No | — | FK to `devices.id`, `ON DELETE CASCADE`. |
| `mac_address` | VARCHAR(17) | No | — | Must match MAC format regex. Unique per device. |
| `first_seen` / `last_seen` | TIMESTAMPTZ | No | NOW() | — |

---

### 4.9 device_fingerprint_signals

Raw identity evidence collected per device. The identity resolution
service reads this to compute `fingerprint_hash` and
`identity_strength` on `devices`.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `device_id` | INTEGER | No | — | FK to `devices.id`, `ON DELETE CASCADE`. |
| `observation_id` | INTEGER | Yes | — | FK to `observations.id`, `ON DELETE SET NULL`. NULL for manually-added signals. |
| `signal_type` | VARCHAR(30) | No | — | `HARDWARE_UUID` \| `SERIAL` \| `MAC` \| `NETBIOS` \| `HOSTNAME` \| `SNMP_SYSDESCR` \| `TTL_PROFILE` \| `OPEN_PORTS`. |
| `signal_value` | VARCHAR(500) | No | — | The raw signal value. |
| `confidence` | SMALLINT | No | — | Signal weight, 0–100. See `cloud/app/config/identity.py` for the exact mapping. |
| `source` | VARCHAR(20) | No | — | `ARP` \| `PING` \| `SNMP` \| `MDNS` \| `WMI` \| `SSH` \| `MANUAL`. |
| `first_seen` / `last_seen` | TIMESTAMPTZ | No | NOW() | — |

Signal weight reference:

| Signal Type | Weight | Rationale |
|---|---|---|
| `HARDWARE_UUID` | 70 | Motherboard UUID — survives reimaging, gold standard |
| `SERIAL` | 65 | Hardware serial — very stable, not always retrievable |
| `MAC` | 50 | Reliable short-term; can be spoofed or reassigned |
| `NETBIOS` | 30 | Stable on Windows; recyclable |
| `HOSTNAME` | 25 | Useful corroboration; not primary identity |
| `SNMP_SYSDESCR` | 20 | Good for network equipment |
| `TTL_PROFILE` | 15 | OS class hint only |
| `OPEN_PORTS` | 10 | Changes frequently; weak alone |

---

### 4.10 observations

The append-only log of every network scan result.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `organization_id` / `site_id` | INTEGER | No | — | FK to `organization.id` / `sites.id`. |
| `agent_id` | INTEGER | No | — | FK to `agents.id`. |
| `device_id` | INTEGER | Yes | — | FK to `devices.id`, `ON DELETE SET NULL`. NULL until resolved. |
| `network_segment_id` | INTEGER | Yes | — | FK to `network_segments.id`, `ON DELETE SET NULL`. |
| `mac_address` | VARCHAR(17) | Yes | — | Nullable — some discovery methods may not capture it. |
| `ip_address` | VARCHAR(45) | Yes | — | Nullable — supports ARP-only scans. IPv6-ready (45 chars). |
| `hostname` | VARCHAR(253) | Yes | — | Max DNS label length. |
| `payload_hash` | VARCHAR(64) | No | — | SHA-256 for deduplication. **Unique across the table** (`uq_observations_payload_hash`) — a retried agent submission is rejected by the database itself, not just application logic. |
| `protocol_used` | VARCHAR(20) | Yes | — | `ARP` \| `PING` \| `SNMP` \| `MDNS` \| `MANUAL`. |
| `scan_tier` | VARCHAR(20) | No | `'UNAUTHENTICATED'` | `UNAUTHENTICATED` \| `SNMP` \| `WMI` \| `SSH`. |
| `match_confidence` | SMALLINT | Yes | — | 0–100. Set by identity resolution. |
| `match_method` | VARCHAR(150) | Yes | — | e.g. `MAC+HOSTNAME`. Set by identity resolution. |
| `observed_at` | TIMESTAMPTZ | No | NOW() | Scan timestamp. |

Scan tier confidence ceilings (enforced in `services/identity.py`, not
the schema):

| Scan Tier | Max Confidence | Rationale |
|---|---|---|
| `UNAUTHENTICATED` | 65 | Network-observable signals only. Can never auto-link. |
| `SNMP` | 80 | System description available. Stronger, not hardware-level. |
| `WMI` | 100 | Hardware UUID/serial available. Full auto-link permitted. |
| `SSH` | 100 | Same hardware-level evidence as WMI. |

---

### 4.11 device_ports

Historical record of every `(device, port, protocol)` combination
ever seen.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `device_id` | INTEGER | No | — | FK to `devices.id`, `ON DELETE CASCADE`. |
| `observation_id` | INTEGER | Yes | — | FK to `observations.id`, `ON DELETE SET NULL`. Nullable for historical backfill. |
| `port_number` | INTEGER | No | — | 0–65535. |
| `protocol` | VARCHAR(5) | No | — | `TCP` \| `UDP`. |
| `service_name` | VARCHAR(50) | Yes | — | e.g. `SSH`, `HTTPS`. |
| `banner` | VARCHAR(500) | Yes | — | Captured service banner, for version fingerprinting. |
| `is_expected` | BOOLEAN | No | FALSE | When true, suppresses `new_port` alerts for this port. |
| `first_seen` / `last_seen` | TIMESTAMPTZ | No | NOW() | — |

`UNIQUE (device_id, port_number, protocol)`.

---

### 4.12 services

Active per-observation service state — complements `device_ports`
(lifetime history) with a record tied to a specific scan.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `organization_id` / `site_id` | INTEGER | No | — | FK to `organization.id` / `sites.id`. |
| `device_id` | INTEGER | No | — | FK to `devices.id`, `ON DELETE CASCADE`. |
| `observation_id` | INTEGER | No | — | FK to `observations.id`, `ON DELETE CASCADE`. |
| `port` | INTEGER | No | — | 0–65535. |
| `protocol` | VARCHAR(5) | No | — | `TCP` \| `UDP`. |
| `service_name` | VARCHAR(100) | Yes | — | — |
| `banner` | VARCHAR(500) | Yes | — | — |
| `service_state` | VARCHAR(10) | No | `'open'` | `open` \| `closed` \| `filtered`. |
| `is_expected` | BOOLEAN | No | FALSE | — |
| `first_seen` / `last_seen` | TIMESTAMPTZ | No | NOW() | — |

`UNIQUE (observation_id, port, protocol)`. See Section 6 for a note on
this table's missing index.

---

### 4.13 alert_type

Lookup table for alert types. Must be seeded before the alert engine
can insert rows into `alerts`.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `alert_type_name` | VARCHAR(60) | No | — | Unique. |
| `alert_type_description` | VARCHAR(300) | No | — | — |
| `default_severity` | VARCHAR(10) | No | `'medium'` | `low` \| `medium` \| `high` \| `critical`. |
| `created_at` | TIMESTAMPTZ | No | NOW() | — |

Required seed data:

```sql
INSERT INTO alert_type (alert_type_name, alert_type_description, default_severity) VALUES
    ('new_device',     'A device was seen for the first time',                        'medium'),
    ('missing_device', 'A known device has not been seen within its threshold window', 'high'),
    ('new_port',       'A new open port was detected on a known device',               'medium');
```

---

### 4.14 alerts

Alert events. `device_id` and `observation_id` are nullable — a
`missing_device` alert has no associated observation.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `organization_id` / `site_id` | INTEGER | No | — | FK to `organization.id` / `sites.id`. |
| `device_id` | INTEGER | Yes | — | FK to `devices.id`, `ON DELETE SET NULL`. |
| `observation_id` | INTEGER | Yes | — | FK to `observations.id`, `ON DELETE SET NULL`. |
| `alert_type_id` | INTEGER | No | — | FK to `alert_type.id`. |
| `metadata` | VARCHAR(1000) | Yes | — | JSON string — alert-type-specific context (see below). |
| `severity` | VARCHAR(10) | No | `'medium'` | `low` \| `medium` \| `high` \| `critical`. |
| `alert_status` | VARCHAR(15) | No | `'open'` | `open` \| `acknowledged` \| `resolved`. |
| `alert_message` | VARCHAR(500) | No | — | Human-readable, written by the alert engine. |
| `resolved_at` | TIMESTAMPTZ | Yes | — | Consistency-checked: set if and only if `alert_status = 'resolved'`. |
| `created_at` / `updated_at` | TIMESTAMPTZ | No | NOW() | `updated_at` trigger-maintained. |

Metadata shapes by alert type:

```json
new_device:     { "mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.100" }
missing_device: { "last_seen": "2026-05-10T14:00:00Z", "threshold_hours": 2 }
new_port:       { "port": 443, "protocol": "TCP", "service": "HTTPS" }
```

---

### 4.15 analyst_notes

Free-text notes attachable to any combination of an alert, device, or
observation. `CHECK ck_analyst_notes_has_context` ensures a note
always references at least one entity.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | SERIAL | No | auto | Primary key. |
| `user_id` | INTEGER | No | — | FK to `users.id`, `ON DELETE RESTRICT`. |
| `alert_id` / `device_id` / `observation_id` | INTEGER | Yes | — | At least one must be non-null. |
| `note` | VARCHAR(300) | No | — | Max 300 characters. |
| `created_at` / `updated_at` | TIMESTAMPTZ | No | NOW() | `updated_at` trigger-maintained. |

---

### 4.16 audit_log

Immutable record of every human-initiated mutation to tenant-owned
data. Distinct from `observations` (machine activity) and
`analyst_notes` (optional commentary) — this is mandatory, structured,
and cannot be altered after the fact.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | BIGSERIAL | No | auto | Primary key. |
| `organization_id` | INTEGER | No | — | FK to `organization.id`, `ON DELETE RESTRICT`. |
| `user_id` | INTEGER | Yes | — | FK to `users.id`, `ON DELETE SET NULL`. Who made the change. |
| `action` | VARCHAR(60) | No | — | e.g. `device.rename`, `alert.resolve`, `user.role_change`. |
| `entity_type` | VARCHAR(30) | No | — | `device` \| `alert` \| `user` \| `site` \| `agent`. |
| `entity_id` | INTEGER | Yes | — | The mutated row's id. |
| `before_value` | JSONB | Yes | — | Entity state before the change. Secrets redacted before write. |
| `after_value` | JSONB | Yes | — | Entity state after the change. Same redaction requirement. |
| `ip_address` | VARCHAR(45) | Yes | — | Captured from the request at write time. |
| `created_at` | TIMESTAMPTZ | No | NOW() | — |

**Immutability:** `trg_audit_log_no_update` and `trg_audit_log_no_delete`
raise an exception on any `UPDATE` or `DELETE` against this table, via
`fn_prevent_audit_log_mutation()`. This holds even for a database
session with otherwise full write access — there is no code path,
authorized or not, that can alter a written row.

---

## 5. Index Reference

| Table | Index | Purpose |
|---|---|---|
| `organization` | `uq_organization_slug` | Enforces unique tenant slugs |
| `users` | `idx_users_org`, `idx_users_email` | Tenant-scoped and email lookups |
| `sessions` | `idx_sessions_user`, `idx_sessions_token` | Session lookup and revocation checks |
| `sites` | `idx_sites_org` | Tenant-scoped site lookups |
| `network_segments` | `idx_network_segments_site` | Segment lookup by org/site |
| `agents` | `idx_agents_site` | Agent lookup by site |
| `devices` | `idx_devices_org_site`, `idx_devices_fingerprint`, `idx_devices_last_seen` | Dashboard queries, identity lookups, missing-device queries |
| `device_mac_addresses` | `idx_device_mac_device`, `idx_device_mac_address` | Device MAC history lookups |
| `device_fingerprint_signals` | `idx_signals_device`, `idx_signals_type_value` | Signal loading; `idx_signals_type_value` is the core identity-resolution candidate lookup |
| `observations` | `idx_obs_device_time`, `idx_obs_org_site_time`, `idx_obs_device_lookup` (partial, `WHERE device_id IS NULL`), `idx_obs_agent_time`, `idx_obs_network_segment` | Device history, tenant log, unresolved-observation backlog, agent activity |
| `device_ports` | `idx_ports_device` | Port history per device |
| `services` | *(none — see Section 6)* | — |
| `alerts` | `idx_alerts_org_unresolved` (partial, `WHERE resolved_at IS NULL`), `idx_alerts_device_active`, `idx_alerts_site` | Dashboard unresolved-alert count stays fast as the table grows |
| `analyst_notes` | `idx_analyst_notes_user`, `idx_analyst_notes_device` | Note lookups |
| `audit_log` | `idx_audit_log_org_time`, `idx_audit_log_entity` | Tenant activity feed, per-entity audit trail |

---

## 6. Design Notes and Open Items

### 6.1 `services` table has no defined index

Every other table with a `device_id` or `(organization_id, site_id)`
pattern has a supporting index; `services` does not yet. Add
`CREATE INDEX idx_services_device ON services (device_id, observation_id);`
once query patterns against this table are known — premature indexing
without real query patterns risks indexing the wrong columns.

### 6.2 No UNIQUE constraint on `device_fingerprint_signals`

There is no `UNIQUE (device_id, signal_type, signal_value)` constraint.
The application layer (`repositories/signals.py`) handles this with an
explicit check-then-act pattern (`get_existing_signal()` before
`insert_signal()`) rather than relying on `ON CONFLICT`. This is
intentional for now but worth revisiting if a race condition between
concurrent identity resolution processes ever produces duplicate
signal rows in practice.

### 6.3 `ck_audit_log_entity_type` will need updates

The CHECK constraint on `audit_log.entity_type` currently allows
`device`, `alert`, `user`, `site`, `agent`. If audit logging is
extended to cover mutations on `network_segments` or other entities,
this constraint needs a corresponding migration.

### 6.4 Row-Level Security is scaffolded but not active

`ENABLE ROW LEVEL SECURITY` statements and an example tenant-isolation
policy exist in the schema as commented-out SQL, ready for activation
once the application sets `app.current_org_id` via `current_setting()`
on each connection. This is intentionally deferred — see
`docs/owasp-controls-mapping.md` Section 7 for the activation plan.

### 6.5 `organization_id` FK enforcement is now real

Unlike the SQLite version, every tenant-scoped table has an actual
`FOREIGN KEY ... REFERENCES organization(id)` constraint. This closes
a gap noted in earlier revisions of this document and the OWASP
mapping — orphaned tenant data is no longer structurally possible.

---

## 7. Planned Post-MVP Additions

| Addition | Rationale |
|---|---|
| RLS policy activation | Schema scaffold exists; needs `app.current_org_id` wiring at the connection layer |
| `alerts.metadata` as JSONB | Currently `VARCHAR(1000)`; JSONB would allow indexed queries on alert metadata |
| `services` table index | See 6.1 |
| Observations archival strategy | The table grows with every scan cycle; needs a partition or cold-storage plan at scale |
| Alert suppression window | Prevent re-firing the same alert immediately after resolution |
| Alert escalation | Increase severity when a device exceeds 2x its missing threshold |

---

## 8. Version History

| Version | Database | Changes |
|---|---|---|
| 1.0 | SQLite | Initial schema — `devices`, `observations`, `agents`, `device_ports`, `alerts`. |
| 1.1 | SQLite | Added `device_fingerprint_signals`. Replaced fingerprint black-box with raw signal storage. Added `match_confidence`, `match_method`. Removed `matched_device_id`. |
| 1.2 | SQLite | Added `organization`, `users`, `sites` with business hours. Added `seen_count`, `missing_threshold_hours`, `classification_source`. Added `scan_tier`. Added `is_expected`, `banner`. Added `severity`, `alert_status`, `alert_message`, `alert_type`. Added `analyst_notes`. |
| 1.3 | SQLite | Added `payload_hash` for deduplication. Fixed SQLite compatibility issues. |
| **2.0** | **PostgreSQL** | Full migration off SQLite. Added `sessions` (server-side revocation), `network_segments` (replaces free-text), `services` (per-observation state), `audit_log` (immutable human-action trail). Switched `identity_strength` / `confidence` / `match_confidence` from `REAL` (0.0–1.0) to `SMALLINT` (0–100). Added `oauth_provider` / `oauth_subject` to `users`, removed any password storage. Added `failed_login_count` / `lockout_until` for brute-force tracking. Added `CITEXT` for case-insensitive email. Added `fn_set_updated_at()` trigger — `updated_at` no longer requires manual maintenance. Added named constraints throughout. Added RLS scaffold (inactive). Added `UNIQUE (payload_hash)` on `observations` — deduplication became a schema guarantee rather than an application-layer check. |
