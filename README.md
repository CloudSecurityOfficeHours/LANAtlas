# LAN Atlas

LAN Atlas is a lightweight, cloud-hosted network visibility SaaS for solo IT admins and small MSPs. On-prem agents scan local networks and securely send observations to a centralized cloud service, which provides dashboards, alerts, and exports that answer three questions: 

- what devices exist?
- what changed?
- what needs attention?

Development happens in the open through **Cloud Security Office Hours** ([`CloudSecurityOfficeHours`](https://github.com/CloudSecurityOfficeHours) on GitHub) as a hands-on exercise in building a production-minded system against real security frameworks.

---

## Security frameworks in active use

Every control decision in this project is checked against at least one of:

- **OWASP Top 10 (2025)** — web dashboard
- **OWASP API Security Top 10 (2023)** — agent-to-cloud API surface
- **OWASP ASVS** — verification-level requirements (sessions, auth, encoding)
- **NIST SP 800-53 / SP 800-61** — control baselines and incident handling
- **CIS Controls v8.1** (Control 1, Control 8, Control 16) — cross-check against schema/asset and logging gaps
- **MITRE ATT&CK** — threat modeling reference for the agent trust boundary

Control status is tracked continuously in `LAN_Atlas_OWASP_Controls_v3.docx` (v3.0), gap by gap, session by session. That document is the authoritative source of truth for control status. This README summarizes it.

---

## Functional requirements

**On-prem agent:**
- Scans configured subnets (ARP/ping + limited port checks)
- Signs observations and heartbeats (HMAC-SHA256) before sending to the cloud API
- Buffers locally and retries with exponential back-off during cloud outages

**Cloud service:**
- Supports organizations, sites, agents, devices, observations (multi-tenant)
- Per-site dashboards and alerts
- CSV/JSON exports

**Alerting for:**
- New device detected
- Device missing for N hours
- New open port on an existing device

## Non-functional requirements

- Secure agent-to-cloud communication (hashed API keys, HMAC-signed payloads, TLS 1.3)
- Multi-tenant data isolation (`organization_id` sourced from verified session, never request body)
- Resilient agent behavior (local buffering, retries)
- Cloud deployment on AWS following least-privilege and defense-in-depth practices
- Clean, typed, linted, tested Python codebase

---

## Current security posture

| Control area | Status | Notes |
|---|---|---|
| **A01 — Broken Access Control** | ✅ Implemented | FastAPI RBAC middleware: session-validated `get_current_user` dependency, `require_role()` factory, tenant scope from verified session only, 404-not-403 pattern to prevent resource enumeration. |
| **A02 — Security Misconfiguration** | 🟡 Partial | `fn_set_updated_at()` triggers, `.env`-sourced secrets, DB-layer FK/CHECK enforcement. AWS Secrets Manager migration and security-header/CORS policy still open. |
| **A03 — Software Supply Chain Failures** | 🟡 Partial | Dependabot (pip + GitHub Actions ecosystems) implemented. Super Linter runs in CI but does **not** close dependency CVE scanning, hash verification, signed commits, or artifact signing — those remain open. `pip-audit --strict` integration is next up (see Roadmap). |
| **A04 — Insecure Design** | ✅ Implemented | `slowapi` + ElastiCache Redis rate limiting keyed by agent ID; threshold-based volume anomaly detection on `idx_obs_agent_time`; bulk-resolve gated to admin role with alert ceiling + re-auth window. |
| **A06 / API4 — Rate Limiting & Resource Abuse** | ✅ Implemented | Same rate-limiting stack as above, applied to the agent-to-cloud API surface. |
| **A07 — Auth & Session Failures** | ✅ Implemented | OAuth 2.0/OIDC (Google/Microsoft/Okta), server-side `sessions` table with `token_hash`/`expires_at`/`revoked_at`, `failed_login_count` + `lockout_until` brute-force tracking. |
| **A08 — Data Integrity Failures** | 🟡 Partial | `payload_hash` (HMAC) on every observation for tamper/dedup detection. **Gap:** `agent_token` is currently stored plaintext — should be hashed consistent with the `api_key_hash` pattern on `agents`. |
| **A09 — Logging & Alerting Failures** | ⚪ Not started | Audit data exists (`observations`, `alerts`, `analyst_notes`, `sessions`) but there's no structured application-level logging framework and nothing ships to CloudWatch yet. |
| **Replay protection (agent payloads)** | ⚪ Planned — Sprint 3 | HMAC-SHA256 replay protection is the next hardening item on the agent-to-cloud path. |

Legend: ✅ Implemented · 🟡 Partial (closes some but not all of the control) · ⚪ Not started / planned

---

## Technology stack

| Layer | Technology | Purpose |
|---|---|---|
| API & Runtime | FastAPI ≥ 0.136 · Python 3 · Uvicorn | Async REST API, Pydantic validation on all request schemas |
| Database | PostgreSQL 18 · SQLAlchemy 2 · Alembic | Production DB, parameterized queries, migrations |
| Security | pwdlib (Argon2id) · PyJWT[crypto] · cryptography 44 | Password hashing (pre-OAuth fallback), JWT signing, HMAC-SHA256 |
| Auth | OAuth 2.0 / OIDC (Google, Microsoft, Okta) | Third-party identity; `oauth_provider` + `oauth_subject` as identity anchor |
| Rate limiting | `slowapi` · AWS ElastiCache Redis | Per-agent request throttling, anomaly detection |
| Background jobs | Dramatiq · Redis | Async alert email dispatch |
| Cloud | AWS (RDS, ECR, ElastiCache, CloudWatch) · boto3 | Deployment target, logs, alarms |
| Agent (on-prem) | Python 3 · scapy/ARP · SQLite buffer | Scanning, payload signing, local buffering, retry logic |
| Testing | pytest · pytest-cov · ruff · mypy | Unit/integration tests, coverage, linting, type safety |
| CI/CD | GitHub Actions · Docker* · Dependabot | Automated quality/security gates + container build |

Schema: PostgreSQL in production on AWS RDS- 15 tables, 31 named foreign keys, 32 named CHECK constraints. Full reference in `LAN_Atlas_LLD.docx`.

* Use of Docker not finalized 
---

## Contributing

See [Contributor Setup](docs/contributor-setup.md) for local environment and `.env` instructions. Branch naming, PR templates, and commit message conventions (present-tense type prefixes) are defined in `CONTRIBUTING.md`.

