# LANAtlas

LAN Atlas is a lightweight, cloud-hosted network visibility SaaS designed for solo IT admins and small MSPs. It uses on-prem agents to scan local networks and securely send observations to a centralized cloud service, providing simple dashboards, alerts, and exports that explain what devices exist, what changed, and what needs attention.
The MVP focuses on proving end-to-end agent → cloud → dashboard workflows while remaining intentionally minimal and production-minded.

Functional Requirements
On-prem agent that:
- Scans configured subnets (ping/ARP + limited ports)
- Sends signed observations and heartbeats to cloud API

Cloud service that:
- Supports orgs, sites, agents, devices, observations
- Provides per-site dashboards and alerts
- Supports CSV/JSON exports
Alerting for:
- New device detected
- Device missing for N hours
- New open port on existing device

Non-Functional Requirements
- Secure agent-to-cloud communication (API keys)
- Multi-tenant data isolation
- Resilient agent behavior (buffering, retries)
- Cloud deployment using AWS best practices
- Clean, maintainable Python codebase

See [Contributor Setup](docs/contributor-setup.md) for local environment and `.env` instructions.