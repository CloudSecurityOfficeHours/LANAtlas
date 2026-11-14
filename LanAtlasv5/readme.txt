Lan Atlas version 5 

In version 5, Lan Atlas's structure changed from an SQLAlchemy ORM Model to a structure that splits Lan Atlas into cloud, agent, and protocol. Agent runs on customer's networks. Cloud runs on AWS. Agent never imports from cloud, cloud never imports from agent. Protocol is the only shared surface. 
Both sides import ObservationV1 from protocol/schemas/observation_v1.py — that's genuinely the sole coupling point between them. It's deliberately thin (Pydantic models, a version file, a changelog) so it never drags cloud-side or agent-side dependencies into the other's install.

## Architecture Rules

1. `api/` calls `services/` only — never `repositories/` or `database/` directly
2. `services/` calls `repositories/` only — never `database/` directly
3. `repositories/` calls `database/` only — all SQL lives here
4. `workers/` follows the same rules as `api/` — calls `services/` only
5. No raw SQL strings outside `repositories/`



What This Structure Does Not Yet Decide

Being straight with you — three real gaps remain that matter specifically for the "on-prem" half of this:

1. Agent packaging and distribution is undefined. Right now agent/ is just Python source files. How does a customer actually install and run this? A pip package they pip install? A PyInstaller-built standalone binary? A Docker container? A systemd service file? This affects how requirements.txt gets used and whether agent/ needs a setup.py or pyproject.toml and a build step. This isn't a structural gap in the folder tree — it's a decision the tree doesn't make for you yet.

2. Local persistence for buffer.py isn't specified. The offline-buffering requirement means the agent needs some local storage that survives a restart — otherwise a buffered observation is lost if the agent process dies before it reconnects. That's almost certainly a local SQLite file (lightweight, no server needed, fits the "agent stays minimal" principle), but nothing in the structure names that file or where it lives on the customer's machine.

3. How the agent discovers the cloud API URL and initial credentials isn't addressed. agent/.env having the cloud API URL and API key assumes those values got there somehow — that's an onboarding/provisioning flow (a registration endpoint, a one-time setup token, a config file the customer downloads from the dashboard) that doesn't exist as a folder yet, possibly api/routes/agents.py handling a /register endpoint.


