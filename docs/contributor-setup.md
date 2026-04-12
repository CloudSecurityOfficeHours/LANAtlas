# Contributor Setup

This guide walks contributors through setting up a local Python virtual environment and configuring environment variables for LAN Atlas.

## Prerequisites

Before you begin, make sure you have:

- Git installed
- Python 3 installed
- Access to this repository

You can check your Python version with:

```bash
python3 --version
```

or on some systems:

```bash
python --version
```

## 1. Clone the repository

```bash
git clone <your-repo-url>
cd lan-atlas
```

Replace `<your-repo-url>` with the actual repository URL.

## 2. Create a virtual environment

Create a local virtual environment named `.venv`.

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

After activation, your terminal should show that the virtual environment is active.

## 3. Install dependencies

If the project uses a `requirements.txt` file, run:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

If the project later uses a different dependency manager, follow the project-specific instructions in the repository.

## 4. Create your local environment file

This project uses a local `.env` file for development settings.

Copy the example file:

### macOS / Linux

```bash
cp .env.example .env
```

### Windows PowerShell

```powershell
Copy-Item .env.example .env
```

## 5. Update `.env` with your local values

Open `.env` and replace placeholder values such as `change-me` with safe local development values.

The repository should include a `.env.example` file similar to this:

```dotenv
# =========================================================
# LAN Atlas - example environment file
# Copy this file to .env for local development
# Do not put real secrets in this file
# =========================================================

# App environment
APP_ENV=development
DEBUG=true
LOG_LEVEL=INFO

# App server
APP_HOST=127.0.0.1
APP_PORT=8000
SECRET_KEY=change-me

# Database
DATABASE_URL=sqlite:///./lan_atlas.db

# Agent / API auth
AGENT_SHARED_SECRET=change-me
API_TOKEN_EXPIRY_HOURS=24

# AWS
AWS_REGION=us-east-1
AWS_S3_BUCKET=your-bucket-name
AWS_DYNAMODB_TABLE=lan-atlas
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

# Alerts / email
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USER=
SMTP_PASSWORD=
ALERT_FROM_EMAIL=alerts@example.com

# Scanning defaults
DEFAULT_SCAN_SUBNET=192.168.1.0/24
SCAN_TIMEOUT_SECONDS=2
SCAN_MAX_HOSTS=1024

# Dashboard / frontend
DASHBOARD_ORIGIN=http://localhost:3000
```

## 6. Keep secrets out of git

Never commit real secrets or local-only files.

Important rules:

- `.env.example` is committed to the repository as a template
- `.env` stays local on your machine
- Do not commit API keys, AWS credentials, certificates, packet captures, logs, or local databases

## 7. Confirm `.env` is ignored

Before committing anything, check Git status:

```bash
git status
```

You should **not** see `.env` listed as a file to be committed.

If `.env` appears in Git, stop and fix that before pushing.

## 8. Deactivate the virtual environment

When you are done working:

```bash
deactivate
```

## Recommended first-time setup

### macOS / Linux

```bash
git clone <your-repo-url>
cd lan-atlas
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

### Windows PowerShell

```powershell
git clone <your-repo-url>
cd lan-atlas
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Then open `.env` and update the placeholder values before running the project.

## Troubleshooting

### `python3: command not found`

Try:

```bash
python --version
```

If that works, use `python` instead of `python3`.

### Virtual environment activation is blocked on Windows

If PowerShell blocks activation, you may need to allow local scripts for your user account. Open PowerShell and run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then try activating the virtual environment again.

### `.env` is already being tracked by git

If `.env` was accidentally added before `.gitignore` was updated, untrack it with:

```bash
git rm --cached .env
```

Then commit the removal.

## Notes for contributors using AI coding tools

If you use tools such as Claude, Cursor, or ChatGPT-assisted workflows:

- Do not commit personal assistant settings unless the team explicitly wants shared instructions in the repo
- Do not paste secrets into prompts
- Do not upload real customer or network data into external tools unless approved
- Keep local tool state and personal config files out of version control

