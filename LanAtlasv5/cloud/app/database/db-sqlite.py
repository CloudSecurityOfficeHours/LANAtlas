# db.py
"""
Author: Me
Date: 2026-05-10
Version: 1.5
Description: Central database connection factory for LAN Atlas.

All engine code should obtain connections through this module.
To migrate from SQLite to MySQL/PostgreSQL, change this file only.

Usage:
    # Production
    with get_db() as db:
        result = resolve_observation(observation, db)

    # Testing (in-memory, no file)
    db = get_test_db()
"""

import os
import sqlite3
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────

# Read from .env — expected format: sqlite:///data/lanatlas.db
# Falls back to a safe default if not set
_RAW_URL = os.getenv("DATABASE_URL", "sqlite:///data/lanatlas.db")

def _parse_sqlite_path(url: str) -> str:
    """
    Extract the file path from a sqlite:/// URL.

    sqlite:///data/lanatlas.db  → data/lanatlas.db  (relative)
    sqlite:////abs/path/db      → /abs/path/db      (absolute)
    """
    if not url.startswith("sqlite:///"):
        raise ValueError(
            f"DATABASE_URL must start with sqlite:/// for SQLite. Got: {url}\n"
            "When migrating to MySQL/PostgreSQL, update db.py to handle "
            "the new connection string format."
        )
    return url[len("sqlite:///"):]


_DB_PATH = _parse_sqlite_path(_RAW_URL)


# ─────────────────────────────────────────
# Connection Setup
# ─────────────────────────────────────────

def _configure(connection: sqlite3.Connection) -> sqlite3.Connection:
    """
    Apply standard configuration to every connection.

    - Row factory: allows column access by name (row["column_name"])
    - Foreign keys: SQLite disables FK enforcement by default.
      This PRAGMA enables it so schema constraints are actually enforced.
    """
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


# ─────────────────────────────────────────
# Public Interface
# ─────────────────────────────────────────

@contextmanager
def get_db():
    """
    Context manager that yields a configured SQLite connection.
    Commits on clean exit, rolls back on exception, always closes.

    Usage:
        with get_db() as db:
            db.execute("SELECT ...")
    """
    # ensure the data directory exists
    db_dir = os.path.dirname(_DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    connection = sqlite3.connect(_DB_PATH)
    _configure(connection)

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_test_db() -> sqlite3.Connection:
    """
    Returns a configured in-memory SQLite connection for use in tests.

    Does NOT load the schema — tests are responsible for calling
    setup_db() to initialize tables. This keeps schema control
    explicit and test-local.

    Usage:
        db = get_test_db()
        # then pass to setup_db() or use directly
    """
    connection = sqlite3.connect(":memory:")
    _configure(connection)
    return connection


def get_db_path() -> str:
    """
    Returns the resolved database file path.
    Useful for logging and diagnostics.
    """
    return _DB_PATH