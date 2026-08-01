# db.py
"""
Author: Me
Date: 2026-05-10
Version: 2.0
Description: PostgreSQL connection factory for LAN Atlas using SQLAlchemy Core.

All engine code obtains connections through get_db().
To switch databases, change DATABASE_URL in .env only.

Usage (production):
    with get_db() as db:
        db.execute(text("SELECT ..."), {"key": val})

Usage (testing):
    conn = get_test_db()
    setup_db(conn)
    # run tests
    conn.close()

NOTE: SQLAlchemy 2.x (future=True) requires raw SQL wrapped in text():
    from sqlalchemy import text
    db.execute(text("SELECT * FROM devices WHERE id = :id"), {"id": device_id})
    Named parameters use :name syntax — not ? or %s.
"""

import os
from contextlib import contextmanager
from dotenv import load_dotenv
from sqlalchemy import create_engine

load_dotenv()

# ─────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is not set. "
        "Add it to your .env file. "
        "Expected format: postgresql://user:password@host:port/dbname"
    )

# ─────────────────────────────────────────
# Engine
# ─────────────────────────────────────────

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,    # drops stale connections before handing to caller
    pool_recycle=3600,     # recycle connections older than 1 hour
    pool_size=5,           # baseline pool — increase for production load
    max_overflow=10,       # allows burst up to 15 total connections
    future=True,           # SQLAlchemy 2.x mode
)

# ─────────────────────────────────────────
# Public Interface
# ─────────────────────────────────────────

@contextmanager
def get_db():
    """
    Context manager yielding a SQLAlchemy Core connection.

    Commits on clean exit, rolls back on exception, always closes.
    Wraps every request in an explicit transaction.

    Usage:
        with get_db() as db:
            db.execute(text("SELECT * FROM devices WHERE id = :id"), {"id": 1})
    """
    conn = engine.connect()
    trans = conn.begin()
    try:
        yield conn
        trans.commit()
    except Exception:
        trans.rollback()
        raise
    finally:
        conn.close()


def get_test_db():
    """
    Returns a configured SQLAlchemy connection for use in tests.
    Caller is responsible for closing the connection.

    Usage:
        conn = get_test_db()
        setup_db(conn)
        # run tests
        conn.close()
    """
    conn = engine.connect()
    conn.begin()
    return conn


def get_database_url() -> str:
    """
    Returns the active DATABASE_URL.
    Useful for logging and diagnostics.
    Never log this in production — it contains credentials.
    """
    return DATABASE_URL