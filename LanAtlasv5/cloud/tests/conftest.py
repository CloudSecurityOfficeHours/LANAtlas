"""
tests/conftest.py

Shared pytest fixtures for LAN Atlas cloud tests.

Requires a real PostgreSQL test database with the schema already
applied via Alembic (`alembic upgrade head` pointed at a dedicated
test DATABASE_URL — never point tests at production or shared dev).

There is no in-memory equivalent for PostgreSQL, so this replaces the
old setup_db()-per-test SQLite pattern with transaction rollback:
each test runs inside its own uncommitted transaction, and the `db`
fixture rolls it back afterward. Nothing a test writes — including
ON CONFLICT upserts and trigger side effects like fn_set_updated_at
— persists beyond that single test.

This is deliberately real PostgreSQL, not a mock or in-memory stand-in:
tests exercise actual RETURNING, ON CONFLICT, CHECK constraints, and
triggers, so a passing test means the code will behave the same way
in production.
"""

import pytest
from database.db import get_test_db


@pytest.fixture
def db():
    conn = get_test_db()
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()
