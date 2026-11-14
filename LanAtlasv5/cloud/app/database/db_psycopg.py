"""
db.py - PostgreSQL connection factory using psycopg (v3)
Adapted from LAN Atlas v1.5
"""
import os
from contextlib import contextmanager
from dotenv import load_dotenv
import psycopg
from psycopg.rows import dict_row

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set.")

@contextmanager
def get_db():
    conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def get_test_db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)

def get_database_url():
    return DATABASE_URL
