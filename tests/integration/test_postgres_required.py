"""Integration proof refuses to pretend SQLite/mocks establish database semantics."""
import os
from pathlib import Path

import psycopg
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="PostgreSQL integration unavailable: DATABASE_URL is not configured; SQLite/mocks are prohibited")

def test_migration_requires_real_postgresql():
    assert DATABASE_URL and DATABASE_URL.startswith(("postgresql://", "postgres://"))
    migration = Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version(), transaction_timestamp()")
            assert "PostgreSQL" in cur.fetchone()[0]
            # The migration itself remains an operator-owned isolated database action.
            assert "one_active_turn_per_conversation" in migration
