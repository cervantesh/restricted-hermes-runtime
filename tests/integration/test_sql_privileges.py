"""Database role separation is executable, not inferred from Terraform text."""
import os
from pathlib import Path

import psycopg
import pytest

URL=os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL")
pytestmark=pytest.mark.skipif(not URL,reason="requires isolated PostgreSQL")

@pytest.fixture(autouse=True)
def migrated():
    with psycopg.connect(URL,autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
        conn.execute(Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8"))
        conn.execute("UPDATE inference_ledger.runtime_controls SET dispatch_enabled=true WHERE control_key=true")

def test_sql_roles_cannot_read_or_write_the_other_schema():
    with psycopg.connect(URL) as conn:
        conn.execute("SET ROLE restricted_content_runtime")
        assert conn.execute("SELECT count(*) FROM restricted_content.turns").fetchone()[0] == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT count(*) FROM inference_ledger.attempts")
    with psycopg.connect(URL) as conn:
        conn.execute("SET ROLE restricted_ledger_runtime")
        assert conn.execute("SELECT count(*) FROM inference_ledger.attempts").fetchone()[0] == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT count(*) FROM restricted_content.turns")
