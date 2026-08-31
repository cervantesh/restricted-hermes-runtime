"""Real PostgreSQL proof of the migration runner's committed privilege boundary."""
import os
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict

from restricted_runtime.migration_runner import execute_migration


URL = os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="requires isolated PostgreSQL")


def test_migration_commits_then_verifies_exclusive_roles_on_a_second_connection():
    conversation = "rhrt_postflight_conversation"
    gateway = "rhrt_postflight_gateway"
    with psycopg.connect(URL, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
        connection.execute(f'DROP ROLE IF EXISTS "{conversation}"; DROP ROLE IF EXISTS "{gateway}"')
        connection.execute(f'CREATE ROLE "{conversation}" NOLOGIN; CREATE ROLE "{gateway}" NOLOGIN')
    opened = []

    def tracked_connect(dsn: str):
        opened.append(dsn)
        return psycopg.connect(dsn)

    try:
        expected_socket = conninfo_to_dict(URL).get("host")
        execute_migration(URL, Path("migrations"), conversation, gateway, expected_socket, tracked_connect)
        assert len(opened) == 2
        with psycopg.connect(URL) as connection:
            memberships = set(connection.execute(
                """
                SELECT member_role.rolname, granted_role.rolname
                FROM pg_auth_members membership
                JOIN pg_roles member_role ON member_role.oid = membership.member
                JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
                WHERE granted_role.rolname IN ('restricted_content_runtime', 'restricted_ledger_runtime')
                """
            ).fetchall())
            assert memberships == {(conversation, "restricted_content_runtime"), (gateway, "restricted_ledger_runtime")}
            assert not connection.execute("SELECT has_schema_privilege(%s, 'inference_ledger', 'USAGE')", (conversation,)).fetchone()[0]
            assert not connection.execute("SELECT has_schema_privilege(%s, 'restricted_content', 'USAGE')", (gateway,)).fetchone()[0]
            assert not connection.execute("SELECT has_table_privilege(%s, 'inference_ledger.runtime_controls', 'UPDATE')", (gateway,)).fetchone()[0]
            assert not connection.execute("SELECT has_schema_privilege(%s::oid, 'restricted_content', 'USAGE') OR has_schema_privilege(%s::oid, 'inference_ledger', 'USAGE')", (0,0)).fetchone()[0]
            assert connection.execute("SELECT count(*), bool_and(dispatch_enabled = false) FROM inference_ledger.runtime_controls").fetchone() == (1, True)
    finally:
        with psycopg.connect(URL, autocommit=True) as connection:
            connection.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
            connection.execute(f'DROP ROLE IF EXISTS "{conversation}"; DROP ROLE IF EXISTS "{gateway}"')
