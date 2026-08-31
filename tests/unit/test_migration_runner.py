from pathlib import Path
import pytest

import restricted_runtime.migration_runner as migration_runner
from restricted_runtime.migration_runner import migration_sql, validate_admin_dsn


def test_migration_grants_are_rendered_only_for_the_two_runtime_iam_users():
    statements=migration_sql(Path("migrations"),"conversation@example.com","gateway@example.com")
    assert len(statements)==2
    assert 'GRANT restricted_content_runtime TO "conversation@example.com"' in statements[1]
    assert 'GRANT restricted_ledger_runtime TO "gateway@example.com"' in statements[1]
    with pytest.raises(RuntimeError):migration_sql(Path("migrations"),"", "gateway@example.com")


def test_migration_admin_dsn_is_password_auth_over_exact_private_socket():
    socket="/cloudsql/project:us-central1:instance"
    validate_admin_dsn(f"host={socket} dbname=postgres user=operator password=opaque",socket)
    with pytest.raises(RuntimeError,match="expected private Cloud SQL socket"):
        validate_admin_dsn("host=127.0.0.1 dbname=postgres user=operator password=opaque",socket)
    with pytest.raises(RuntimeError,match="password authentication"):
        validate_admin_dsn(f"host={socket} dbname=postgres user=operator",socket)


def test_main_runs_only_migration_and_postflight_path(monkeypatch):
    calls=[]
    monkeypatch.setattr(migration_runner,"run_from_environment",lambda connect: calls.append(("migration",connect)))
    migration_runner.main(connect="connection-factory")
    assert calls==[("migration","connection-factory")]


def test_main_propagates_the_migration_or_postflight_error_unchanged(monkeypatch):
    def primary_failure(connect):
        raise ValueError("primary migration failure")
    monkeypatch.setattr(migration_runner,"run_from_environment",primary_failure)
    with pytest.raises(ValueError,match="primary migration failure"):
        migration_runner.main(connect="connection-factory")


def test_migration_runner_has_no_local_proxy_shutdown_side_channel():
    source=Path(migration_runner.__file__).read_text(encoding="utf-8")
    for forbidden in ("shutdown_proxy", "quitquitquit", "urlopen", "urllib"):
        assert forbidden not in source


def test_post_migration_verification_queries_public_as_oid_zero_with_parameters():
    class Cursor:
        def __init__(self, one=None, many=None): self.one=one; self.many=many or []
        def fetchone(self): return self.one
        def fetchall(self): return self.many
    class Connection:
        def __init__(self): self.calls=[]
        def execute(self, sql, params=None):
            self.calls.append((sql,params))
            if "pg_namespace" in sql: return Cursor(many=[("restricted_content",),("inference_ledger",)])
            if "pg_auth_members" in sql: return Cursor(many=[("conversation", "restricted_content_runtime"),("gateway", "restricted_ledger_runtime")])
            if "pg_roles" in sql: return Cursor(many=[("restricted_content_runtime",),("restricted_ledger_runtime",)])
            if "has_table_privilege" in sql: return Cursor(one=(False,))
            if "runtime_controls" in sql: return Cursor(one=(1,True))
            if "has_schema_privilege" in sql and "PUBLIC" not in sql: return Cursor(one=(False,))
            raise AssertionError("PUBLIC must be represented only by the OID parameter")
    connection=Connection()
    migration_runner.verify_post_migration(connection,"conversation","gateway")
    public_calls=[params for sql,params in connection.calls if "has_schema_privilege(%s::oid" in sql]
    assert public_calls==[(0,0)]
