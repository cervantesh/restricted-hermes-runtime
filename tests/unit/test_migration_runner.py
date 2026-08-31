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


def test_main_always_requests_proxy_shutdown_after_a_successful_migration(monkeypatch):
    calls=[]
    monkeypatch.setattr(migration_runner,"run_from_environment",lambda connect: calls.append(("migration",connect)))
    migration_runner.main(connect="connection-factory",proxy_shutdown=lambda: calls.append(("shutdown",None)))
    assert calls==[("migration","connection-factory"),("shutdown",None)]


def test_main_preserves_the_primary_migration_error_when_proxy_shutdown_also_fails(monkeypatch):
    def primary_failure(connect):
        raise ValueError("primary migration failure")
    monkeypatch.setattr(migration_runner,"run_from_environment",primary_failure)
    with pytest.raises(ValueError,match="primary migration failure"):
        migration_runner.main(connect="connection-factory",proxy_shutdown=lambda: (_ for _ in ()).throw(RuntimeError("proxy failure")))


def test_main_fails_when_proxy_shutdown_fails_after_successful_migration(monkeypatch):
    monkeypatch.setattr(migration_runner,"run_from_environment",lambda connect: None)
    with pytest.raises(RuntimeError,match="proxy shutdown failed"):
        migration_runner.main(connect="connection-factory",proxy_shutdown=lambda: (_ for _ in ()).throw(OSError("proxy failure")))


def test_proxy_shutdown_uses_only_the_local_quitquitquit_endpoint(monkeypatch):
    seen=[]
    class Response:
        status=200
        def __enter__(self): return self
        def __exit__(self,*args): return False
    monkeypatch.setattr(migration_runner,"urlopen",lambda request,timeout: (seen.append((request.full_url,request.get_method(),timeout)) or Response()))
    migration_runner.shutdown_proxy(timeout_seconds=1)
    assert seen==[("http://127.0.0.1:9091/quitquitquit","POST",1)]


def test_proxy_shutdown_rejects_a_failed_quitquitquit_response(monkeypatch):
    class Response:
        status=503
        def __enter__(self): return self
        def __exit__(self,*args): return False
    monkeypatch.setattr(migration_runner,"urlopen",lambda request,timeout: Response())
    with pytest.raises(RuntimeError,match="rejected shutdown"):
        migration_runner.shutdown_proxy()
