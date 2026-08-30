from pathlib import Path
import pytest

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
