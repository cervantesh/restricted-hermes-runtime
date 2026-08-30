from pathlib import Path
import pytest

from restricted_runtime.migration_runner import migration_sql


def test_migration_grants_are_rendered_only_for_the_two_runtime_iam_users():
    statements=migration_sql(Path("migrations"),"conversation@example.com","gateway@example.com")
    assert len(statements)==2
    assert 'GRANT restricted_content_runtime TO "conversation@example.com"' in statements[1]
    assert 'GRANT restricted_ledger_runtime TO "gateway@example.com"' in statements[1]
    with pytest.raises(RuntimeError):migration_sql(Path("migrations"),"", "gateway@example.com")
