"""One-shot migration entry point for the isolated synthetic migration job."""
from __future__ import annotations
import os
from pathlib import Path


def migration_sql(directory: Path, conversation_user: str, gateway_user: str) -> list[str]:
    first=(directory / "001_restricted_runtime.sql").read_text(encoding="utf-8")
    grants=(directory / "002_synthetic_iam_role_grants.sql.tmpl").read_text(encoding="utf-8")
    rendered=grants.replace("${CONVERSATION_IAM_DB_USER}",conversation_user).replace("${GATEWAY_IAM_DB_USER}",gateway_user)
    if "${" in rendered or not conversation_user or not gateway_user:
        raise RuntimeError("closed migration grants render failed")
    return [first,rendered]


def validate_admin_dsn(dsn: str, expected_socket: str) -> None:
    from psycopg.conninfo import conninfo_to_dict
    values=conninfo_to_dict(dsn)
    if values.get("host") != expected_socket or not values.get("user") or not values.get("password"):
        raise RuntimeError("migration admin DSN must use the expected private Cloud SQL socket and password authentication")


def main() -> None:
    dsn=os.environ.get("MIGRATION_ADMIN_DSN")
    directory=os.environ.get("RESTRICTED_MIGRATIONS_DIR")
    conversation=os.environ.get("CONVERSATION_IAM_DB_USER")
    gateway=os.environ.get("GATEWAY_IAM_DB_USER")
    expected_socket=os.environ.get("RESTRICTED_EXPECTED_MIGRATION_SOCKET")
    if not all((dsn,directory,conversation,gateway,expected_socket)):
        raise RuntimeError("migration bootstrap input is incomplete")
    import psycopg
    validate_admin_dsn(dsn,expected_socket)
    with psycopg.connect(dsn) as connection:
        for statement in migration_sql(Path(directory),conversation,gateway):
            connection.execute(statement)


if __name__ == "__main__": main()
