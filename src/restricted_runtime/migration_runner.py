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


def main() -> None:
    dsn=os.environ.get("MIGRATION_ADMIN_DSN")
    directory=os.environ.get("RESTRICTED_MIGRATIONS_DIR")
    conversation=os.environ.get("CONVERSATION_IAM_DB_USER")
    gateway=os.environ.get("GATEWAY_IAM_DB_USER")
    if not all((dsn,directory,conversation,gateway)):
        raise RuntimeError("migration bootstrap input is incomplete")
    import psycopg
    with psycopg.connect(dsn) as connection:
        for statement in migration_sql(Path(directory),conversation,gateway):
            connection.execute(statement)


if __name__ == "__main__": main()
