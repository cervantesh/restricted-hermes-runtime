"""One-shot migration entry point for the isolated synthetic migration job."""
from __future__ import annotations

import os
from pathlib import Path
from urllib.request import Request, urlopen


def migration_sql(directory: Path, conversation_user: str, gateway_user: str) -> list[str]:
    first = (directory / "001_restricted_runtime.sql").read_text(encoding="utf-8")
    grants = (directory / "002_synthetic_iam_role_grants.sql.tmpl").read_text(encoding="utf-8")
    rendered = grants.replace("${CONVERSATION_IAM_DB_USER}", conversation_user).replace("${GATEWAY_IAM_DB_USER}", gateway_user)
    if "${" in rendered or not conversation_user or not gateway_user:
        raise RuntimeError("closed migration grants render failed")
    return [first, rendered]


def validate_admin_dsn(dsn: str, expected_socket: str) -> None:
    from psycopg.conninfo import conninfo_to_dict

    values = conninfo_to_dict(dsn)
    if values.get("host") != expected_socket or not values.get("user") or not values.get("password"):
        raise RuntimeError("migration admin DSN must use the expected private Cloud SQL socket and password authentication")


def verify_post_migration(connection: object, conversation_user: str, gateway_user: str) -> None:
    """Validate the committed grants from a separate administrative connection."""
    schemas = {row[0] for row in connection.execute("SELECT nspname FROM pg_namespace WHERE nspname IN ('restricted_content', 'inference_ledger')").fetchall()}
    if schemas != {"restricted_content", "inference_ledger"}:
        raise RuntimeError("restricted migration schemas are incomplete")
    roles = {row[0] for row in connection.execute("SELECT rolname FROM pg_roles WHERE rolname IN ('restricted_content_runtime', 'restricted_ledger_runtime')").fetchall()}
    if roles != {"restricted_content_runtime", "restricted_ledger_runtime"}:
        raise RuntimeError("restricted runtime roles are incomplete")
    memberships = set(connection.execute(
        """
        SELECT member_role.rolname, granted_role.rolname
        FROM pg_auth_members membership
        JOIN pg_roles member_role ON member_role.oid = membership.member
        JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
        WHERE granted_role.rolname IN ('restricted_content_runtime', 'restricted_ledger_runtime')
        """
    ).fetchall())
    if memberships != {(conversation_user, "restricted_content_runtime"), (gateway_user, "restricted_ledger_runtime")}:
        raise RuntimeError("restricted runtime role membership is not exclusive")
    if connection.execute("SELECT has_table_privilege(%s, 'inference_ledger.runtime_controls', 'UPDATE')", (gateway_user,)).fetchone()[0]:
        raise RuntimeError("gateway runtime role must not update dispatch controls")
    cross_scope = connection.execute(
        "SELECT has_schema_privilege(%s, 'inference_ledger', 'USAGE') OR has_schema_privilege(%s, 'restricted_content', 'USAGE')",
        (conversation_user, gateway_user),
    ).fetchone()[0]
    if cross_scope:
        raise RuntimeError("runtime IAM users must not retain cross-schema usage")
    public_usage = connection.execute(
        "SELECT has_schema_privilege('PUBLIC', 'restricted_content', 'USAGE') OR has_schema_privilege('PUBLIC', 'inference_ledger', 'USAGE')"
    ).fetchone()[0]
    if public_usage:
        raise RuntimeError("PUBLIC must not retain schema usage")
    count, disabled = connection.execute(
        "SELECT count(*), bool_and(dispatch_enabled = false) FROM inference_ledger.runtime_controls"
    ).fetchone()
    if count != 1 or disabled is not True:
        raise RuntimeError("dispatch control must be exactly one disabled row")


def execute_migration(dsn: str, directory: Path, conversation_user: str, gateway_user: str, expected_socket: str, connect: object) -> None:
    """Commit migrations, then verify their durable privilege boundary separately."""
    validate_admin_dsn(dsn, expected_socket)
    with connect(dsn) as connection:
        for statement in migration_sql(directory, conversation_user, gateway_user):
            connection.execute(statement)
    with connect(dsn) as verification_connection:
        verify_post_migration(verification_connection, conversation_user, gateway_user)


def shutdown_proxy(timeout_seconds: float = 3) -> None:
    request = Request("http://127.0.0.1:9091/quitquitquit", method="POST")
    with urlopen(request, timeout=timeout_seconds) as response:
        if response.status not in (200, 204):
            raise RuntimeError("Cloud SQL proxy quitquitquit endpoint rejected shutdown")


def run_from_environment(connect: object) -> None:
    dsn = os.environ.get("MIGRATION_ADMIN_DSN")
    directory = os.environ.get("RESTRICTED_MIGRATIONS_DIR")
    conversation = os.environ.get("CONVERSATION_IAM_DB_USER")
    gateway = os.environ.get("GATEWAY_IAM_DB_USER")
    expected_socket = os.environ.get("RESTRICTED_EXPECTED_MIGRATION_SOCKET")
    if not all((dsn, directory, conversation, gateway, expected_socket)):
        raise RuntimeError("migration bootstrap input is incomplete")
    execute_migration(dsn, Path(directory), conversation, gateway, expected_socket, connect)


def main(*, connect: object | None = None, proxy_shutdown: object = shutdown_proxy) -> None:
    primary_error: BaseException | None = None
    try:
        if connect is None:
            import psycopg

            connect = psycopg.connect
        run_from_environment(connect)
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            proxy_shutdown()
        except Exception as shutdown_error:
            if primary_error is None:
                raise RuntimeError("Cloud SQL proxy shutdown failed") from shutdown_error


if __name__ == "__main__":
    main()
