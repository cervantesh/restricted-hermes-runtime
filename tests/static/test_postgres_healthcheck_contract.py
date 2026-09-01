"""The local Compose health gate must not accept the init-time postgres server."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _healthy(pid1_comm: str, pg_isready_exit: int) -> bool:
    """Semantic model of the intentionally tiny shell health gate."""
    return pid1_comm == "postgres" and pg_isready_exit == 0


def test_temporary_entrypoint_server_is_not_healthy_even_when_pg_isready_passes():
    # docker-entrypoint runs a temporary postgres server while init scripts are
    # still executing, so pg_isready alone is not an application-ready gate.
    assert not _healthy("docker-entrypoint", 0)


def test_final_execed_postgres_server_remains_healthy_when_ready():
    assert _healthy("postgres", 0)
    assert not _healthy("postgres", 1)


def test_compose_uses_the_pid1_gate_and_the_existing_database_probe():
    compose = (ROOT / "deploy/local/compose.yaml").read_text(encoding="utf-8")
    assert r'test: ["CMD-SHELL", "test \"$$(cat /proc/1/comm)\" = postgres && pg_isready -h /run/restricted-postgres -U postgres -d restricted_runtime"]' in compose
