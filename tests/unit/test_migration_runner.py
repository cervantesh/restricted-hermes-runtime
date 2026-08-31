from pathlib import Path
import pytest

import restricted_runtime.migration_runner as migration_runner
import restricted_runtime.migration_supervisor as migration_supervisor
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


class _Proxy:
    def __init__(self, *, wait_result=0):
        self.wait_result=wait_result
        self.terminated=False
    def poll(self): return None
    def terminate(self): self.terminated=True
    def wait(self, timeout): return self.wait_result


def _ready_proxy_supervisor(**overrides):
    process=overrides.pop("process",_Proxy())
    calls=[]
    defaults={
        "connection_name":"project:us-central1:restricted-synthetic-postgres",
        "socket_dir":Path("/cloudsql"),
        "run_migration":lambda connect: calls.append(("migration",connect)),
        "connect":"connection-factory",
        "popen":lambda command, **kwargs: (calls.append(("start",command)) or process),
        "readiness_probe":lambda: calls.append(("ready",None)),
        "prepare_socket":lambda path: calls.append(("socket",path)),
        "cleanup":lambda child: (calls.append(("cleanup",child)), child.terminate()),
    }
    defaults.update(overrides)
    migration_supervisor.run_with_proxy(**defaults)
    return calls,process


def test_supervisor_starts_bounded_proxy_then_runs_migration_and_cleans_up():
    calls,process=_ready_proxy_supervisor()
    assert calls[0]==("socket",Path("/cloudsql"))
    assert calls[1][0]=="start"
    assert calls[1][1]==[
        "/cloud-sql-proxy","--private-ip","--unix-socket=/cloudsql",
        "--health-check","--http-address=127.0.0.1","--http-port=9091",
        "--exit-zero-on-sigterm","project:us-central1:restricted-synthetic-postgres",
    ]
    assert calls[2:]==[("ready",None),("migration","connection-factory"),("cleanup",process)]
    assert process.terminated is True


def test_supervisor_fails_closed_when_proxy_cannot_start():
    calls=[]
    with pytest.raises(OSError,match="proxy start"):
        migration_supervisor.run_with_proxy(
            connection_name="project:region:instance",socket_dir=Path("/cloudsql"),connect="connection",
            run_migration=lambda connect: calls.append("migration"),prepare_socket=lambda path: calls.append("socket"),
            popen=lambda command, **kwargs: (_ for _ in ()).throw(OSError("proxy start")),readiness_probe=lambda: None,
            cleanup=lambda process: calls.append("cleanup"),
        )
    assert calls==["socket"]


def test_supervisor_fails_closed_when_local_proxy_readiness_times_out():
    process=_Proxy()
    clock=iter((0,0,11))
    with pytest.raises(RuntimeError,match="readiness timed out"):
        migration_supervisor.wait_for_proxy_ready(
            process,
            readiness_probe=lambda: (_ for _ in ()).throw(OSError("not ready")),
            timeout_seconds=10,
            monotonic=lambda: next(clock),
            sleep=lambda seconds: None,
        )


def test_supervisor_does_not_pass_bootstrap_dsn_to_child_and_reaps_an_exited_child(monkeypatch):
    monkeypatch.setenv("MIGRATION_ADMIN_DSN","password=not-for-child")
    process=_Proxy()
    process.poll=lambda: 9
    seen={}
    with pytest.raises(RuntimeError,match="exited before readiness"):
        _ready_proxy_supervisor(
            process=process,
            popen=lambda command, **kwargs: (seen.update(kwargs) or process),
            cleanup=lambda child: None,
        )
    assert "MIGRATION_ADMIN_DSN" not in seen["env"]


@pytest.mark.parametrize("failure",[ValueError("migration failed"),RuntimeError("postflight failed")])
def test_supervisor_preserves_migration_or_postflight_failure_while_cleaning_child(failure):
    process=_Proxy()
    calls=[]
    with pytest.raises(type(failure),match=str(failure)):
        _ready_proxy_supervisor(
            process=process,
            run_migration=lambda connect: (_ for _ in ()).throw(failure),
            cleanup=lambda child: calls.append(child),
        )
    assert calls==[process]


def test_supervisor_fails_when_proxy_cleanup_fails_after_successful_migration():
    with pytest.raises(RuntimeError,match="cleanup failed"):
        _ready_proxy_supervisor(cleanup=lambda child: (_ for _ in ()).throw(OSError("cleanup failed")))


def test_supervisor_keeps_signal_handlers_until_cleanup_finishes():
    events=[]
    _ready_proxy_supervisor(
        cleanup=lambda child: events.append("cleanup"),
        install_signals=lambda: lambda: events.append("restore"),
    )
    assert events==["cleanup","restore"]


def test_shutdown_handler_raises_once_then_ignores_repeated_term_until_restore(monkeypatch):
    handlers={}
    previous=object()
    monkeypatch.setattr(migration_supervisor.signal,"signal",lambda number, handler: handlers.setdefault(number,handler) and previous)
    restore=migration_supervisor.install_shutdown_handlers()
    with pytest.raises(RuntimeError,match="interrupted by signal"):
        handlers[migration_supervisor.signal.SIGTERM](migration_supervisor.signal.SIGTERM,None)
    assert handlers[migration_supervisor.signal.SIGTERM](migration_supervisor.signal.SIGTERM,None) is None
    restore()


def test_cleanup_rejects_a_child_that_exited_before_supervised_shutdown_even_with_zero_status():
    process=_Proxy()
    process.poll=lambda: 0
    with pytest.raises(RuntimeError,match="before supervised shutdown"):
        migration_supervisor.cleanup_proxy(process)
    assert process.terminated is False


def test_cleanup_terminates_then_kills_and_reaps_a_timed_out_child():
    import subprocess
    class TimedOutProxy(_Proxy):
        def __init__(self):
            super().__init__()
            self.killed=False
            self.waits=0
        def wait(self, timeout):
            self.waits+=1
            if self.waits==1: raise subprocess.TimeoutExpired("proxy",timeout)
            return 0
        def kill(self): self.killed=True
    process=TimedOutProxy()
    migration_supervisor.cleanup_proxy(process)
    assert process.terminated is True and process.killed is True and process.waits==2


def test_main_uses_supervisor_and_requires_the_exact_connection_name(monkeypatch):
    seen=[]
    monkeypatch.setenv("RESTRICTED_CLOUD_SQL_CONNECTION_NAME","project:us-central1:restricted-synthetic-postgres")
    monkeypatch.setattr(migration_supervisor,"run_with_proxy",lambda **kwargs: seen.append(kwargs))
    migration_runner.main(connect="connection-factory")
    assert seen[0]["connection_name"]=="project:us-central1:restricted-synthetic-postgres"
    assert seen[0]["connect"]=="connection-factory"


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
