import ast
from pathlib import Path

FORBIDDEN = ("run_agent", "agent.agent_init", "agent.conversation_loop", "plugins", "mcp", "toolsets", "memory", "compression", "checkpoint", "trajectory", "vertex_adapter", "subprocess", "AIAgent")

def test_restricted_runtime_import_graph_is_closed_except_the_single_audited_migration_supervisor():
    for path in Path("src/restricted_runtime").rglob("*.py"):
        imported = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import): imported.update(alias.name for alias in node.names)
            if isinstance(node, ast.ImportFrom) and node.module: imported.add(node.module)
        for symbol in FORBIDDEN:
            if path.name == "migration_supervisor.py" and symbol == "subprocess":
                assert imported == {"__future__", "os", "signal", "subprocess", "time", "http.client", "pathlib", "typing"}
                continue
            assert all(symbol not in module for module in imported)


def test_migration_supervisor_has_one_explicit_safe_process_boundary():
    source = Path("src/restricted_runtime/migration_supervisor.py").read_text(encoding="utf-8")
    assert 'subprocess.Popen(command, env=env, shell=False)' in source
    assert 'child_environment.pop("MIGRATION_ADMIN_DSN", None)' in source
    assert "stdout=" not in source and "stderr=" not in source
