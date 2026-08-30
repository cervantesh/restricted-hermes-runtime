import ast
from pathlib import Path

FORBIDDEN = ("run_agent", "agent.agent_init", "agent.conversation_loop", "plugins", "mcp", "toolsets", "memory", "compression", "checkpoint", "trajectory", "vertex_adapter", "subprocess", "AIAgent")

def test_restricted_runtime_import_graph_is_closed():
    imported = set()
    for path in Path("src/restricted_runtime").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import): imported.update(alias.name for alias in node.names)
            if isinstance(node, ast.ImportFrom) and node.module: imported.add(node.module)
    for symbol in FORBIDDEN:
        assert all(symbol not in module for module in imported)
