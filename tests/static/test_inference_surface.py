"""AST-backed scan of the actual provider dispatch surface."""
import ast
from pathlib import Path

ROOT=Path("src/restricted_runtime")

def test_only_gateway_has_provider_client_and_one_non_streaming_dispatch():
    clients=[];posts=[]
    for path in ROOT.rglob("*.py"):
        tree=ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node,ast.ClassDef) and node.name in {"VertexClient","VertexAdapter","AnthropicClient","BedrockClient"}:
                clients.append(path)
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr == "stream":
                posts.append((path,node.func.attr))
    assert clients==[ROOT/"vertex.py"]
    assert posts==[(ROOT/"vertex.py","stream")]

def test_production_conversation_has_no_vertex_or_dynamic_runtime_imports():
    source=(ROOT/"services"/"production_conversation.py").read_text(encoding="utf-8")
    tree=ast.parse(source)
    imports=[n.module or "" for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)]
    assert not any("vertex" in module or module in {"subprocess","run_agent","agent"} for module in imports)
