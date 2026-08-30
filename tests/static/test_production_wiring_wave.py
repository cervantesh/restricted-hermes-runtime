"""Adversarial static checks for the two immutable composition roots."""
import ast
from pathlib import Path

CONV=Path("src/restricted_runtime/services/production_conversation.py")
GATE=Path("src/restricted_runtime/services/production_gateway.py")

def _imports(path):
    tree=ast.parse(path.read_text(encoding="utf-8"))
    return {alias.name for node in ast.walk(tree) if isinstance(node,ast.Import) for alias in node.names} | {node.module for node in ast.walk(tree) if isinstance(node,ast.ImportFrom) and node.module}

def test_conversation_root_is_real_content_service_with_internal_gateway_client():
    source=CONV.read_text(encoding="utf-8");imports=_imports(CONV)
    assert "conversation" in imports and "gateway_client" in imports
    assert "VertexClient" not in source and "ConversationService(" in source and "HttpGatewayClient(" in source and "PostgresContentStore(" in source
    assert "app=build_app()" in source

def test_gateway_root_is_real_vertex_service_and_not_a_nominal_placeholder():
    source=GATE.read_text(encoding="utf-8");imports=_imports(GATE)
    assert "vertex" in imports and "gateway" in imports
    assert "VertexClient(" in source and "PostgresLedger(" in source and "Gateway(" in source and "app=build_app()" in source

def test_conversation_root_contains_gateway_readiness_pairing_hook():
    source=CONV.read_text(encoding="utf-8")
    assert "gateway.ready" in source and "gateway_ready" in source and "policy.epoch" in source and "policy.digest" in source

def test_conversation_root_starts_bounded_reconciliation_without_provider_import():
    source=CONV.read_text(encoding="utf-8")
    assert "ReconciliationDriver" in source and "run_once" in source and "periodic" in source
    assert "VertexClient" not in source and "infer_once" not in source
