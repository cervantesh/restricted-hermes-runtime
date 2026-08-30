"""Named local matrix rows: static closed graph and one provider surface."""
from pathlib import Path

def test_ac1_closed_import_graph():
    source="\n".join(p.read_text(encoding="utf-8") for p in Path("src/restricted_runtime").rglob("*.py"))
    assert "AIAgent" not in source and "agent.conversation_loop" not in source

def test_ac2_fixed_phi_language_and_instruction():
    source=Path("src/restricted_runtime/policy.py").read_text(encoding="utf-8")
    assert '"classification": "PHI"' in source and "non-clinical administrative" in source

def test_ac10_ac16_no_partial_response_profile():
    source=Path("src/restricted_runtime/vertex.py").read_text(encoding="utf-8")
    assert "finishReason" in source and "INDETERMINATE" in source and "follow_redirects=False" in source

def test_inference_surface_has_one_http_dispatch_module():
    matches=[p for p in Path("src/restricted_runtime").rglob("*.py") if 'client.stream("POST"' in p.read_text(encoding="utf-8")]
    assert matches==[Path("src/restricted_runtime/vertex.py")]
