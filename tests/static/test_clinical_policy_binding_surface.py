"""Static wiring contract for the content-safe active-policy binding."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_final_report_uses_only_a_validated_closed_policy_binding():
    control = (ROOT / "tests/deployment/clinical-composed-e2e/control.py").read_text(encoding="utf-8")
    runner = (ROOT / "tests/deployment/test_clinical_composed_e2e.py").read_text(encoding="utf-8")
    assert "def active_policy_binding" in control
    assert '"active-policy-binding"' in control
    assert 'return {"epoch": epoch, "digest": "sha256:" + digest}' in control
    assert 'policy_binding = json.loads(control("active-policy-binding").stdout)' in runner
    assert 'set(policy_binding) != {"epoch", "digest"}' in runner
    assert '"policy": policy_binding' in runner
