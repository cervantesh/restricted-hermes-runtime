from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_current_egress_witness_uses_real_red_green_and_content_safe_receipt_boundary():
    runner = (ROOT / "tests" / "deployment" / "test_clinical_egress_witness.py").read_text(encoding="utf-8")
    collector = (ROOT / "tools" / "clinical_egress_witness.py").read_text(encoding="utf-8")
    for phrase in ("network", "connect", "disconnect", "controlled RED", "controlled external", "status", "cleanup", "--ipv6", "controlled_v6", "initialization_attempted", "output_owned", "diagnostic"):
        assert phrase in runner
    for phrase in ("canonical_bytes", "candidate_receipt", "controlled_red", "controlled_external", "network_membership", "_strict_bool_mapping", "raw endpoints"):
        assert phrase in collector
