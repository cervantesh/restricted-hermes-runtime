from __future__ import annotations

import hashlib
import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "clinical_composed_receipt.py"


def load_module():
    spec = importlib.util.spec_from_file_location("clinical_composed_receipt", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def evidence():
    return {
        "runtime_head": "a" * 40,
        "runtime_tree": "b" * 40,
        "hrh_head": "c" * 40,
        "hrh_tree": "d" * 40,
        "runtime_product_sha": "e" * 40,
        "built_images": {
            "clinical-adapter": {"image_id": "sha256:" + "f" * 64},
            "ingress": {"image_id": "sha256:" + "1" * 64},
        },
        "boundaries": {name: True for name in (
            "adapter_cannot_resolve_mattermost", "adapter_resolves_only_hrh_boundary",
            "edge_cannot_resolve_hrh", "zero model/conversation/provider calls",
        )},
        "scenarios": {
            "valid": "pass", "actor_cross": "deny", "channel_cross": "deny",
            "patient_cross": "deny", "unbound": "deny", "disabled": "deny",
            "missing_each_permission": "deny", "revoked_before_delivery": "zero-post",
            "source_deleted_before_delivery": "blocked-zero-post", "swapped_digest": "deny",
            "crash_retry": "stable-result", "logs": "no synthetic identifiers",
        },
        "post_counts": {"valid": 1, "recovered": 0, "source_deleted": 0, "actor-cross": 0, "channel-cross": 0, "disabled": 0, "missing-appointments": 0, "missing-patients": 0, "revoked": 0, "unbound": 0},
        "crash_invariants": {"response_digest_equal": True, "read_authorized": 1, "read_completed": 1, "delivery_reauthorized": 1},
        "source_deletion": {
            "delete_accepted": True, "delivery_count": 0,
            "before": {"state": "IN_FLIGHT", "reason": "", "nonce_erased": False, "ciphertext_erased": False, "record_tag": "not-retained"},
            "after": {"state": "BLOCKED", "reason": "post_authorization_source_rejected", "nonce_erased": True, "ciphertext_erased": True, "record_tag": "not-retained"},
        },
    }


def subjects(values):
    source = {key: values[key] for key in ("runtime_head", "runtime_tree", "hrh_head", "hrh_tree")}
    images = {name: values["built_images"][name]["image_id"] for name in ("clinical-adapter", "ingress")}
    return source, images, values["runtime_product_sha"]


def test_builds_a_closed_content_safe_receipt():
    module = load_module()
    values = evidence()
    source, images, product = subjects(values)
    receipt = module.build_receipt(values, cleanup_complete=True)
    raw = module.canonical_bytes(receipt)
    assert module.verify_receipt(raw, expected_source=source, expected_images=images, expected_product=product) == []
    assert b"record_tag" not in raw and b"not-retained" not in raw


@pytest.mark.parametrize("mutate, expected", [
    (lambda receipt: receipt["edge_image_subjects"].update(ingress="sha256:" + "2" * 64), "images"),
    (lambda receipt: receipt.update(runtime_product_sha="2" * 40), "product"),
    (lambda receipt: receipt["boundaries"].update(edge_cannot_resolve_hrh=1), "boundaries"),
    (lambda receipt: receipt["source"].update(unreviewed_identifier="forbidden"), "source"),
    (lambda receipt: receipt["source_deletion"]["after"].update(ciphertext_erased=1), "source-deletion"),
    (lambda receipt: receipt["source_deletion"]["before"].update(nonce_erased=0), "source-deletion"),
    (lambda receipt: receipt["source_deletion"].update(delivery_count=False), "source-deletion"),
    (lambda receipt: receipt.update(raw_log="forbidden"), "fields"),
])
def test_rejects_substitution_and_non_boolean_claims(mutate, expected):
    module = load_module()
    values = evidence()
    source, images, product = subjects(values)
    receipt = deepcopy(module.build_receipt(values, cleanup_complete=True))
    mutate(receipt)
    assert module.verify_receipt(module.canonical_bytes(receipt), expected_source=source, expected_images=images, expected_product=product) == [expected]


def test_builder_requires_completed_cleanup_and_exact_e2e_outcomes():
    module = load_module()
    with pytest.raises(ValueError, match="cleanup"):
        module.build_receipt(evidence(), cleanup_complete=False)
    values = evidence()
    values["post_counts"]["valid"] = 0
    with pytest.raises(ValueError, match="scenario"):
        module.build_receipt(values, cleanup_complete=True)


@pytest.mark.parametrize("mutate", [
    lambda value: value["source_deletion"]["after"].update(ciphertext_erased=1),
    lambda value: value["source_deletion"]["before"].update(nonce_erased=0),
    lambda value: value["source_deletion"].update(delivery_count=False),
])
def test_builder_refuses_boolean_integer_aliases_in_source_deletion_evidence(mutate):
    module = load_module()
    values = evidence()
    mutate(values)
    with pytest.raises(ValueError, match="deletion"):
        module.build_receipt(values, cleanup_complete=True)


def test_returned_receipt_does_not_share_mutable_expectations():
    module = load_module()
    receipt = module.build_receipt(evidence(), cleanup_complete=True)
    receipt["scenarios"]["valid"] = "tampered"
    receipt["post_counts"]["valid"] = 0
    receipt["crash_invariants"]["read_authorized"] = 0
    assert module._SCENARIOS["valid"] == "pass"
    assert module._POST_COUNTS["valid"] == 1
    assert module._CRASH["read_authorized"] == 1
    next_receipt = module.build_receipt(evidence(), cleanup_complete=True)
    assert next_receipt["scenarios"]["valid"] == "pass"
    assert next_receipt["post_counts"]["valid"] == 1
    assert next_receipt["crash_invariants"]["read_authorized"] == 1


def test_writer_does_not_replace_existing_path(tmp_path):
    module = load_module()
    output = tmp_path / "receipt.json"
    output.write_bytes(b"sentinel")
    with pytest.raises(FileExistsError):
        module.write_new(output, module.build_receipt(evidence(), cleanup_complete=True))
    assert output.read_bytes() == b"sentinel"


def test_composed_runner_emits_a_receipt_only_after_successful_teardown():
    runner = (ROOT / "tests" / "deployment" / "test_clinical_composed_e2e.py").read_text(encoding="utf-8")
    assert 'parser.add_argument("--receipt", type=Path' in runner
    assert runner.index('compose("down", "--volumes", "--remove-orphans"') < runner.index("build_receipt(evidence, cleanup_complete=True)")
    assert runner.index("build_receipt(evidence, cleanup_complete=True)") < runner.index("Clinical composed E2E: PASS")


def test_versioned_composed_receipt_is_canonical_and_bound_to_its_subjects():
    module = load_module()
    raw = (ROOT / "docs" / "evidence" / "clinical-composed-receipt-2026-09-11.json").read_bytes().replace(b"\r\n", b"\n")
    source = {
        "runtime_head": "14793b98d310fab44ef4bc22086c55039e279d46",
        "runtime_tree": "cc83f7c4cad7e6f4da063c4ce9fcc90ad90bce19",
        "hrh_head": "ad13735e9881a48580a9e138daac137f8c865dea",
        "hrh_tree": "f217b0b1cf7f438422528dfe178d81b78212c68b",
    }
    images = {
        "clinical-adapter": "sha256:d15716b12846576175686928de84cb7c7b9c6ee3f1dca2034a618372ca59b99f",
        "ingress": "sha256:2114445b55496a67eb71831d70889ac39a66f741d88eba7aeec99f0cfc731064",
    }
    assert module.verify_receipt(raw, expected_source=source, expected_images=images, expected_product="c0fc85d894700823deb92a085d36291589160028") == []
    assert hashlib.sha256(raw).hexdigest() == "f126f48d8146efa9b9e877d56724b7d12a17ae476bab9c56e58e9d1db8597cc7"
