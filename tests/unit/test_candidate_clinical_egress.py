from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "candidate_clinical_egress.py"


def load_module():
    spec = importlib.util.spec_from_file_location("candidate_clinical_egress", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def status(module):
    return {
        "source": {"runtime_head": "a" * 40, "runtime_tree": "b" * 40, "hrh_head": "c" * 40, "hrh_tree": "d" * 40},
        "restricted_container_controls": deepcopy(module.EXPECTED_RESTRICTED_CONTROLS),
        "restricted_process_identities": deepcopy(module.EXPECTED_RESTRICTED_IDENTITIES),
    }


def observations(module):
    return {
        service: {
            "denied": {name: True for name in module.DENIED_CLASSES},
            "allowed": {name: True for name in module.ALLOWED_CLASSES[service]},
        }
        for service in module.SERVICES
    }


def test_candidate_bound_receipt_is_canonical_and_content_safe():
    module = load_module()
    current = status(module)
    receipt = module.build_receipt(current, observations(module))
    raw = module.canonical_bytes(receipt)

    assert module.verify_receipt(raw, expected_source=current["source"]) == []
    # A named, read-only secret mount is admissible confinement evidence; raw
    # secret values, raw probe output, and endpoints are never admissible.
    assert b"raw_log" not in raw and b"http" not in raw.lower()


@pytest.mark.parametrize("mutate, expected", [
    (lambda value: value["source"].update(hrh_head="0" * 40), "source"),
    (lambda value: value["restricted_container_controls"]["ingress"].update(privileged=True), "restricted-evidence"),
    (lambda value: value["restricted_process_identities"]["ingress"].update(uid=0), "restricted-evidence"),
    (lambda value: value["services"]["ingress"]["denied"].update(public_ipv6=False), "denied"),
    (lambda value: value["services"]["clinical-adapter"]["allowed"].update(hrh_tls=False), "allowed"),
    (lambda value: value.update(raw_log="forbidden"), "fields"),
])
def test_rejects_source_control_probe_or_content_substitution(mutate, expected):
    module = load_module()
    current = status(module)
    receipt = module.build_receipt(current, observations(module))
    mutate(receipt)
    assert module.verify_receipt(module.canonical_bytes(receipt), expected_source=current["source"]) == [expected]


def test_noncanonical_json_is_not_a_receipt():
    module = load_module()
    current = status(module)
    receipt = module.build_receipt(current, observations(module))
    pretty = json.dumps(receipt, indent=2).encode() + b"\n"
    assert module.verify_receipt(pretty, expected_source=current["source"]) == ["canonical"]


def test_builder_refuses_raw_or_incomplete_observations():
    module = load_module()
    incomplete = observations(module)
    incomplete["ingress"]["raw_log"] = "must not be serializable"
    with pytest.raises(ValueError, match="content-safe"):
        module.build_receipt(status(module), incomplete)
