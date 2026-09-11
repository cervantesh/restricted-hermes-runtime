from __future__ import annotations

import importlib.util
import hashlib
from copy import deepcopy
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "clinical_egress_witness.py"


def load_module():
    spec = importlib.util.spec_from_file_location("clinical_egress_witness", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def status(module):
    candidate = module._candidate()
    return {
        "source": {"runtime_head": "a" * 40, "runtime_tree": "b" * 40, "hrh_head": "c" * 40, "hrh_tree": "d" * 40},
        "restricted_container_controls": deepcopy(candidate.EXPECTED_RESTRICTED_CONTROLS),
        "restricted_process_identities": deepcopy(candidate.EXPECTED_RESTRICTED_IDENTITIES),
        "built_images": {service: "sha256:" + char * 64 for service, char in zip(module.SERVICES, "ef")},
    }


def observations(module):
    candidate = module._candidate()
    return {service: {"denied": {item: True for item in candidate.DENIED_CLASSES}, "allowed": {item: True for item in candidate.ALLOWED_CLASSES[service]}} for service in module.SERVICES}


def inputs(module):
    return (status(module), observations(module), {"system": "Linux", "kernel": "6.8.0", "architecture": "x86_64", "docker": "29.4.3", "compose": "2.40.3"}, {"clinical-adapter": ["clinical_upstream"], "ingress": ["mattermost_edge"]}, {service: True for service in module.SERVICES}, {"open_control": True, **{service: False for service in module.SERVICES}}, {"network_absent": True, "sink_absent": True})


def test_builds_closed_content_safe_witness():
    module = load_module()
    values = inputs(module)
    receipt = module.build_receipt(*values)
    raw = module.canonical_bytes(receipt)
    assert module.verify_receipt(raw, expected_source=values[0]["source"]) == []
    assert b"http" not in raw.lower() and b"raw_log" not in raw


def test_selects_only_the_two_edge_image_subjects_from_full_staging_status():
    module = load_module()
    values = list(inputs(module))
    values[0]["built_images"]["mattermost"] = "sha256:" + "a" * 64
    receipt = module.build_receipt(*values)
    assert set(receipt["effective_images"]) == set(module.SERVICES)


def test_accepts_a_normal_distribution_qualified_compose_version_without_accepting_content():
    module = load_module()
    values = list(inputs(module))
    values[2]["compose"] = "2.40.3+ds1-0ubuntu1~24.04.1"
    assert module.verify_receipt(module.canonical_bytes(module.build_receipt(*values)), expected_source=values[0]["source"]) == []


@pytest.mark.parametrize("mutate, expected", [
    (lambda receipt: receipt["controlled_red"].update(ingress=False), "red"),
    (lambda receipt: receipt["controlled_external"].update(ingress=True), "external"),
    (lambda receipt: receipt["cleanup"].update(sink_absent=False), "cleanup"),
    (lambda receipt: receipt["network_membership"].update(ingress=["mattermost_edge", "red"]), "networks"),
    (lambda receipt: receipt["effective_images"].update(ingress="latest"), "images"),
    (lambda receipt: receipt.update(raw_log="forbidden"), "fields"),
])
def test_rejects_incomplete_or_unsafe_witness(mutate, expected):
    module = load_module()
    values = inputs(module)
    receipt = module.build_receipt(*values)
    mutate(receipt)
    assert module.verify_receipt(module.canonical_bytes(receipt), expected_source=values[0]["source"]) == [expected]


def test_builder_rejects_incomplete_red_or_cleanup():
    module = load_module()
    values = list(inputs(module))
    values[4]["ingress"] = False
    with pytest.raises(ValueError, match="RED"):
        module.build_receipt(*values)


def test_versioned_wsl_receipt_is_canonical_and_bound_to_its_recorded_subject():
    module = load_module()
    raw = (ROOT / "docs" / "evidence" / "clinical-egress-wsl-receipt-2026-09-11.json").read_bytes()
    expected = {
        "runtime_head": "e06e0a81964544123b507c31cf9190d36593a345",
        "runtime_tree": "e699bbacfa02d77c3ec601810be628ee1cb4720b",
        "hrh_head": "ad13735e9881a48580a9e138daac137f8c865dea",
        "hrh_tree": "f217b0b1cf7f438422528dfe178d81b78212c68b",
    }
    assert module.verify_receipt(raw, expected_source=expected) == []
    assert hashlib.sha256(raw).hexdigest() == "101ddd90cde61107dd6ad27a1ba52a0c6dd0794bb7baf53d2306821404ef247a"
