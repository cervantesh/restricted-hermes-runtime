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
    assert module.verify_receipt(raw, expected_status=values[0]) == []
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
    assert module.verify_receipt(module.canonical_bytes(module.build_receipt(*values)), expected_status=values[0]) == []


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
    assert module.verify_receipt(module.canonical_bytes(receipt), expected_status=values[0]) == [expected]


def test_builder_rejects_incomplete_red_or_cleanup():
    module = load_module()
    values = list(inputs(module))
    values[4]["ingress"] = False
    with pytest.raises(ValueError, match="RED"):
        module.build_receipt(*values)


def test_receipt_writer_does_not_replace_an_existing_caller_path(tmp_path):
    module = load_module()
    output = tmp_path / "receipt.json"
    output.write_bytes(b"sentinel")
    with pytest.raises(FileExistsError):
        module.write_new(output, module.build_receipt(*inputs(module)))
    assert output.read_bytes() == b"sentinel"


def test_legacy_versioned_wsl_receipt_hash_is_preserved_until_replacement():
    module = load_module()
    # The evidence was generated on Linux with LF.  Keep its source digest
    # stable when this test runs from a Windows checkout that expands text to
    # CRLF.
    raw = (ROOT / "docs" / "evidence" / "clinical-egress-wsl-receipt-2026-09-11.json").read_bytes().replace(b"\r\n", b"\n")
    expected_source = {
        "runtime_head": "793feea781f2c9b70d0aa3f846c537826db889eb",
        "runtime_tree": "83539372e8c46cc3ebccecf148a17304805fcf70",
        "hrh_head": "ad13735e9881a48580a9e138daac137f8c865dea",
        "hrh_tree": "f217b0b1cf7f438422528dfe178d81b78212c68b",
    }
    expected_status = status(module)
    expected_status["source"] = expected_source
    expected_status["built_images"] = {
        "clinical-adapter": "sha256:612a53906df02298b92a33d663adf510d92572c18557dd8d0d207d28045b5f2a",
        "ingress": "sha256:944a5e7946e6338bbcb5456b9b20ed946340f0c6a4c1a61f38ed822d4181870b",
    }
    # This historical receipt predates the current receipt contract.  Preserve
    # its digest until the real-path collector replaces it with fresh evidence.
    assert module.verify_receipt(raw, expected_status=expected_status) == ["candidate-receipt"]
    assert hashlib.sha256(raw).hexdigest() == "920284a6a411396f5befb5433a95e89fc6a0cb1d896aa85faf00e87a498ac914"
