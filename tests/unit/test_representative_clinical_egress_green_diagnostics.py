from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "representative_clinical_egress.py"
HARNESS = ROOT / "tests" / "deployment" / "test_representative_clinical_egress.sh"


def load_module():
    spec = importlib.util.spec_from_file_location("egress_green_diagnostics", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def green_fixture(module, tmp_path, monkeypatch, scenario="good", service="ingress"):
    marker = {"expected_images": {name: "sha256:" + str(index) * 64 for index, name in enumerate(module.POLICIES)}}
    images = marker["expected_images"]
    monkeypatch.setattr(module, "_source_marker", lambda *_args: marker)
    monkeypatch.setattr(module, "_read_marker_proof", lambda *_args: "a" * 64)
    monkeypatch.setattr(module, "_read_json", lambda *_args: marker)
    monkeypatch.setattr(module, "_service_id", lambda *_args: _args[-1])
    monkeypatch.setattr(module, "_inspect_container", lambda name: {"Image": images[name]})

    def target(_image, name, _endpoints, **_kwargs):
        values = dict.fromkeys(module.DENIED_CLASSES, True)
        if scenario == "target-denial" and name == service:
            values["controlled_ipv4"] = False
        return values

    def fixed(image, network):
        control = not network.startswith("container:")
        values = {"public_dns_example_com": control, "metadata_ipv4": "other" if control else "network-unreachable",
                  "metadata_ipv6": "network-unreachable"}
        if image != images[service]:
            return values
        if scenario == "fixed-shape" and not control:
            values.pop("metadata_ipv6")
        elif scenario == "target-public-dns" and not control:
            values["public_dns_example_com"] = True
        elif scenario == "control-public-dns" and control:
            values["public_dns_example_com"] = False
        elif scenario in {"target-metadata-ipv4", "target-metadata-ipv6"} and not control:
            values[scenario.removeprefix("target-").replace("-", "_")] = "connected"
        elif scenario in {"control-metadata-ipv4", "control-metadata-ipv6"} and control:
            values[scenario.removeprefix("control-").replace("-", "_")] = "invalid"
        elif scenario == "metadata-ipv4-discrimination" and control:
            values["metadata_ipv4"] = "network-unreachable"
        return values

    monkeypatch.setattr(module, "_probe_results", target)
    monkeypatch.setattr(module, "_fixed_outcomes", fixed)
    monkeypatch.setattr(module, "_network_control", lambda *_args: scenario != "controlled-sink")
    monkeypatch.setattr(module, "_control_resolves_public_dns", lambda *_args: scenario != "public-dns-control")
    return {"runtime": ROOT, "state_dir": tmp_path, "project": "synthetic", "expected_head": "b" * 40,
            "expected_tree": "c" * 40, "network": "control", "endpoints": {"controlled_ipv4": ("127.0.0.1", 80)},
            "output": tmp_path / "green.json", "marker_proof": tmp_path / "marker.json"}


def test_green_success_still_writes_the_same_proof_contract(tmp_path, monkeypatch):
    module = load_module()
    kwargs = green_fixture(module, tmp_path, monkeypatch)
    digest = module.collect_green(**kwargs)
    proof = json.loads(kwargs["output"].read_text())
    assert len(digest) == 64
    assert proof["control_reachable"] is True
    assert proof["public_dns_control"] is True
    assert all(all(values.values()) for values in proof["target"].values())
    assert "diagnostic" not in proof


@pytest.mark.parametrize("scenario", ["target-denial", "controlled-sink", "public-dns-control"])
def test_green_control_failures_remain_denied_and_get_distinct_codes(tmp_path, monkeypatch, scenario):
    module = load_module()
    kwargs = green_fixture(module, tmp_path, monkeypatch, scenario)
    with pytest.raises(module.ReceiptError) as caught:
        module.collect_green(**kwargs)
    assert module.collector_error_class(caught.value) == "green-policy/" + scenario
    assert not kwargs["output"].exists()


FIXED_SCENARIOS = ["fixed-shape", "target-public-dns", "control-public-dns", "target-metadata-ipv4",
                   "target-metadata-ipv6", "control-metadata-ipv4", "control-metadata-ipv6",
                   "metadata-ipv4-discrimination"]


@pytest.mark.parametrize("service", ["ingress", "clinical-adapter"])
@pytest.mark.parametrize("scenario", FIXED_SCENARIOS)
def test_green_fixed_failures_identify_only_service_and_property(tmp_path, monkeypatch, service, scenario):
    module = load_module()
    kwargs = green_fixture(module, tmp_path, monkeypatch, scenario, service)
    with pytest.raises(module.ReceiptError) as caught:
        module.collect_green(**kwargs)
    assert module.collector_error_class(caught.value) == "green-policy/" + service + "-" + scenario
    assert not kwargs["output"].exists()


def test_fixed_validator_retains_shape_and_attribution_denials():
    module = load_module()
    fixed = {name: {"public_dns_example_com": False, "metadata_ipv4": "network-unreachable",
                    "metadata_ipv6": "network-unreachable"} for name in module.POLICIES}
    control = {name: {"public_dns_example_com": True, "metadata_ipv4": "other",
                      "metadata_ipv6": "network-unreachable"} for name in module.POLICIES}
    attribution = dict.fromkeys(module.POLICIES, "host-bound-control-unreachable")
    assert module._fixed_evidence_valid(fixed, control, attribution)
    assert module._fixed_evidence_failure(None, control, attribution) == "fixed-shape"
    assert not module._fixed_evidence_valid(None, control, attribution)
    for service in module.POLICIES:
        bad = copy.deepcopy(attribution)
        bad[service] = "target-only-denied"
        assert module._fixed_evidence_failure(fixed, control, bad) == service + "-metadata-ipv6-attribution"
        assert not module._fixed_evidence_valid(fixed, control, bad)


def test_green_exception_rejects_unlisted_codes():
    module = load_module()
    for code in module.GREEN_POLICY_SUBCODES:
        assert module.collector_error_class(module.GreenPolicyError(code)) == "green-policy/" + code
    with pytest.raises(ValueError):
        module.GreenPolicyError("arbitrary private output")


def test_shell_retains_only_exact_allowlisted_green_codes():
    module = load_module()
    bash = shutil.which("bash")
    if os.name == "nt":
        # The legacy system32 bash.exe is a WSL launcher, not a native shell.
        git = shutil.which("git")
        native_bash = Path(git).resolve().parents[1] / "bin" / "bash.exe" if git else None
        bash = str(native_bash) if native_bash and native_bash.is_file() else None
    if bash is None:
        pytest.skip("bash is required to exercise the shell diagnostic boundary")
    harness = HARNESS.read_text(encoding="utf-8")
    classifier = "collector_class_from() {" + harness.split("collector_class_from() {", 1)[1].split("\nwrite_diagnostic()", 1)[0]
    known = ["representative-clinical-egress: DENIED class=green-policy/" + code for code in sorted(module.GREEN_POLICY_SUBCODES)]
    unknown = ["representative-clinical-egress: DENIED class=green-policy/unknown",
               "representative-clinical-egress: DENIED class=green-policy/ingress-private-value",
               "representative-clinical-egress: DENIED class=green-policy/ingress-target-metadata-ipv5",
               known[0] + " private detail", known[0] + "\nprivate detail",
               "arbitrary private command output"]
    # Execute just the real classification function; no harness startup or Docker.
    result = subprocess.run([bash, "-s", "--", *known, *unknown], input=classifier + '\nfor arg in "$@"; do collector_class_from "$arg"; printf "\\n"; done\n',
                            text=True, capture_output=True, timeout=30, check=True)
    assert result.stderr == ""
    assert result.stdout.splitlines() == [line.split("class=", 1)[1] for line in known] + ["unclassified"] * len(unknown)
