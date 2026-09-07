from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "representative_clinical_egress.py"
HEAD = "de9d00de9d19ccebb3148b2daf4a10bbfdc0edac"
TREE = "808e0d94c279313d1d55b63dc36aa4dd575b7e42"


def load_module():
    spec = importlib.util.spec_from_file_location("representative_clinical_egress", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def receipt(module):
    images = {
        "mattermost-postgres": "sha256:" + "c" * 64, "mattermost": "sha256:" + "c" * 64,
        "hrh-postgres": "sha256:" + "c" * 64, "hrh": "sha256:" + "c" * 64,
        "hrh-tls": "sha256:" + "c" * 64, "clinical-adapter": "sha256:" + "b" * 64,
        "ingress": "sha256:" + "a" * 64, "operator-proxy": "sha256:" + "c" * 64,
    }
    marker = {
        "schema": module.MARKER_PROOF_SCHEMA, "marker_sha256": "c" * 64,
        "source": {"runtime_head": HEAD, "runtime_tree": TREE, "hrh_head": module.STAGING_HRH_HEAD, "hrh_tree": module.STAGING_HRH_TREE},
        "lifecycle": "ready", "compose_env_sha256": "f" * 64, "expected_images": images,
        "volume_keys": ["clinical_config", "clinical_socket", "controller_state", "hrh_db", "hrh_secret", "hrh_tls", "ingress_config", "ingress_outbox", "mattermost_data", "mattermost_db", "mattermost_tls"],
    }
    return {
        "schema": module.SCHEMA,
        "synthetic_non_phi_only": True,
        "runtime": {"head": HEAD, "tree": TREE},
        "staging": {
            "marker": marker, "marker_proof_sha256": "c" * 64,
        },
        "host": {"kernel": "6.8.0-test", "architecture": "x86_64"},
        "docker": {"server_version": "27.5.1", "compose_version": "v2.31.0"},
        "services": {
            "ingress": {
                "image_id": "sha256:" + "a" * 64,
                "networks": ["mattermost_edge"],
                "proxy_environment_absent": True,
                "controls": {"read_only_rootfs": True, "capabilities_restricted": True, "mount_destinations_exact": True},
                "denied": {name: True for name in module.DENIED_CLASSES},
                "permitted_internal": {"mattermost": True},
                "denied_internal": {"hrh-tls": True},
            },
            "clinical-adapter": {
                "image_id": "sha256:" + "b" * 64,
                "networks": ["clinical_upstream"],
                "proxy_environment_absent": True,
                "controls": {"read_only_rootfs": True, "capabilities_restricted": True, "mount_destinations_exact": True},
                "denied": {name: True for name in module.DENIED_CLASSES},
                "permitted_internal": {"hrh-tls": True},
                "denied_internal": {"mattermost": True},
            },
        },
        "red_witness": {
            "proof_sha256": {"ingress": "d" * 64, "clinical-adapter": "e" * 64},
            "green_proof_sha256": "f" * 64,
            "green": {service: {name: True for name in module.DENIED_CLASSES} for service in module.POLICIES},
            "cleanup": {"network_absent": True, "sink_absent": True},
            "fixed": {service: {"public_dns_example_com": False, "metadata_ipv4": "network-unreachable", "metadata_ipv6": "network-unreachable"} for service in module.POLICIES},
            "fixed_control": {service: {"public_dns_example_com": True, "metadata_ipv4": "other", "metadata_ipv6": "network-unreachable"} for service in module.POLICIES},
            "metadata_ipv6_attribution": {service: "host-bound-control-unreachable" for service in module.POLICIES},
            "metadata_scope": "fixed-classes-content-free",
        },
    }


def test_valid_candidate_bound_receipt_verifies_and_contains_no_probe_content():
    module = load_module()
    value = receipt(module)

    assert module.verify_receipt(value, expected_head=HEAD, expected_tree=TREE) == []
    rendered = module.canonical_receipt(value)
    assert "169.254.169.254" not in rendered
    assert "HTTP_PROXY=" not in rendered
    assert "PASSWORD_SECRET_CANARY" not in rendered


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda value, module: value["services"]["ingress"]["denied"].update(controlled_ipv4=False), "denied probe"),
        (lambda value, module: value["services"]["clinical-adapter"]["denied"].pop("controlled_ipv6"), "denied classes"),
        (lambda value, module: value["services"]["ingress"].update(proxy_environment_absent=False), "proxy"),
        (lambda value, module: value["services"]["ingress"].update(networks=["mattermost_edge", "escape"]), "networks"),
        (lambda value, module: value["services"]["ingress"]["controls"].update(mount_destinations_exact=False), "mounts or capabilities"),
        (lambda value, module: value["services"]["ingress"].update(image_id="sha256:" + "f" * 64), "initialized image"),
        (lambda value, module: value["runtime"].update(head="f" * 40), "runtime head"),
        (lambda value, module: value["runtime"].update(tree="e" * 40), "runtime tree"),
        (lambda value, module: value["red_witness"]["cleanup"].update(network_absent=False), "cleanup"),
        (lambda value, module: value["red_witness"]["proof_sha256"].pop("ingress"), "proof"),
    ],
)
def test_verifier_rejects_each_required_negative_control(mutate, expected):
    module = load_module()
    value = receipt(module)
    mutate(value, module)

    assert any(expected in error for error in module.verify_receipt(value, expected_head=HEAD, expected_tree=TREE))


def test_receipt_builder_records_only_classes_booleans_versions_and_hashes():
    module = load_module()
    observations = {
        "ingress": {
            "image_id": "sha256:" + "a" * 64,
            "networks": ["mattermost_edge"],
            "proxy_environment_absent": True,
            "controls": {"read_only_rootfs": True, "capabilities_restricted": True, "mount_destinations_exact": True},
            "denied": {name: True for name in module.DENIED_CLASSES},
            "permitted_internal": {"mattermost": True},
            "denied_internal": {"hrh-tls": True},
        },
        "clinical-adapter": {
            "image_id": "sha256:" + "b" * 64,
            "networks": ["clinical_upstream"],
            "proxy_environment_absent": True,
            "controls": {"read_only_rootfs": True, "capabilities_restricted": True, "mount_destinations_exact": True},
            "denied": {name: True for name in module.DENIED_CLASSES},
            "permitted_internal": {"hrh-tls": True},
            "denied_internal": {"mattermost": True},
        },
    }

    value = module.build_receipt(
        head=HEAD,
        tree=TREE,
        kernel="6.8.0-test",
        architecture="x86_64",
        docker_version="27.5.1",
        compose_version="v2.31.0",
        observations=observations,
        marker=receipt(module)["staging"]["marker"], marker_proof_sha256="c" * 64,
        proof_sha256={"ingress": "d" * 64, "clinical-adapter": "e" * 64},
        green={service: {name: True for name in module.DENIED_CLASSES} for service in module.POLICIES},
        cleanup={"network_absent": True, "sink_absent": True},
        green_proof_sha256="f" * 64,
        fixed={service: {"public_dns_example_com": False, "metadata_ipv4": "network-unreachable", "metadata_ipv6": "network-unreachable"} for service in module.POLICIES},
        fixed_control={service: {"public_dns_example_com": True, "metadata_ipv4": "other", "metadata_ipv6": "network-unreachable"} for service in module.POLICIES},
        metadata_ipv6_attribution={service: "host-bound-control-unreachable" for service in module.POLICIES},
    )

    assert module.verify_receipt(value, expected_head=HEAD, expected_tree=TREE) == []
    assert set(value) == {"schema", "synthetic_non_phi_only", "runtime", "staging", "host", "docker", "services", "red_witness"}


def test_builder_rejects_a_syntactically_valid_swapped_container_image():
    module = load_module()
    observations = receipt(module)["services"]
    observations["ingress"]["image_id"] = "sha256:" + "f" * 64

    with pytest.raises(module.ReceiptError, match="initialized image"):
        module.build_receipt(
            head=HEAD, tree=TREE, kernel="6.8.0-test", architecture="x86_64", docker_version="27.5.1", compose_version="v2.31.0",
                observations=observations, marker=receipt(module)["staging"]["marker"], marker_proof_sha256="c" * 64,
            proof_sha256={"ingress": "d" * 64, "clinical-adapter": "e" * 64},
            green={service: {name: True for name in module.DENIED_CLASSES} for service in module.POLICIES},
            cleanup={"network_absent": True, "sink_absent": True},
                green_proof_sha256="f" * 64,
                fixed={service: {"public_dns_example_com": False, "metadata_ipv4": "network-unreachable", "metadata_ipv6": "network-unreachable"} for service in module.POLICIES},
                fixed_control={service: {"public_dns_example_com": True, "metadata_ipv4": "other", "metadata_ipv6": "network-unreachable"} for service in module.POLICIES},
                metadata_ipv6_attribution={service: "host-bound-control-unreachable" for service in module.POLICIES},
        )


def test_actual_container_image_must_match_the_initialized_marker_before_probing():
    module = load_module()

    with pytest.raises(module.ReceiptError, match="image identity"):
        module._service_observation(
            "ingress", "a" * 64, {"Image": "sha256:" + "f" * 64}, "clinicalstagingdemo",
            {name: ("controlled-probe", 80) for name in module.DENIED_CLASSES}, "sha256:" + "a" * 64,
        )


def test_red_dns_proof_requires_resolution_and_tcp_reachability(monkeypatch):
    module = load_module()
    calls = []

    def probe(_image, _container, _host, _port, *, resolve_only=False):
        calls.append(resolve_only)
        return not resolve_only

    monkeypatch.setattr(module, "_probe", probe)
    result = module._probe_results("sha256:" + "a" * 64, "a" * 64, {"controlled_dns": ("controlled-probe", 80)}, reachable=True)

    assert result == {"controlled_dns": False}
    assert calls == [False, True]


@pytest.mark.parametrize("returncode, output", [(125, "denied\n"), (126, "denied\n"), (127, "denied\n"), (0, ""), (73, ""), (73, "other\n")])
def test_probe_rejects_docker_runtime_errors_and_malformed_outcomes(monkeypatch, returncode, output):
    module = load_module()
    monkeypatch.setattr(module, "_run", lambda *_args, **_kwargs: SimpleNamespace(returncode=returncode, stdout=output))

    with pytest.raises(module.ReceiptError, match="expected outcome"):
        module._probe("sha256:" + "a" * 64, "a" * 64, "controlled-probe", 80)


def test_probe_accepts_only_explicit_program_outcomes(monkeypatch):
    module = load_module()
    monkeypatch.setattr(module, "_run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="reachable\n"))
    assert module._probe("sha256:" + "a" * 64, "a" * 64, "controlled-probe", 80) is True
    monkeypatch.setattr(module, "_run", lambda *_args, **_kwargs: SimpleNamespace(returncode=73, stdout="denied\n"))
    assert module._probe("sha256:" + "a" * 64, "a" * 64, "controlled-probe", 80) is False


@pytest.mark.parametrize("outcome", ["connected", "refused", "timeout"])
def test_fixed_metadata_reachability_or_ambiguous_timeout_is_not_green(outcome):
    module = load_module()
    value = receipt(module)
    value["red_witness"]["fixed"]["ingress"]["metadata_ipv4"] = outcome

    assert "fixed probe evidence is invalid" in module.verify_receipt(value, expected_head=HEAD, expected_tree=TREE)


def write_evidence(module, directory, value):
    directory.mkdir()
    marker_path = directory / "marker.json"
    marker_path.write_text(module.canonical_receipt(value["staging"]["marker"]) + "\n", encoding="utf-8")
    marker_hash = hashlib.sha256(marker_path.read_bytes()).hexdigest()
    value["staging"]["marker_proof_sha256"] = marker_hash
    endpoints = {name: hashlib.sha256(name.encode()).hexdigest() for name in module.DENIED_CLASSES}
    green = {
        "schema": module.GREEN_SCHEMA, "runtime": {"head": HEAD, "tree": TREE},
        "images": value["staging"]["marker"]["expected_images"],
        "target": value["red_witness"]["green"], "control_reachable": True, "public_dns_control": True,
        "fixed": value["red_witness"]["fixed"], "fixed_control": value["red_witness"]["fixed_control"],
        "metadata_ipv6_attribution": value["red_witness"]["metadata_ipv6_attribution"], "marker_proof_sha256": marker_hash,
        "endpoint_sha256": endpoints,
        "fixed_definitions_sha256": hashlib.sha256(module.canonical_receipt({"public_dns": module.FIXED_PUBLIC_DNS, "metadata": module.FIXED_METADATA}).encode()).hexdigest(),
    }
    green_path = directory / "green.json"
    green_path.write_text(module.canonical_receipt(green) + "\n", encoding="utf-8")
    value["red_witness"]["green_proof_sha256"] = hashlib.sha256(green_path.read_bytes()).hexdigest()
    for service in module.POLICIES:
        red = {
            "schema": module.RED_SCHEMA, "service": service, "runtime": {"head": HEAD, "tree": TREE},
            "image_id": value["staging"]["marker"]["expected_images"][service], "endpoint_sha256": endpoints,
            "marker_proof_sha256": marker_hash, "network_shape_sha256": module.RED_NETWORK_SHAPE_SHA256,
            "probes": {name: True for name in module.DENIED_CLASSES},
        }
        path = directory / f"red-{service}.json"
        path.write_text(module.canonical_receipt(red) + "\n", encoding="utf-8")
        value["red_witness"]["proof_sha256"][service] = hashlib.sha256(path.read_bytes()).hexdigest()


def test_offline_verifier_rejects_arbitrary_hash_matching_proof_bytes(tmp_path):
    module = load_module()
    value = receipt(module)
    write_evidence(module, tmp_path / "evidence", value)
    path = tmp_path / "evidence" / "red-ingress.json"
    path.write_bytes(b"{}\n")
    value["red_witness"]["proof_sha256"]["ingress"] = hashlib.sha256(path.read_bytes()).hexdigest()

    assert "retained proof semantics are invalid" in module.verify_receipt(value, expected_head=HEAD, expected_tree=TREE, evidence_dir=tmp_path / "evidence")


def test_offline_verifier_rejects_incomplete_or_semantically_tampered_marker(tmp_path):
    module = load_module()
    value = receipt(module)
    write_evidence(module, tmp_path / "evidence", value)
    marker = value["staging"]["marker"]
    marker.pop("volume_keys")
    path = tmp_path / "evidence" / "marker.json"
    path.write_text(module.canonical_receipt(marker) + "\n", encoding="utf-8")
    value["staging"]["marker_proof_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    assert "staging marker binding is invalid" in module.verify_receipt(value, expected_head=HEAD, expected_tree=TREE, evidence_dir=tmp_path / "evidence")


def test_marker_projection_rejects_an_incomplete_canonical_staging_marker(tmp_path):
    module = load_module()
    project = "clinicalstagingmarker"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    state.mkdir()
    (state / "staging-state.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(module.ReceiptError, match="initialized staging marker"):
        module._marker(state, project, HEAD, TREE, ROOT)


def test_offline_verifier_rejects_semantically_tampered_marker_projection(tmp_path):
    module = load_module()
    value = receipt(module)
    write_evidence(module, tmp_path / "evidence", value)
    marker = value["staging"]["marker"]
    marker["expected_images"]["ingress"] = "sha256:" + "9" * 64
    value["services"]["ingress"]["image_id"] = marker["expected_images"]["ingress"]
    path = tmp_path / "evidence" / "marker.json"
    path.write_text(module.canonical_receipt(marker) + "\n", encoding="utf-8")
    value["staging"]["marker_proof_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    assert "retained proof semantics are invalid" in module.verify_receipt(value, expected_head=HEAD, expected_tree=TREE, evidence_dir=tmp_path / "evidence")


def test_offline_verifier_rejects_mixed_proof_generation(tmp_path):
    module = load_module()
    value = receipt(module)
    write_evidence(module, tmp_path / "evidence", value)
    path = tmp_path / "evidence" / "green.json"
    green = json.loads(path.read_text(encoding="utf-8"))
    green["marker_proof_sha256"] = "0" * 64
    path.write_text(module.canonical_receipt(green) + "\n", encoding="utf-8")
    value["red_witness"]["green_proof_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    assert "retained proof semantics are invalid" in module.verify_receipt(value, expected_head=HEAD, expected_tree=TREE, evidence_dir=tmp_path / "evidence")
