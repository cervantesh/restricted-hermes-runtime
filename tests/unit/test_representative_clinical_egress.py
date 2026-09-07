from __future__ import annotations

import importlib.util
from pathlib import Path

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
    return {
        "schema": module.SCHEMA,
        "synthetic_non_phi_only": True,
        "runtime": {"head": HEAD, "tree": TREE},
        "staging": {
            "marker_sha256": "c" * 64,
            "initialized_images": {"ingress": "sha256:" + "a" * 64, "clinical-adapter": "sha256:" + "b" * 64},
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
            "metadata_scope": "synthetic-controlled-only",
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
        marker_sha256="c" * 64,
        initialized_images={"ingress": "sha256:" + "a" * 64, "clinical-adapter": "sha256:" + "b" * 64},
        proof_sha256={"ingress": "d" * 64, "clinical-adapter": "e" * 64},
        green={service: {name: True for name in module.DENIED_CLASSES} for service in module.POLICIES},
        cleanup={"network_absent": True, "sink_absent": True},
        green_proof_sha256="f" * 64,
        fixed={service: {"public_dns_example_com": False, "metadata_ipv4": "network-unreachable", "metadata_ipv6": "network-unreachable"} for service in module.POLICIES},
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
            observations=observations, marker_sha256="c" * 64,
            initialized_images={"ingress": "sha256:" + "a" * 64, "clinical-adapter": "sha256:" + "b" * 64},
            proof_sha256={"ingress": "d" * 64, "clinical-adapter": "e" * 64},
            green={service: {name: True for name in module.DENIED_CLASSES} for service in module.POLICIES},
            cleanup={"network_absent": True, "sink_absent": True},
            green_proof_sha256="f" * 64,
            fixed={service: {"public_dns_example_com": False, "metadata_ipv4": "network-unreachable", "metadata_ipv6": "network-unreachable"} for service in module.POLICIES},
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
