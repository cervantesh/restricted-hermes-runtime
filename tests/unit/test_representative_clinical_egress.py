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
        "red_witness": {"detected": True, "cleanup_complete": True},
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
        (lambda value, module: value["services"]["ingress"]["denied"].update(direct_ipv4=False), "denied probe"),
        (lambda value, module: value["services"]["clinical-adapter"]["denied"].pop("direct_ipv6"), "denied classes"),
        (lambda value, module: value["services"]["ingress"].update(proxy_environment_absent=False), "proxy"),
        (lambda value, module: value["services"]["ingress"].update(networks=["mattermost_edge", "escape"]), "networks"),
        (lambda value, module: value["services"]["ingress"]["controls"].update(mount_destinations_exact=False), "mounts or capabilities"),
        (lambda value, module: value["services"]["ingress"].update(image_id="sha256:" + "g" * 64), "image"),
        (lambda value, module: value["runtime"].update(head="f" * 40), "runtime head"),
        (lambda value, module: value["runtime"].update(tree="e" * 40), "runtime tree"),
        (lambda value, module: value["red_witness"].update(cleanup_complete=False), "cleanup"),
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
        red_detected=True,
        cleanup_complete=True,
    )

    assert module.verify_receipt(value, expected_head=HEAD, expected_tree=TREE) == []
    assert set(value) == {"schema", "synthetic_non_phi_only", "runtime", "host", "docker", "services", "red_witness"}
