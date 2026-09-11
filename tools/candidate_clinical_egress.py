#!/usr/bin/env python3
"""Validate the content-safe, candidate-bound egress receipt contract.

Collection is deliberately separate: this module rejects a receipt unless it
binds the source and restricted-container evidence already emitted by the
current staging lifecycle.  It never serializes raw probe output, endpoints,
environment values, logs, or secrets.
"""
from __future__ import annotations

import json
import re
from typing import Any, Mapping


SCHEMA = "restricted-runtime-candidate-clinical-egress.v1"
SERVICES = ("clinical-adapter", "ingress")
DENIED_CLASSES = (
    "public_ipv4", "public_ipv6", "public_dns", "metadata_ipv4",
    "metadata_ipv6", "metadata_dns", "proxy_environment",
)
ALLOWED_CLASSES = {
    "clinical-adapter": ("hrh_tls",),
    "ingress": ("mattermost",),
}
EXPECTED_RESTRICTED_CONTROLS = {
    "clinical-adapter": {
        "user": "restricted-clinical-adapter", "privileged": False,
        "read_only_rootfs": True, "cap_drop": ["ALL"],
        "no_new_privileges": True, "tmpfs": ["/tmp"],
        "read_only_mounts": ["/run/clinical-config", "/run/hrh-secret", "/run/hrh-tls"],
        "writable_mounts": ["/run/restricted-clinical"],
    },
    "ingress": {
        "user": "restricted-mattermost-ingress", "privileged": False,
        "read_only_rootfs": True, "cap_drop": ["ALL"],
        "no_new_privileges": True, "tmpfs": ["/tmp"],
        "read_only_mounts": ["/run/ingress"],
        "writable_mounts": ["/run/restricted-clinical", "/var/lib/restricted-mattermost-outbox"],
    },
}
EXPECTED_RESTRICTED_IDENTITIES = {
    "clinical-adapter": {"uid": 10008, "gid": 20007, "groups": [20006, 20007]},
    "ingress": {"uid": 10007, "gid": 20005, "groups": [20000, 20001, 20005, 20006]},
}
_SHA = re.compile(r"[a-f0-9]{40}")
_IMAGE = re.compile(r"sha256:[a-f0-9]{64}")


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def _parse_canonical(raw: object) -> dict[str, Any] | None:
    if not isinstance(raw, bytes):
        return None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        return None
    return value


def _source(value: object) -> dict[str, str] | None:
    if not isinstance(value, dict) or set(value) != {"runtime_head", "runtime_tree", "hrh_head", "hrh_tree"}:
        return None
    if not all(isinstance(item, str) and _SHA.fullmatch(item) for item in value.values()):
        return None
    return dict(value)


def _strict_equal(observed: object, expected: object) -> bool:
    """Compare JSON-shaped evidence without accepting bool/int aliases."""
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(observed) == set(expected) and all(_strict_equal(observed[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return len(observed) == len(expected) and all(_strict_equal(item, value) for item, value in zip(observed, expected))
    return observed == expected


def _images(status: object) -> dict[str, str] | None:
    if not isinstance(status, dict):
        return None
    images = status.get("built_images")
    if not isinstance(images, dict) or not set(SERVICES).issubset(images):
        return None
    selected = {service: images[service] for service in SERVICES}
    if not all(isinstance(image, str) and _IMAGE.fullmatch(image) for image in selected.values()):
        return None
    return selected


def _restricted_evidence(status: object) -> tuple[dict[str, Any], dict[str, Any]] | None:
    if not isinstance(status, dict):
        return None
    controls = status.get("restricted_container_controls")
    identities = status.get("restricted_process_identities")
    if not isinstance(controls, dict) or not isinstance(identities, dict):
        return None
    if set(controls) != set(SERVICES) or set(identities) != set(SERVICES):
        return None
    for service in SERVICES:
        control = controls[service]
        identity = identities[service]
        if not _strict_equal(control, EXPECTED_RESTRICTED_CONTROLS[service]) or not _strict_equal(identity, EXPECTED_RESTRICTED_IDENTITIES[service]):
            return None
    return controls, identities


def build_receipt(status: Mapping[str, Any], observations: Mapping[str, Any]) -> dict[str, Any]:
    source = _source(status.get("source"))
    restricted = _restricted_evidence(status)
    images = _images(status)
    if source is None or restricted is None or images is None:
        raise ValueError("status is not an admissible candidate binding")
    controls, identities = restricted
    receipt = {
        "schema": SCHEMA,
        "synthetic_non_phi_only": True,
        "source": source,
        "restricted_container_controls": controls,
        "restricted_process_identities": identities,
        "effective_images": images,
        "services": dict(observations),
    }
    if verify_receipt(canonical_bytes(receipt), expected_status=status):
        raise ValueError("observations are not an admissible content-safe egress receipt")
    return receipt


def verify_receipt(raw: bytes, *, expected_status: Mapping[str, Any]) -> list[str]:
    value = _parse_canonical(raw)
    if value is None:
        return ["canonical"]
    if set(value) != {
        "schema", "synthetic_non_phi_only", "source", "restricted_container_controls",
        "restricted_process_identities", "effective_images", "services",
    }:
        return ["fields"]
    if value["schema"] != SCHEMA or value["synthetic_non_phi_only"] is not True:
        return ["schema"]
    source = _source(value["source"])
    expected_source = _source(expected_status.get("source"))
    if source is None or expected_source is None or source != expected_source:
        return ["source"]
    if _restricted_evidence(value) is None:
        return ["restricted-evidence"]
    images = _images({"built_images": value["effective_images"]})
    expected_images = _images(expected_status)
    if images is None or expected_images is None or images != expected_images:
        return ["images"]
    services = value["services"]
    if not isinstance(services, dict) or set(services) != set(SERVICES):
        return ["services"]
    for service in SERVICES:
        observed = services[service]
        if not isinstance(observed, dict) or set(observed) != {"denied", "allowed"}:
            return ["services"]
        if not _strict_equal(observed["denied"], {name: True for name in DENIED_CLASSES}):
            return ["denied"]
        if not _strict_equal(observed["allowed"], {name: True for name in ALLOWED_CLASSES[service]}):
            return ["allowed"]
    return []
