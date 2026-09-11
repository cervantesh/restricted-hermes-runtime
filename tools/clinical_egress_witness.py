#!/usr/bin/env python3
"""Build and verify the current synthetic clinical egress witness.

This is deliberately a receipt boundary, not a network-policy mechanism.  The
Linux runner obtains the observations through real containers; this program
retains only their fixed, content-safe outcomes, never raw endpoints, logs,
environment values, DNS answers, response bodies, or credentials.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "tools" / "candidate_clinical_egress.py"
SCHEMA = "restricted-runtime-clinical-egress-witness.v1"
SERVICES = ("clinical-adapter", "ingress")
EXPECTED_NETWORKS = {
    "clinical-adapter": ["clinical_upstream"],
    "ingress": ["mattermost_edge"],
}
_VERSION = re.compile(r"[A-Za-z0-9._+:/-]{1,160}")
_IMAGE = re.compile(r"sha256:[a-f0-9]{64}")


def _candidate():
    spec = importlib.util.spec_from_file_location("candidate_clinical_egress", CANDIDATE)
    if spec is None or spec.loader is None:
        raise RuntimeError("candidate egress contract is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def _closed_mapping(value: object, keys: set[str]) -> dict[str, Any] | None:
    if not isinstance(value, dict) or set(value) != keys:
        return None
    return dict(value)


def _environment(value: object) -> dict[str, str] | None:
    fields = _closed_mapping(value, {"system", "kernel", "architecture", "docker", "compose"})
    if fields is None or not all(isinstance(item, str) and _VERSION.fullmatch(item) for item in fields.values()):
        return None
    return fields  # type: ignore[return-value]


def _networks(value: object) -> dict[str, list[str]] | None:
    fields = _closed_mapping(value, set(SERVICES))
    if fields is None:
        return None
    output: dict[str, list[str]] = {}
    for service in SERVICES:
        networks = fields[service]
        if not isinstance(networks, list) or not networks or not all(isinstance(item, str) and _VERSION.fullmatch(item) for item in networks):
            return None
        if networks != sorted(set(networks)):
            return None
        output[service] = networks
    if output != EXPECTED_NETWORKS:
        return None
    return output


def _images(status: Mapping[str, Any]) -> dict[str, str] | None:
    images = status.get("built_images")
    # Staging status binds the full Compose set.  This witness retains only
    # its two edge subjects while refusing to synthesize either one.
    if not isinstance(images, dict) or not set(SERVICES).issubset(images):
        return None
    selected = {service: images[service] for service in SERVICES}
    if not all(isinstance(item, str) and _IMAGE.fullmatch(item) for item in selected.values()):
        return None
    return selected


def build_receipt(
    status: Mapping[str, Any], observations: Mapping[str, Any], environment: Mapping[str, Any],
    networks: Mapping[str, Any], red: Mapping[str, Any], cleanup: Mapping[str, Any],
) -> dict[str, Any]:
    candidate = _candidate()
    candidate_receipt = candidate.build_receipt(status, observations)
    images = _images(status)
    valid_environment = _environment(environment)
    valid_networks = _networks(networks)
    valid_red = _closed_mapping(red, set(SERVICES))
    valid_cleanup = _closed_mapping(cleanup, {"network_absent", "sink_absent"})
    if images is None or valid_environment is None or valid_networks is None:
        raise ValueError("candidate witness binding is incomplete")
    if valid_red != {service: True for service in SERVICES}:
        raise ValueError("controlled RED observations are incomplete")
    if valid_cleanup != {"network_absent": True, "sink_absent": True}:
        raise ValueError("controlled resource cleanup is incomplete")
    receipt = {
        "schema": SCHEMA,
        "synthetic_non_phi_only": True,
        "candidate_receipt": candidate_receipt,
        "effective_images": images,
        "environment": valid_environment,
        "network_membership": valid_networks,
        "controlled_red": valid_red,
        "cleanup": valid_cleanup,
    }
    if verify_receipt(canonical_bytes(receipt), expected_source=status.get("source")):
        raise ValueError("candidate witness is not admissible")
    return receipt


def verify_receipt(raw: bytes, *, expected_source: object) -> list[str]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return ["canonical"]
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        return ["canonical"]
    if set(value) != {"schema", "synthetic_non_phi_only", "candidate_receipt", "effective_images", "environment", "network_membership", "controlled_red", "cleanup"}:
        return ["fields"]
    if value["schema"] != SCHEMA or value["synthetic_non_phi_only"] is not True:
        return ["schema"]
    candidate = _candidate()
    if candidate.verify_receipt(candidate.canonical_bytes(value["candidate_receipt"]), expected_source=expected_source):
        return ["candidate-receipt"]
    if _images({"built_images": value["effective_images"]}) is None:
        return ["images"]
    if _environment(value["environment"]) is None:
        return ["environment"]
    if _networks(value["network_membership"]) is None:
        return ["networks"]
    if value["controlled_red"] != {service: True for service in SERVICES}:
        return ["red"]
    if value["cleanup"] != {"network_absent": True, "sink_absent": True}:
        return ["cleanup"]
    return []


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("input must be a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    for name in ("status", "observations", "environment", "networks", "red", "cleanup"):
        build.add_argument(f"--{name}", required=True, type=Path)
    build.add_argument("--output", required=True, type=Path)
    verify = sub.add_parser("verify")
    verify.add_argument("--receipt", required=True, type=Path)
    verify.add_argument("--status", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            receipt = build_receipt(*(_read(getattr(args, name)) for name in ("status", "observations", "environment", "networks", "red", "cleanup")))
            args.output.write_bytes(canonical_bytes(receipt))
        else:
            errors = verify_receipt(args.receipt.read_bytes(), expected_source=_read(args.status).get("source"))
            if errors:
                raise ValueError(errors[0])
    except (OSError, ValueError):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
