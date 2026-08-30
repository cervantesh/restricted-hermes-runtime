"""Closed parsing for retired Cloud KMS MAC verifier configuration."""
from __future__ import annotations

import json


def parse_retired_versions(value: str, *, active_resource: str, active_version: str) -> dict[tuple[str, str], str]:
    """Return verifier-only retired versions, rejecting ambiguous key aliases."""
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=reject_duplicates)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("retired KMS map must be closed JSON") from exc
    if not isinstance(parsed, list):
        raise RuntimeError("retired KMS map must be an array")
    result: dict[tuple[str, str], str] = {}
    for item in parsed:
        if not isinstance(item, dict) or set(item) != {"key_resource", "key_version", "verify_version"}:
            raise RuntimeError("invalid retired KMS map")
        if not all(isinstance(item[key], str) and item[key] for key in item):
            raise RuntimeError("invalid retired KMS map")
        key = (item["key_resource"], item["key_version"])
        verifier = item["verify_version"]
        if key in result or key == (active_resource, active_version):
            raise RuntimeError("invalid retired KMS alias")
        # A verifier name is a full version path owned by precisely its declared
        # key resource.  Never silently accept an active-version alias.
        if verifier == active_version or not verifier.startswith(item["key_resource"] + "/cryptoKeyVersions/"):
            raise RuntimeError("retired verifier is not bound to its key resource")
        result[key] = verifier
    return result
