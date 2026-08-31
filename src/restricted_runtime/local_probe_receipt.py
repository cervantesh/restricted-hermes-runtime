"""Content-free local protocol-probe receipt; external claims are immutable false."""
from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime

from .contracts import ProviderResult
from .policy import LOCAL_POLICY_SCHEMA, PolicyBundle

_REVISION_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_TERMINAL_STATES = {"SUCCEEDED", "FAILED", "INDETERMINATE", "CANCELLED_NO_DISPATCH"}


def protocol_probe_receipt(policy: PolicyBundle, result: ProviderResult, *, source_revision_claim: str) -> dict[str, object]:
    policy.validate()
    if policy.values["schema_version"] != LOCAL_POLICY_SCHEMA:
        raise ValueError("local probe receipt requires the local policy")
    if not isinstance(source_revision_claim, str) or _REVISION_RE.fullmatch(source_revision_claim) is None:
        raise ValueError("source revision claim is not a commit digest")
    if not isinstance(result, ProviderResult) or result.state not in _TERMINAL_STATES:
        raise ValueError("local probe result state is not terminal")
    if not isinstance(result.provider_request_id, str) or not result.provider_request_id:
        raise ValueError("local probe provider request id is required")
    if result.state == "SUCCEEDED" and result.broker_declared_model_sha256 != policy.values["model_sha256"]:
        raise ValueError("local probe model digest mismatch")
    if result.state != "SUCCEEDED" and result.broker_declared_model_sha256 is not None:
        raise ValueError("local probe terminal model field is invalid")
    request_id_digest = hashlib.sha256((result.provider_request_id or "").encode("utf-8")).hexdigest()
    return {
        "schema_version": "restricted-local-protocol-probe-receipt.v1",
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source_revision_claim": source_revision_claim,
        "source_revision_claim_verified": False,
        "policy_epoch": policy.epoch,
        "policy_digest": policy.digest,
        "provider": "local-uds",
        "response_profile": policy.values["response_profile"],
        "broker_declared_model_sha256": result.broker_declared_model_sha256,
        "socket_path": policy.values["socket_path"],
        "terminal_class": result.state,
        "broker_request_id_sha256": request_id_digest,
        "external_controls_verified": False,
        "deployment_conformant": False,
        "model_attested": False,
        "phi_authorized": False,
    }
