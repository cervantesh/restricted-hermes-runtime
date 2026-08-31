"""Content-free local protocol-probe receipt; external claims are immutable false."""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from .contracts import ProviderResult
from .policy import LOCAL_POLICY_SCHEMA, PolicyBundle


def protocol_probe_receipt(policy: PolicyBundle, result: ProviderResult, *, source_revision_claim: str) -> dict[str, object]:
    policy.validate()
    if policy.values["schema_version"] != LOCAL_POLICY_SCHEMA:
        raise ValueError("local probe receipt requires the local policy")
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
