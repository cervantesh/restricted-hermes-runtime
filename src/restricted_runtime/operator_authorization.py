"""Offline operator authority for the self-hosted local-UDS profile.

This validates a binding supplied by the operator; it does not assert anything
about host controls, broker provenance, model attestation, or PHI compliance.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import ContractError, jcs_bytes, load_closed_json
from .policy import LOCAL_POLICY_SCHEMA, PolicyBundle


_FIELDS = {"schema_version", "policy_epoch", "policy_digest", "tenant_id", "provider", "model_sha256", "permitted_use_id", "issued_at", "expires_at"}


@dataclass(frozen=True)
class OperatorAuthorization:
    permitted_use_id: str
    issued_at: datetime
    expires_at: datetime


def _instant(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ContractError("operator authorization instant is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("operator authorization instant is invalid") from exc
    if parsed.tzinfo is None:
        raise ContractError("operator authorization instant requires timezone")
    return parsed.astimezone(UTC)


def load_operator_authorization(values: Any, signature_b64: str, public_key_b64: str, policy: PolicyBundle, *, now: datetime | None = None) -> OperatorAuthorization:
    policy.validate()
    if policy.values["schema_version"] != LOCAL_POLICY_SCHEMA:
        raise ContractError("operator authorization is local-profile only")
    if not isinstance(values, dict) or set(values) != _FIELDS or values.get("schema_version") != "restricted-operator-authorization.v1":
        raise ContractError("operator authorization schema is closed")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True))
        key.verify(signature, jcs_bytes(values))
    except Exception as exc:
        raise ContractError("operator authorization signature validation failed") from exc
    bindings = {
        "policy_epoch": policy.epoch,
        "policy_digest": policy.digest,
        "tenant_id": policy.values["tenant_id"],
        "provider": "local-uds",
        "model_sha256": policy.values["model_sha256"],
    }
    if any(values.get(key) != value for key, value in bindings.items()):
        raise ContractError("operator authorization binding mismatch")
    if not isinstance(values["permitted_use_id"], str) or not values["permitted_use_id"]:
        raise ContractError("operator authorization permitted use is required")
    issued_at, expires_at = _instant(values["issued_at"]), _instant(values["expires_at"])
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if issued_at > current or expires_at <= current or expires_at <= issued_at:
        raise ContractError("operator authorization is not currently valid")
    return OperatorAuthorization(values["permitted_use_id"], issued_at, expires_at)


def load_operator_authorization_files(path: Path, signature_path: Path, public_key_b64: str, policy: PolicyBundle) -> OperatorAuthorization:
    try:
        values = load_closed_json(path.read_bytes())
        signature = signature_path.read_text(encoding="ascii")
    except Exception as exc:
        raise ContractError("operator authorization artifact is unavailable") from exc
    return load_operator_authorization(values, signature, public_key_b64, policy)


@dataclass(frozen=True)
class OperatorAuthorizationGate:
    path: Path
    signature_path: Path
    public_key_b64: str
    policy: PolicyBundle
    clock: callable = lambda: datetime.now(UTC)
    def __call__(self) -> None:
        load_operator_authorization_files_at(self.path, self.signature_path, self.public_key_b64, self.policy, self.clock())


def load_operator_authorization_files_at(path: Path, signature_path: Path, public_key_b64: str, policy: PolicyBundle, now: datetime) -> OperatorAuthorization:
    try:
        values = load_closed_json(path.read_bytes()); signature = signature_path.read_text(encoding="ascii")
    except Exception as exc:
        raise ContractError("operator authorization artifact is unavailable") from exc
    return load_operator_authorization(values, signature, public_key_b64, policy, now=now)
