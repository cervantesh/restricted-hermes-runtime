"""Closed wire contracts and RFC 8785-compatible restricted canonicalization."""
from __future__ import annotations

import json
import math
import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

TURN_SCHEMA = "restricted-turn.v1"
RESULT_SCHEMA = "restricted-turn-result.v1"
CONTENT_AAD_SCHEMA = "restricted-content-aad.v1"
PHI = "PHI"
MAX_CANONICAL_BYTES = 131_072


class ContractError(ValueError):
    """A closed-contract rejection; callers must not echo its input."""


class ClinicalAuthorizationDenied(ContractError):
    """An authoritative clinical denial that must never be retried as transient."""


class Classification(StrEnum):
    PHI = "PHI"


class TurnState(StrEnum):
    RECEIVED = "RECEIVED"
    REQUEST_COMMITTED = "REQUEST_COMMITTED"
    INFERENCE_PENDING = "INFERENCE_PENDING"
    RESPONSE_RECEIVED = "RESPONSE_RECEIVED"
    COMMITTED = "COMMITTED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    INDETERMINATE = "INDETERMINATE"

    @property
    def terminal(self) -> bool:
        return self in {self.COMMITTED, self.REJECTED, self.FAILED, self.INDETERMINATE}


class AttemptState(StrEnum):
    RESERVED = "RESERVED"
    DISPATCH_STARTED = "DISPATCH_STARTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    INDETERMINATE = "INDETERMINATE"
    CANCELLED_NO_DISPATCH = "CANCELLED_NO_DISPATCH"

@dataclass(frozen=True)
class ProviderResult:
    state: str
    text: str | None = None
    failure_class: str | None = None
    provider_request_id: str | None = None
    decision_id: str | None = None
    policy_epoch: str | None = None
    policy_digest: str | None = None
    broker_declared_model_sha256: str | None = None


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ContractError("duplicate JSON object key")
        obj[key] = value
    return obj


def load_closed_json(raw: bytes | str) -> Any:
    """Parse one UTF-8 JSON value, rejecting duplicate keys and invalid Unicode."""
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ContractError("invalid UTF-8") from exc
    if raw.startswith("\ufeff"):
        raise ContractError("BOM is prohibited")
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicate_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ContractError("non-finite number")))
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ContractError("invalid JSON") from exc
    _reject_surrogates(value)
    return value


def _reject_surrogates(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise ContractError("invalid Unicode surrogate")
    elif isinstance(value, list):
        for item in value:
            _reject_surrogates(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_surrogates(key)
            _reject_surrogates(item)


def jcs_bytes(value: Any) -> bytes:
    """Canonical JSON for the restricted schemas.

    RFC 8785 ordering and escaping are implemented without accepting floats;
    closed v0 wire objects contain strings, booleans, integers, arrays, and maps.
    Rejecting floats avoids silently implementing an incomplete number grammar.
    """
    _reject_surrogates(value)
    def encode(v: Any) -> str:
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            if not math.isfinite(v):
                raise ContractError("non-finite number")
            raise ContractError("floats are not in the closed restricted schema")
        if isinstance(v, str):
            return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
        if isinstance(v, list):
            return "[" + ",".join(encode(x) for x in v) + "]"
        if isinstance(v, dict):
            if not all(isinstance(k, str) for k in v):
                raise ContractError("object keys must be strings")
            return "{" + ",".join(encode(k) + ":" + encode(v[k]) for k in sorted(v)) + "}"
        raise ContractError("unsupported canonical JSON type")
    return encode(value).encode("utf-8")


def _closed_object(value: Any, allowed: set[str], required: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != allowed or not required <= set(value):
        raise ContractError("unknown, missing, or invalid fields")
    return value


@dataclass(frozen=True)
class TurnRequest:
    schema_version: str
    client_request_id: str
    conversation_epoch: str
    message: str

    @classmethod
    def parse(cls, body: Any) -> "TurnRequest":
        data = _closed_object(body, {"schema_version", "client_request_id", "conversation_epoch", "message"}, {"schema_version", "client_request_id", "conversation_epoch", "message"})
        if data["schema_version"] != TURN_SCHEMA:
            raise ContractError("unsupported schema")
        if not all(isinstance(data[k], str) and data[k] for k in data):
            raise ContractError("turn fields must be non-empty strings")
        try:
            uuid.UUID(data["client_request_id"])
        except ValueError as exc:
            raise ContractError("client_request_id must be UUID") from exc
        return cls(**data)

    def identity(self, *, principal: str, tenant_id: str, conversation_id: str) -> dict[str, str]:
        if not principal or not tenant_id or not conversation_id:
            raise ContractError("server identity is required")
        return {
            "authenticated_caller_principal": principal,
            "tenant_id": tenant_id,
            "conversation_id": conversation_id,
            "conversation_epoch": self.conversation_epoch,
            "schema_version": self.schema_version,
            "client_request_id": self.client_request_id,
            "message": self.message,
        }


def content_aad(*, tenant_id: str, conversation_id: str, conversation_epoch: str, turn_id: str, client_request_id: str, direction: str, policy_digest: str, content_schema_version: str = "restricted-content.v1") -> bytes:
    if direction not in {"request", "response"}:
        raise ContractError("invalid content direction")
    return jcs_bytes({
        "schema_version": CONTENT_AAD_SCHEMA, "tenant_id": tenant_id,
        "conversation_id": conversation_id, "conversation_epoch": conversation_epoch,
        "turn_id": turn_id, "client_request_id": client_request_id,
        "direction": direction, "policy_digest": policy_digest,
        "content_schema_version": content_schema_version,
    })
