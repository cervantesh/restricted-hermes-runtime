"""Closed, offline-signed policy for the standalone restricted Mattermost edge."""
from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import ContractError, jcs_bytes, load_closed_json

MATTERMOST_POLICY_SCHEMA = "restricted-mattermost-ingress-policy.v1"
MAX_TOKEN_BYTES = 4096
MAX_EVENT_BYTES = 1_048_576
_MAX_MESSAGE_BYTES = 131_072
_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_USERNAME = re.compile(r"^[a-z0-9._-]{1,64}$")
_FIELDS = {
    "schema_version", "policy_epoch", "inference_policy_epoch", "inference_policy_digest",
    "tenant_id", "origin", "team_id", "allowed_channel_ids", "allowed_user_ids",
    "bot_user_id", "bot_username", "allowed_modality", "dms_allowed", "files_allowed",
    "delivery_mode", "initiation_mode", "max_message_utf8_bytes", "not_before",
    "expires_at", "clock_skew_seconds", "websocket_timeout_seconds",
    "rest_timeout_seconds", "uds_timeout_seconds", "conversation_deadline_seconds",
    "outbox_key_fingerprint", "outbox_payload_retention_seconds", "outbox_payload_capacity",
    "outbox_tombstone_capacity", "outbox_scan_limit", "outbox_scan_interval_seconds",
}


def _utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ContractError("Mattermost policy timestamp is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ContractError("Mattermost policy timestamp is invalid") from exc
    if parsed.tzinfo != UTC or parsed.microsecond:
        raise ContractError("Mattermost policy timestamp is not canonical UTC")
    return parsed


def _ids(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 256:
        raise ContractError(f"Mattermost {name} allowlist is empty or oversized")
    if any(not isinstance(item, str) or not _ID.fullmatch(item) for item in value):
        raise ContractError(f"Mattermost {name} allowlist is invalid")
    if len(set(value)) != len(value) or value != sorted(value):
        raise ContractError(f"Mattermost {name} allowlist is not canonical")
    return tuple(value)


@dataclass(frozen=True)
class MattermostPolicy:
    values: dict[str, Any]
    digest: str

    @property
    def origin(self) -> str:
        return str(self.values["origin"])

    def validate(self, *, now: datetime | None = None) -> None:
        value = self.values
        if set(value) != _FIELDS or value.get("schema_version") != MATTERMOST_POLICY_SCHEMA:
            raise ContractError("Mattermost ingress policy schema is closed")
        split = urlsplit(value.get("origin", ""))
        if (
            split.scheme != "https" or not split.hostname or split.username is not None
            or split.password is not None or split.path or split.query or split.fragment
            or split.hostname != split.hostname.lower() or split.port == 443
            or value["origin"] != f"https://{split.hostname}" + (f":{split.port}" if split.port else "")
        ):
            raise ContractError("Mattermost origin is not exact canonical HTTPS")
        scalar_ids = ("team_id", "bot_user_id", "tenant_id", "policy_epoch", "inference_policy_epoch")
        if any(not isinstance(value.get(name), str) or not _ID.fullmatch(value[name]) for name in scalar_ids):
            raise ContractError("Mattermost identity binding is invalid")
        _ids(value.get("allowed_channel_ids"), "channel")
        _ids(value.get("allowed_user_ids"), "user")
        if value["bot_user_id"] in value["allowed_user_ids"]:
            raise ContractError("Mattermost bot cannot be an allowed initiator")
        if not isinstance(value.get("bot_username"), str) or not _USERNAME.fullmatch(value["bot_username"]):
            raise ContractError("Mattermost bot username is invalid")
        digest = value.get("inference_policy_digest")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ContractError("inference policy digest is invalid")
        expected = {
            "allowed_modality": "text", "dms_allowed": False, "files_allowed": False,
            "delivery_mode": "thread-only", "initiation_mode": "explicit-mention",
        }
        if any(value.get(key) != item for key, item in expected.items()):
            raise ContractError("Mattermost ingress capability is outside the closed contract")
        limit = value.get("max_message_utf8_bytes")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 0 < limit <= _MAX_MESSAGE_BYTES:
            raise ContractError("Mattermost message limit is invalid")
        skew = value.get("clock_skew_seconds")
        if not isinstance(skew, int) or isinstance(skew, bool) or not 0 <= skew <= 60:
            raise ContractError("Mattermost policy clock skew is invalid")
        rest, websocket, uds, downstream = (
            value.get("rest_timeout_seconds"), value.get("websocket_timeout_seconds"),
            value.get("uds_timeout_seconds"), value.get("conversation_deadline_seconds"),
        )
        if any(not isinstance(item, int) or isinstance(item, bool) for item in (rest, websocket, uds, downstream)):
            raise ContractError("Mattermost deadlines must be integers")
        if not (1 <= rest <= 30 and 1 <= websocket <= 60 and 1 <= downstream <= 60 and downstream <= uds <= 90):
            raise ContractError("Mattermost deadlines are not safely ordered")
        fingerprint = value.get("outbox_key_fingerprint")
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ContractError("Mattermost outbox key fingerprint is invalid")
        retention, payload_capacity, tombstone_capacity, scan_limit, scan_interval = (
            value.get("outbox_payload_retention_seconds"), value.get("outbox_payload_capacity"),
            value.get("outbox_tombstone_capacity"), value.get("outbox_scan_limit"),
            value.get("outbox_scan_interval_seconds"),
        )
        if any(not isinstance(item, int) or isinstance(item, bool) for item in (retention, payload_capacity, tombstone_capacity, scan_limit, scan_interval)):
            raise ContractError("Mattermost outbox limits are invalid")
        if not (60 <= retention <= 86_400 and 1 <= payload_capacity <= 100_000 and 1 <= tombstone_capacity <= 100_000 and 1 <= scan_limit <= 1_000 and 1 <= scan_interval <= 60):
            raise ContractError("Mattermost outbox limits are outside the closed contract")
        current = now or datetime.now(UTC)
        if current.tzinfo != UTC:
            raise ContractError("Mattermost policy validation clock must be UTC")
        not_before, expires = _utc(value["not_before"]), _utc(value["expires_at"])
        if not_before >= expires:
            raise ContractError("Mattermost policy validity window is invalid")
        allowance = timedelta(seconds=skew)
        if current + allowance < not_before:
            raise ContractError("Mattermost policy is not yet valid")
        if current - allowance > expires:
            raise ContractError("Mattermost policy is expired")


def load_signed_mattermost_policy(
    path: Path, signature_path: Path, public_key_b64: str, *, now: datetime | None = None
) -> MattermostPolicy:
    try:
        values = load_closed_json(path.read_bytes())
        signature = base64.b64decode(signature_path.read_text(encoding="ascii"), validate=True)
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True))
        key.verify(signature, jcs_bytes(values))
    except Exception as exc:
        raise ContractError("Mattermost policy signature validation failed") from exc
    if not isinstance(values, dict):
        raise ContractError("Mattermost ingress policy schema is closed")
    policy = MattermostPolicy(values, hashlib.sha256(jcs_bytes(values)).hexdigest())
    policy.validate(now=now)
    return policy


def load_token(path: Path) -> str:
    """Read the operator-mounted token once without following a link."""
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_TOKEN_BYTES:
            raise ContractError("Mattermost token artifact is invalid")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ContractError("Mattermost token artifact changed during open")
            raw = os.read(descriptor, MAX_TOKEN_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(raw) > MAX_TOKEN_BYTES:
            raise ContractError("Mattermost token artifact is oversized")
        token = raw.decode("utf-8", "strict").strip()
        if not token or any(character.isspace() for character in token):
            raise ContractError("Mattermost token artifact is malformed")
        return token
    except ContractError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ContractError("Mattermost token artifact is unavailable") from exc
