"""Fail-closed deployment checks for the local Linux profile."""
from __future__ import annotations

import hashlib
import importlib
import os
import socket
import stat
import sys
from pathlib import Path

import psycopg

from .contracts import ContractError, load_closed_json
from .policy import PolicyBundle, load_signed_policy


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ContractError(f"required deployment configuration missing: {name}")
    return value


def _protected_file(path_name: str, digest_name: str) -> None:
    path = Path(_required(path_name))
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ContractError("protected deployment artifact is not a regular file")
        if before.st_uid not in {0, os.geteuid()} or before.st_mode & 0o077:
            raise ContractError("protected deployment artifact ownership or mode rejected")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ContractError("protected deployment artifact changed during open")
            digest = hashlib.file_digest(os.fdopen(os.dup(descriptor), "rb"), "sha256").hexdigest()
        finally:
            os.close(descriptor)
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError("protected deployment artifact is unavailable") from exc
    if digest != _required(digest_name):
        raise ContractError("protected deployment artifact digest mismatch")


def _connect_unix(path: str) -> None:
    target = Path(path)
    try:
        metadata = target.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISSOCK(metadata.st_mode):
            raise ContractError("required deployment socket is invalid")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(path)
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError("required deployment socket is unavailable") from exc


def _expected_conversation_readiness(policy: PolicyBundle) -> dict[str, object]:
    policy.validate()
    return {
        "schema_version": "restricted-conversation-readiness.v1",
        "status": "ready",
        "policy_epoch": policy.epoch,
        "policy_digest": policy.digest,
        "classification": policy.values["classification"],
        "system_instruction_version": policy.values["system_instruction_version"],
        "allowed_modalities": policy.values["allowed_modalities"],
        "tools_allowed": policy.values["tools_allowed"],
        "fallbacks": policy.values["fallbacks"],
        "max_provider_attempts": policy.values["max_provider_attempts"],
        "streaming": policy.values["streaming"],
        "max_output_tokens": policy.values["max_output_tokens"],
        "max_canonical_input_utf8_bytes": policy.values["max_canonical_input_utf8_bytes"],
        "response_profile": policy.values["response_profile"],
    }


def validate_conversation_readiness(raw: bytes, policy: PolicyBundle) -> None:
    """Accept only the exact closed readiness binding for this signed policy."""
    try:
        if load_closed_json(raw) != _expected_conversation_readiness(policy):
            raise ContractError("conversation readiness contract failed")
    except ContractError as exc:
        raise ContractError("conversation readiness contract failed") from exc


def _read_conversation_readiness(response: bytes, policy: PolicyBundle) -> None:
    try:
        head, body = response.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        if not lines or lines[0] != b"HTTP/1.1 200 OK":
            raise ContractError("conversation readiness contract failed")
        lengths = [line.split(b":", 1)[1].strip() for line in lines[1:] if line.lower().startswith(b"content-length:")]
        if len(lengths) != 1 or b"transfer-encoding:" in head.lower() or not lengths[0].isdigit() or int(lengths[0]) != len(body):
            raise ContractError("conversation readiness contract failed")
        validate_conversation_readiness(body, policy)
    except (IndexError, ValueError, ContractError) as exc:
        raise ContractError("conversation readiness contract failed") from exc


def check(role: str) -> None:
    if role not in {"conversation", "gateway"}:
        raise ContractError("deployment role rejected")
    _protected_file("RESTRICTED_OPERATOR_AUTHORIZATION_PATH", "RESTRICTED_OPERATOR_AUTHORIZATION_SHA256")
    _protected_file("RESTRICTED_OPERATOR_AUTHORIZATION_SIGNATURE_PATH", "RESTRICTED_OPERATOR_AUTHORIZATION_SIGNATURE_SHA256")
    if role == "conversation":
        protected = (
            ("RESTRICTED_LOCAL_SERVICE_MAC_KEY_PATH", "RESTRICTED_LOCAL_SERVICE_MAC_KEY_SHA256"),
            ("RESTRICTED_LOCAL_SERVICE_MAC_KEY_RETIRED_KEYS_PATH", "RESTRICTED_LOCAL_SERVICE_MAC_KEY_RETIRED_KEYS_SHA256"),
            ("RESTRICTED_LOCAL_CONTENT_WRAP_KEY_PATH", "RESTRICTED_LOCAL_CONTENT_WRAP_KEY_SHA256"),
            ("RESTRICTED_LOCAL_CONTENT_WRAP_KEY_RETIRED_KEYS_PATH", "RESTRICTED_LOCAL_CONTENT_WRAP_KEY_RETIRED_KEYS_SHA256"),
        )
        socket_path = "/run/restricted-inference/gateway.sock"
    else:
        protected = (
            ("RESTRICTED_LOCAL_GATEWAY_MAC_KEY_PATH", "RESTRICTED_LOCAL_GATEWAY_MAC_KEY_SHA256"),
            ("RESTRICTED_LOCAL_GATEWAY_RETIRED_MAC_KEYS_PATH", "RESTRICTED_LOCAL_GATEWAY_RETIRED_MAC_KEYS_SHA256"),
        )
        socket_path = "/run/restricted-inference/broker.sock"
    for path_name, digest_name in protected:
        _protected_file(path_name, digest_name)
    with psycopg.connect(_required("DATABASE_URL"), connect_timeout=3) as connection:
        connection.execute("SELECT 1").fetchone()
    _connect_unix(socket_path)
    importlib.import_module({
        "conversation": "restricted_runtime.services.production_local_conversation",
        "gateway": "restricted_runtime.services.production_local_gateway",
    }[role])


def ready(role: str) -> None:
    if role == "gateway":
        from .local_gateway_client import LocalGatewayClient
        if not LocalGatewayClient("/run/restricted-inference/gateway.sock").ready(
            _required("RESTRICTED_POLICY_EPOCH"), _required("RESTRICTED_POLICY_DIGEST")
        ):
            raise ContractError("gateway readiness contract failed")
        return
    if role == "conversation":
        path = "/run/restricted-inference/conversation.sock"
        _connect_unix(path)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(3)
            client.connect(path)
            client.sendall(b"GET /readyz HTTP/1.0\r\nHost: localhost\r\n\r\n")
            response = b""
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response += chunk
        policy = load_signed_policy(
            Path(_required("RESTRICTED_POLICY_PATH")),
            Path(_required("RESTRICTED_POLICY_SIGNATURE_PATH")),
            _required("RESTRICTED_POLICY_PUBLIC_KEY_B64"),
        )
        _read_conversation_readiness(response, policy)
        return
    raise ContractError("deployment role rejected")


def _run(role: str) -> None:
    check(role)
    expected = {
        "conversation": "restricted_runtime.services.production_local_conversation",
        "gateway": "restricted_runtime.services.production_local_gateway",
    }[role]
    configured = _required("RESTRICTED_UDS_APP").split(":", 1)[0]
    if configured != expected:
        raise ContractError("deployment app does not match fixed role")
    importlib.import_module(expected)
    from .uds_entrypoint import main
    main()


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in {"check", "ready", "run"}:
        raise SystemExit("usage: local_deployment_preflight.py {check|ready|run} {conversation|gateway}")
    {"check": check, "ready": ready, "run": _run}[sys.argv[1]](sys.argv[2])


if __name__ == "__main__":
    main()
