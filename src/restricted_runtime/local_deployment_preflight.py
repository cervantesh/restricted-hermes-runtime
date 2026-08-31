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

from .contracts import ContractError


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
        if not response.startswith(b"HTTP/1.1 200 OK\r\n"):
            raise ContractError("conversation readiness contract failed")
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
