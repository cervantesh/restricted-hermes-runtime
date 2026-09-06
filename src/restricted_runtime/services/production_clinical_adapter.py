"""Production entry point for the dedicated clinical UDS-to-HRH adapter."""
from __future__ import annotations

import os
from pathlib import Path

from ..clinical_adapter import AdapterConfig, ClinicalAdapter, HrhHttpsClient, SOCKET_PATH, bind_listener, close_listener, load_api_key, peer_uid, receive_one
from ..contracts import ContractError


def _serial_linux_deadline_supported() -> bool:
    """The upstream wall-clock guard relies on Linux/POSIX SIGALRM semantics."""
    return os.name == "posix"


def serve_connection(service: ClinicalAdapter, connection, *, timeout_seconds: float) -> None:
    try:
        raw = receive_one(connection, timeout_seconds=timeout_seconds)
        response = service.handle(peer_uid(connection), raw)
    except (ContractError, OSError, TimeoutError):
        response = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}"
    try:
        connection.sendall(response)
    except OSError:
        return


def run() -> None:
    config_path = Path(os.environ.get("RESTRICTED_CLINICAL_ADAPTER_CONFIG_PATH", "/app/config/clinical-adapter.json"))
    config = AdapterConfig.load(config_path)
    if not _serial_linux_deadline_supported():
        raise ContractError("clinical adapter upstream deadline unavailable")
    effective_uid = getattr(os, "geteuid", lambda: config.api_key_path.stat().st_uid)()
    api_key = load_api_key(config.api_key_path, expected_uid=effective_uid)
    service = ClinicalAdapter(
        expected_ingress_uid=config.expected_ingress_uid,
        expected_clinical_timezone=config.expected_clinical_timezone,
        upstream=HrhHttpsClient(config, api_key=api_key),
    )
    listener = bind_listener()
    identity = (Path(SOCKET_PATH).lstat().st_dev, Path(SOCKET_PATH).lstat().st_ino)
    try:
        while True:
            connection, _ = listener.accept()
            with connection:
                serve_connection(service, connection, timeout_seconds=config.timeout_seconds)
    finally:
        close_listener(listener, identity=identity)


def main() -> None:
    try:
        run()
    except Exception:
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
