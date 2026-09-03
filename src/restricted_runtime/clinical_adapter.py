"""Least-privileged AF_UNIX to pinned-HRH adapter for one clinical capability."""
from __future__ import annotations

import http.client
import os
import re
import socket
import ssl
import stat
import struct
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from .contracts import ContractError, jcs_bytes, load_closed_json

MAX_WIRE_BYTES = 65_536
SOCKET_PATH = "/run/restricted-clinical/query.sock"
CLINICAL_SOCKET_GID = 20006
QUERY_INTERNAL = "/v1/clinical/query"
REAUTHORIZE_INTERNAL = "/v1/clinical/reauthorize-delivery"
QUERY_HRH = "/api/restricted-hermes/clinical/next-appointment"
REAUTHORIZE_HRH = "/api/restricted-hermes/clinical/reauthorize-delivery"
_BASE_FIELDS = {
    "mattermostActorId", "patientId", "requestId", "integrationId",
    "clinicalPolicyId", "policyEpoch", "policyDigest",
}
_PATIENT = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _valid_request(value: Any, *, delivery: bool) -> bool:
    fields = _BASE_FIELDS | ({"responseDigest"} if delivery else set())
    return (
        isinstance(value, dict) and set(value) == fields
        and isinstance(value.get("mattermostActorId"), str) and re.fullmatch(r"[a-z0-9]{26}", value["mattermostActorId"]) is not None
        and isinstance(value.get("patientId"), str) and _PATIENT.fullmatch(value["patientId"]) is not None
        and isinstance(value.get("requestId"), str) and re.fullmatch(r"[A-Za-z0-9_-]{8,64}", value["requestId"]) is not None
        and isinstance(value.get("integrationId"), str) and re.fullmatch(r"[A-Za-z0-9_-]{8,64}", value["integrationId"]) is not None
        and value.get("clinicalPolicyId") == "clinical-read-v1"
        and isinstance(value.get("policyEpoch"), str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", value["policyEpoch"]) is not None
        and isinstance(value.get("policyDigest"), str) and re.fullmatch(r"[a-f0-9]{64}", value["policyDigest"]) is not None
        and (not delivery or isinstance(value.get("responseDigest"), str) and re.fullmatch(r"[a-f0-9]{64}", value["responseDigest"]) is not None)
    )


def _valid_upstream_response(path: str, value: Any) -> bool:
    if path == REAUTHORIZE_HRH:
        return isinstance(value, dict) and set(value) == {"authorized"} and value["authorized"] is True
    if not isinstance(value, dict) or set(value) != {"clinicTimezone", "appointment", "responseDigest"}:
        return False
    return (
        value.get("clinicTimezone") == "America/New_York"
        and isinstance(value.get("responseDigest"), str)
        and re.fullmatch(r"[a-f0-9]{64}", value["responseDigest"]) is not None
        and (value.get("appointment") is None or _valid_appointment(value["appointment"]))
    )


def _valid_appointment(value: Any) -> bool:
    valid = (
        isinstance(value, dict) and set(value) == {"id", "date", "time", "duration", "status"}
        and isinstance(value.get("id"), str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value["id"]) is not None
        and isinstance(value.get("date"), str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value["date"]) is not None
        and isinstance(value.get("time"), str) and re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value["time"]) is not None
        and isinstance(value.get("duration"), int) and not isinstance(value["duration"], bool) and 1 <= value["duration"] <= 1440
        and value.get("status") in {"scheduled", "confirmed", "checked_in", "in_progress", "in_service", "post_procedure", "ready_for_checkout", "awaiting_payment", "payment_collected", "checked_out"}
    )
    if not valid:
        return False
    try:
        datetime.strptime(value["date"], "%Y-%m-%d")
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class AdapterConfig:
    hrh_origin: str
    ca_path: Path
    api_key_path: Path
    timeout_seconds: float
    expected_ingress_uid: int

    @classmethod
    def load(cls, path: Path) -> "AdapterConfig":
        value = load_closed_json(path.read_bytes())
        if not isinstance(value, dict) or set(value) != {"hrh_origin", "ca_path", "api_key_path", "timeout_seconds", "expected_ingress_uid"}:
            raise ContractError("clinical adapter configuration rejected")
        origin = urlsplit(value.get("hrh_origin", ""))
        if origin.scheme != "https" or not origin.hostname or origin.username or origin.password or origin.path not in {"", "/"} or origin.query or origin.fragment:
            raise ContractError("clinical adapter HRH origin rejected")
        if not isinstance(value.get("timeout_seconds"), int) or not 1 <= value["timeout_seconds"] <= 10:
            raise ContractError("clinical adapter timeout rejected")
        if not isinstance(value.get("expected_ingress_uid"), int) or value["expected_ingress_uid"] < 1:
            raise ContractError("clinical adapter principal rejected")
        return cls(value["hrh_origin"].rstrip("/"), Path(value["ca_path"]), Path(value["api_key_path"]), float(value["timeout_seconds"]), value["expected_ingress_uid"])


def load_api_key(path: Path, *, expected_uid: int) -> str:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}:
            raise ContractError("clinical adapter secret permissions rejected")
        raw = path.read_bytes()
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError("clinical adapter secret unavailable") from exc
    if not 8 <= len(raw.rstrip(b"\r\n")) <= 4096 or b"\x00" in raw:
        raise ContractError("clinical adapter secret rejected")
    try:
        return raw.decode("ascii").strip()
    except UnicodeError as exc:
        raise ContractError("clinical adapter secret rejected") from exc


class Upstream(Protocol):
    def request(self, path: str, body: dict[str, Any]) -> dict[str, Any]: ...


class HrhHttpsClient:
    def __init__(self, config: AdapterConfig, *, api_key: str):
        self.config, self.api_key = config, api_key
        try:
            self.context = ssl.create_default_context(cafile=str(config.ca_path))
        except (OSError, ssl.SSLError) as exc:
            raise ContractError("clinical adapter trust bundle rejected") from exc

    def request(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        if path not in {QUERY_HRH, REAUTHORIZE_HRH}:
            raise ContractError("clinical adapter HRH route rejected")
        delivery = path == REAUTHORIZE_HRH
        if not _valid_request(body, delivery=delivery):
            raise ContractError("clinical adapter HRH request rejected")
        origin = urlsplit(self.config.hrh_origin)
        deadline = time.monotonic() + self.config.timeout_seconds

        def remaining() -> float:
            budget = deadline - time.monotonic()
            if budget <= 0:
                raise ContractError("clinical adapter HRH deadline exceeded")
            return budget

        connection = http.client.HTTPSConnection(origin.hostname, origin.port or 443, timeout=remaining(), context=self.context)
        raw = jcs_bytes(body)
        try:
            connection.request("POST", path, body=raw, headers={
                "Authorization": "Bearer " + self.api_key,
                "Content-Type": "application/json",
                "Content-Length": str(len(raw)),
                "Accept": "application/json",
            })
            if getattr(connection, "sock", None) is not None:
                connection.sock.settimeout(remaining())
            response = connection.getresponse()
            length = response.getheader("Content-Length")
            content_type = response.getheader("Content-Type")
            if response.status != 200 or content_type not in {"application/json", "application/json; charset=utf-8"} or length is None or not length.isascii() or not length.isdigit():
                raise ContractError("clinical adapter HRH response rejected")
            declared = int(length)
            if declared > MAX_WIRE_BYTES:
                raise ContractError("clinical adapter HRH response oversized")
            if getattr(connection, "sock", None) is not None:
                connection.sock.settimeout(remaining())
            payload = response.read(declared + 1)
            if len(payload) != declared:
                raise ContractError("clinical adapter HRH response framing rejected")
            value = load_closed_json(payload)
            if not _valid_upstream_response(path, value):
                raise ContractError("clinical adapter HRH response schema rejected")
            remaining()
            return value
        except ContractError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError) as exc:
            raise ContractError("clinical adapter HRH transport failed") from exc
        finally:
            connection.close()


def _reply(status: bytes, body: dict[str, Any] | None = None) -> bytes:
    payload = jcs_bytes(body) if body is not None else b"{}"
    return b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(payload)).encode("ascii") + b"\r\n\r\n" + payload


class ClinicalAdapter:
    def __init__(self, *, expected_ingress_uid: int, upstream: Upstream):
        self.expected_ingress_uid, self.upstream = expected_ingress_uid, upstream

    def handle(self, peer_uid: int, raw: bytes) -> bytes:
        if peer_uid != self.expected_ingress_uid:
            return _reply(b"403 Forbidden")
        try:
            if not raw or len(raw) > MAX_WIRE_BYTES:
                raise ContractError("clinical adapter request size rejected")
            head, body_raw = raw.split(b"\r\n\r\n", 1)
            lines = head.split(b"\r\n")
            if not lines or lines[0] not in {
                b"POST /v1/clinical/query HTTP/1.0",
                b"POST /v1/clinical/reauthorize-delivery HTTP/1.0",
            }:
                raise ContractError("clinical adapter request route rejected")
            headers: dict[bytes, bytes] = {}
            for line in lines[1:]:
                name, value = line.split(b": ", 1)
                key = name.lower()
                if key in headers:
                    raise ContractError("clinical adapter duplicate header")
                headers[key] = value
            if set(headers) != {b"host", b"content-type", b"content-length"} or headers[b"host"] != b"localhost" or headers[b"content-type"] != b"application/json":
                raise ContractError("clinical adapter request headers rejected")
            declared = int(headers[b"content-length"])
            if declared != len(body_raw):
                raise ContractError("clinical adapter request framing rejected")
            body = load_closed_json(body_raw)
            delivery = lines[0].startswith(b"POST /v1/clinical/reauthorize-delivery")
            if not _valid_request(body, delivery=delivery):
                raise ContractError("clinical adapter request schema rejected")
            upstream_path = REAUTHORIZE_HRH if delivery else QUERY_HRH
            result = self.upstream.request(upstream_path, body)
            if not _valid_upstream_response(upstream_path, result):
                raise ContractError("clinical adapter upstream shape rejected")
            return _reply(b"200 OK", result)
        except (ContractError, UnicodeError, ValueError):
            return _reply(b"400 Bad Request")
        except (OSError, TimeoutError):
            return _reply(b"503 Service Unavailable")


def peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise ContractError("clinical adapter peer credentials unavailable")
    try:
        _pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        return uid
    except OSError as exc:
        raise ContractError("clinical adapter peer credentials unavailable") from exc


def receive_one(connection: socket.socket, *, timeout_seconds: float) -> bytes:
    connection.settimeout(timeout_seconds)
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_WIRE_BYTES:
        chunk = connection.recv(min(8192, MAX_WIRE_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        joined = b"".join(chunks)
        if b"\r\n\r\n" in joined:
            head, body = joined.split(b"\r\n\r\n", 1)
            match = re.search(br"(?:^|\r\n)Content-Length: ([0-9]+)(?:\r\n|$)", head, re.IGNORECASE)
            if match and len(body) >= int(match.group(1)):
                break
    return b"".join(chunks)


def _bind_listener_at(path: str, *, socket_gid: int) -> socket.socket:
    target = Path(path)
    try:
        before = target.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ContractError("clinical adapter socket path unavailable") from exc
    else:
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.geteuid():
            raise ContractError("clinical adapter stale socket rejected")
        try:
            current = target.lstat()
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                raise ContractError("clinical adapter stale socket changed")
            target.unlink()
        except ContractError:
            raise
        except OSError as exc:
            raise ContractError("clinical adapter stale socket unavailable") from exc
    listener: socket.socket | None = None
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        os.chown(path, -1, socket_gid)
        os.chmod(path, 0o660)
        os.fchmod(listener.fileno(), 0o660)
        metadata = target.lstat()
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != socket_gid
            or stat.S_IMODE(metadata.st_mode) != 0o660
        ):
            raise ContractError("clinical adapter socket ownership verification failed")
        listener.listen(16)
        return listener
    except (OSError, ContractError) as exc:
        if listener is not None:
            listener.close()
        try:
            metadata = target.lstat()
            if stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.geteuid():
                target.unlink()
        except OSError:
            pass
        if isinstance(exc, ContractError):
            raise
        raise ContractError("clinical adapter socket bind failed") from exc


def bind_listener(path: str = SOCKET_PATH, *, socket_gid: int = CLINICAL_SOCKET_GID) -> socket.socket:
    if path != SOCKET_PATH:
        raise ContractError("clinical adapter socket path rejected")
    return _bind_listener_at(path, socket_gid=socket_gid)


def close_listener(listener: socket.socket, *, path: str = SOCKET_PATH, identity: tuple[int, int] | None = None) -> None:
    try:
        current = Path(path).lstat()
        if stat.S_ISSOCK(current.st_mode) and current.st_uid == os.geteuid() and (identity is None or (current.st_dev, current.st_ino) == identity):
            Path(path).unlink()
    except OSError:
        pass
    finally:
        listener.close()
