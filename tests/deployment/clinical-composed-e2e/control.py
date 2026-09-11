"""Synthetic control plane for the real Mattermost -> runtime -> HRH path."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from restricted_runtime.contracts import jcs_bytes, load_closed_json
from restricted_runtime.mattermost_ingress import request_identity
from restricted_runtime.mattermost_policy import MattermostPolicy
from restricted_runtime.mattermost_outbox import MattermostOutbox, key_fingerprint


STATE = Path("/state")
SEED = Path("/seed")
INGRESS = Path("/run/ingress")
OUTBOX = Path("/var/lib/restricted-mattermost-outbox")
MM_TLS = Path("/run/mattermost-tls")
HRH_TLS = Path("/run/hrh-tls")
HRH_SECRET = Path("/run/hrh-secret")
ADAPTER_CONFIG = Path("/run/clinical-config")
MM_BASE = "https://mattermost:8065/api/v4"
HRH_BASE = "https://hrh-tls:8443"
PATIENT_ID = "018f22bb-414d-7cc4-b5a4-83cc8ec92cb1"
OTHER_PATIENT_ID = "018f22bb-414d-7cc4-b5a4-83cc8ec92cb2"
INTEGRATION_ID = "mattermost_aali_01"
CLINICAL_POLICY_ID = "clinical-read-v1"


class ApiError(RuntimeError):
    def __init__(self, status: int, code: str = "unknown", message: str = "unknown"):
        super().__init__(f"synthetic API returned status {status}")
        self.status = status
        self.code = code
        self.message = message


def _copy(source: Path, destination: Path, *, uid: int, gid: int, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chown(destination, uid, gid)
    os.chmod(destination, mode)


def seed_volumes() -> None:
    if any(path.exists() and any(path.iterdir()) for path in (INGRESS, MM_TLS, HRH_TLS, HRH_SECRET, ADAPTER_CONFIG)):
        raise RuntimeError("clinical E2E volumes are not empty")
    for name in ("ca.crt", "mattermost.crt", "mattermost.key"):
        target = "server.crt" if name == "mattermost.crt" else "server.key" if name == "mattermost.key" else name
        _copy(SEED / name, MM_TLS / target, uid=2000, gid=2000, mode=0o440 if target.endswith(".key") else 0o444)
    for name in ("ca.crt", "hrh-tls.crt", "hrh-tls.key"):
        target = "server.crt" if name == "hrh-tls.crt" else "server.key" if name == "hrh-tls.key" else name
        _copy(SEED / name, HRH_TLS / target, uid=101, gid=101, mode=0o440 if target.endswith(".key") else 0o444)
    _copy(SEED / "hrh_api_key", HRH_SECRET / "api-key", uid=10008, gid=20007, mode=0o400)
    adapter = {
        "api_key_path": "/run/hrh-secret/api-key",
        "ca_path": "/run/hrh-tls/ca.crt",
        "expected_ingress_uid": 10007,
        "expected_clinical_timezone": "America/New_York",
        "hrh_origin": "https://hrh-tls:8443",
        "timeout_seconds": 10,
    }
    (ADAPTER_CONFIG / "adapter.json").write_text(json.dumps(adapter, sort_keys=True, separators=(",", ":")), encoding="ascii")
    os.chown(ADAPTER_CONFIG / "adapter.json", 10008, 20007)
    os.chmod(ADAPTER_CONFIG / "adapter.json", 0o440)
    outbox_key = INGRESS / "outbox.key"
    outbox_key.write_bytes(os.urandom(32))
    os.chown(outbox_key, 10007, 20005)
    os.chmod(outbox_key, 0o400)


def _mm_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(MM_TLS / "ca.crt"))


def _hrh_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(HRH_TLS / "ca.crt"))


def request(base: str, context: ssl.SSLContext, method: str, path: str, body: Any = None, token: str | None = None) -> tuple[Any, dict[str, str]]:
    raw = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {"Accept": "application/json"}
    if raw is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    operation = urllib.request.Request(base + path, data=raw, method=method, headers=headers)
    try:
        with urllib.request.urlopen(operation, context=context, timeout=20) as response:
            payload = response.read()
            return (json.loads(payload) if payload else {}), {k.lower(): v for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        try:
            decoded = json.loads(payload)
            code = str(decoded.get("code", "unknown"))
            message = str(decoded.get("message", "unknown"))
        except (json.JSONDecodeError, AttributeError):
            code = "unknown"
            message = "unknown"
        raise ApiError(exc.code, code, message) from None


def wait_https(base: str, context: ssl.SSLContext, path: str) -> None:
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        try:
            request(base, context, "GET", path)
            return
        except (ApiError, OSError, urllib.error.URLError):
            time.sleep(0.5)
    raise RuntimeError("HTTPS readiness deadline exceeded")


def login(email: str, password: str) -> tuple[dict[str, Any], str]:
    user, headers = request(MM_BASE, _mm_context(), "POST", "/users/login", {"login_id": email, "password": password})
    token = headers.get("token")
    if not isinstance(user, dict) or not isinstance(token, str):
        raise RuntimeError("Mattermost login failed")
    return user, token


def optional_get(path: str, token: str) -> Any | None:
    try:
        return request(MM_BASE, _mm_context(), "GET", path, token=token)[0]
    except ApiError as exc:
        if exc.status == 404:
            return None
        raise


def ensure_user(username: str, email: str, password: str, admin_token: str) -> dict[str, Any]:
    user = optional_get("/users/username/" + username, admin_token)
    if user is None:
        user = request(MM_BASE, _mm_context(), "POST", "/users", {
            "username": username, "email": email, "password": password, "email_verified": True,
        }, admin_token)[0]
    if not isinstance(user, dict) or not isinstance(user.get("id"), str):
        raise RuntimeError("Mattermost user bootstrap failed")
    return user


def bootstrap_mattermost() -> None:
    admin, admin_token = login("admin@clinical.invalid", (SEED / "admin_password").read_text().strip())
    actor = ensure_user("clinicalactor", "actor@clinical.invalid", (SEED / "actor_password").read_text().strip(), admin_token)
    denied = ensure_user("clinicaldenied", "denied@clinical.invalid", (SEED / "denied_password").read_text().strip(), admin_token)
    bot = optional_get("/users/username/clinicalbot", admin_token)
    if bot is None:
        created = request(MM_BASE, _mm_context(), "POST", "/bots", {
            "username": "clinicalbot", "display_name": "Synthetic clinical bot",
            "description": "Synthetic-only E2E", "owner_id": admin["id"],
        }, admin_token)[0]
        bot = optional_get("/users/" + created["user_id"], admin_token)
    if not isinstance(bot, dict) or not isinstance(bot.get("id"), str):
        raise RuntimeError("Mattermost bot bootstrap failed")
    actor_dm = request(MM_BASE, _mm_context(), "POST", "/channels/direct", [actor["id"], bot["id"]], admin_token)[0]
    denied_dm = request(MM_BASE, _mm_context(), "POST", "/channels/direct", [denied["id"], bot["id"]], admin_token)[0]
    group_channel = request(MM_BASE, _mm_context(), "POST", "/channels/group", [actor["id"], denied["id"], bot["id"]], admin_token)[0]
    tokens = request(MM_BASE, _mm_context(), "GET", f"/users/{bot['id']}/tokens", token=admin_token)[0]
    matching = [item for item in tokens if item.get("description") == "clinical-e2e"]
    if matching:
        raise RuntimeError("fresh E2E unexpectedly found an unrecoverable bot token")
    made = request(MM_BASE, _mm_context(), "POST", f"/users/{bot['id']}/tokens", {"description": "clinical-e2e"}, admin_token)[0]
    (INGRESS / "bot_token").write_text(made["token"], encoding="ascii")
    os.chown(INGRESS / "bot_token", 10007, 20005)
    os.chmod(INGRESS / "bot_token", 0o440)
    topology = {
        "actor_id": actor["id"], "denied_id": denied["id"], "bot_id": bot["id"],
        "actor_dm": actor_dm["id"], "denied_dm": denied_dm["id"], "group_channel": group_channel["id"],
    }
    (STATE / "topology.json").write_text(json.dumps(topology, sort_keys=True), encoding="ascii")


def db() -> psycopg.Connection:
    password = os.environ["CLINICAL_HRH_DB_PASSWORD"]
    return psycopg.connect(f"postgresql://hrh:{password}@hrh-postgres:5432/hrh")


def seed_hrh() -> None:
    topology = json.loads((STATE / "topology.json").read_text())
    api_key = (SEED / "hrh_api_key").read_text().strip()
    with db() as connection, connection.cursor() as cursor:
        cursor.execute("INSERT INTO persons (id,first_name,last_name) VALUES (%s,%s,%s)", ("person-staff", "Synthetic", "Staff"))
        cursor.execute("INSERT INTO persons (id,first_name,last_name) VALUES (%s,%s,%s)", ("person-patient", "Synthetic", "Patient"))
        cursor.execute("INSERT INTO persons (id,first_name,last_name) VALUES (%s,%s,%s)", ("person-other", "Synthetic", "Control"))
        cursor.execute("INSERT INTO users (id,username,password,role,department,person_id) VALUES (%s,%s,%s,%s,%s,%s)",
                       ("staff-clinical", "syntheticstaff", "disabled", "hr", "clinical", "person-staff"))
        cursor.execute("INSERT INTO patients (id,person_id,status) VALUES (%s,%s,'active'),(%s,%s,'active')",
                       (PATIENT_ID, "person-patient", OTHER_PATIENT_ID, "person-other"))
        cursor.execute("INSERT INTO appointments (id,patient_id,date,time,duration,type,status) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                       ("appointment_synth_01", PATIENT_ID, "2099-01-01", "09:30", 30, "synthetic", "scheduled"))
        cursor.execute("INSERT INTO api_keys (id,user_id,name,key_hash,prefix,scopes) VALUES (%s,%s,%s,%s,%s,%s)",
                       ("key-clinical", "staff-clinical", "clinical-e2e", hashlib.sha256(api_key.encode()).hexdigest(), api_key[:12], "restricted-hermes:clinical-read"))
        cursor.execute("INSERT INTO restricted_hermes_actor_bindings (id,api_key_id,mattermost_actor_id,integration_id,clinical_policy_id,staff_user_id,active) VALUES (%s,%s,%s,%s,%s,%s,true)",
                       ("binding-clinical", "key-clinical", topology["actor_id"], INTEGRATION_ID, CLINICAL_POLICY_ID, "staff-clinical"))
        cursor.execute("INSERT INTO user_permission_overrides (id,user_id,permission) VALUES (%s,%s,%s),(%s,%s,%s)",
                       ("perm-patient", "staff-clinical", "patients_view", "perm-appointment", "staff-clinical", "appointments_view"))


def policy_private() -> Ed25519PrivateKey:
    seeded = SEED / "policy-private.pem"
    if seeded.exists():
        return serialization.load_pem_private_key(seeded.read_bytes(), password=None)
    path = STATE / "policy-private.pem"
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    private = Ed25519PrivateKey.generate()
    path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return private


def verify_policy_pair(directory: Path, public_key: Any, *, raw: bytes | None = None) -> str:
    raw = (directory / "policy.json").read_bytes() if raw is None else raw
    try:
        signature = base64.b64decode((directory / "policy.sig").read_bytes(), validate=True)
        public_key.verify(signature, raw)
    except Exception as exc:
        raise RuntimeError("policy/signature mismatch") from exc
    return hashlib.sha256(raw).hexdigest()


def install_policy_pair(
    directory: Path,
    raw: bytes,
    signature: bytes,
    public_key: Any,
    *,
    owner: tuple[int, int] | None = None,
    fail_at: str | None = None,
) -> str:
    replacements = {"policy.json": raw, "policy.sig": signature}
    for name, payload in replacements.items():
        temporary = directory / (name + ".new")
        if temporary.exists():
            os.chmod(temporary, 0o600)
            temporary.unlink()
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if owner is not None:
            os.chown(temporary, *owner)
        os.chmod(temporary, 0o440)
    if fail_at == "before-signature":
        raise RuntimeError("injected failure before signature replace")
    if os.name == "nt" and (directory / "policy.sig").exists():
        os.chmod(directory / "policy.sig", 0o600)
    os.replace(directory / "policy.sig.new", directory / "policy.sig")
    if fail_at == "before-policy":
        raise RuntimeError("injected failure before policy replace")
    if os.name == "nt" and (directory / "policy.json").exists():
        os.chmod(directory / "policy.json", 0o600)
    os.replace(directory / "policy.json.new", directory / "policy.json")
    os.chmod(directory / "policy.sig", 0o440)
    os.chmod(directory / "policy.json", 0o440)
    if hasattr(os, "O_DIRECTORY"):
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    return verify_policy_pair(directory, public_key)


def activate_policy(epoch: str = "clinical-e1", validity_seconds: int = 3600) -> None:
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", epoch):
        raise RuntimeError("invalid synthetic policy epoch")
    if not -3600 <= validity_seconds <= 86400:
        raise RuntimeError("invalid synthetic policy lifetime")
    topology = json.loads((STATE / "topology.json").read_text())
    now = datetime.now(UTC).replace(microsecond=0)
    value = {
        "schema_version": "restricted-mattermost-ingress-policy.v1", "policy_epoch": epoch,
        "inference_policy_epoch": epoch, "inference_policy_digest": "a" * 64,
        "tenant_id": "clinicaltenant", "origin": "https://mattermost:8065", "team_id": "not-used-clinical",
        "allowed_channel_ids": [topology["actor_dm"]], "allowed_user_ids": [topology["actor_id"]],
        "bot_user_id": topology["bot_id"], "bot_username": "clinicalbot", "allowed_modality": "text",
        "dms_allowed": False, "files_allowed": False, "delivery_mode": "thread-only", "initiation_mode": "explicit-mention",
        "max_message_utf8_bytes": 4096, "not_before": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=validity_seconds)).isoformat().replace("+00:00", "Z"), "clock_skew_seconds": 30,
        "websocket_timeout_seconds": 10, "rest_timeout_seconds": 10, "uds_timeout_seconds": 15,
        "conversation_deadline_seconds": 15, "outbox_key_fingerprint": key_fingerprint((INGRESS / "outbox.key").read_bytes()),
        "outbox_payload_retention_seconds": 3600, "outbox_payload_capacity": 100, "outbox_tombstone_capacity": 100,
        "outbox_scan_limit": 20, "outbox_scan_interval_seconds": 1,
        "clinical_bindings": [{"channel_id": topology["actor_dm"], "actor_id": topology["actor_id"]}],
        "clinical_integration_id": INTEGRATION_ID, "clinical_policy_id": CLINICAL_POLICY_ID,
        "clinical_query_socket_path": "/run/restricted-clinical/query.sock", "clinical_timezone": "America/New_York",
    }
    raw = jcs_bytes(value)
    private = policy_private()
    install_policy_pair(
        INGRESS,
        raw,
        base64.b64encode(private.sign(raw)),
        private.public_key(),
        owner=(10007, 20005),
        fail_at=os.environ.get("CLINICAL_POLICY_INSTALL_FAIL_AT"),
    )
    _copy(SEED / "ca.crt", INGRESS / "ca.crt", uid=10007, gid=20005, mode=0o444)
    (STATE / "policy-public").write_text(base64.b64encode(private.public_key().public_bytes_raw()).decode(), encoding="ascii")


def policy_digest() -> str:
    return verify_policy_pair(INGRESS, policy_private().public_key())


def policy_live() -> str:
    """Verify the signed policy and its current validity window."""
    raw = (INGRESS / "policy.json").read_bytes()
    digest = verify_policy_pair(INGRESS, policy_private().public_key(), raw=raw)
    values = load_closed_json(raw)
    if not isinstance(values, dict):
        raise RuntimeError("policy is not an object")
    MattermostPolicy(values, digest).validate()
    return digest


def initialize_outbox() -> None:
    if OUTBOX.exists():
        os.chmod(OUTBOX, 0o700)
    store = MattermostOutbox.initialize(OUTBOX, INGRESS / "outbox.key", expected_fingerprint=key_fingerprint((INGRESS / "outbox.key").read_bytes()))
    store.close()
    for path in (OUTBOX, *OUTBOX.iterdir()):
        os.chown(path, 10007, 20005)
        os.chmod(path, 0o700 if path == OUTBOX else 0o600)


def send_post(actor: str, channel: str, patient_id: str, label: str) -> None:
    topology = json.loads((STATE / "topology.json").read_text())
    email = "actor@clinical.invalid" if actor == "actor" else "denied@clinical.invalid"
    password = (SEED / ("actor_password" if actor == "actor" else "denied_password")).read_text().strip()
    user, token = login(email, password)
    channel_id = topology[channel]
    root = request(MM_BASE, _mm_context(), "POST", "/posts", {
        "channel_id": channel_id, "message": f"@clinicalbot next-appointment {patient_id}",
    }, token)[0]
    channel_record = request(MM_BASE, _mm_context(), "GET", f"/channels/{channel_id}", token=token)[0]
    source_shape = {
        "keys": sorted(root), "type": root.get("type"), "root_empty": root.get("root_id") == "",
        "actor_match": root.get("user_id") == user.get("id"), "channel_match": root.get("channel_id") == channel_id,
        "file_count": len(root.get("file_ids", [])), "props_keys": sorted(root.get("props", {})),
        "edit_at": root.get("edit_at"), "delete_at": root.get("delete_at"), "metadata_keys": sorted(root.get("metadata", {})),
        "metadata_truthy": bool(root.get("metadata")), "channel_type": channel_record.get("type"),
    }
    (STATE / f"post-{label}.json").write_text(json.dumps({"actor": actor, "channel": channel, "root": root["id"], "shape": source_shape}), encoding="ascii")


def expect_post(label: str, *, expect_reply: bool) -> None:
    saved = json.loads((STATE / f"post-{label}.json").read_text())
    topology = json.loads((STATE / "topology.json").read_text())
    email = "actor@clinical.invalid" if saved["actor"] == "actor" else "denied@clinical.invalid"
    password = (SEED / ("actor_password" if saved["actor"] == "actor" else "denied_password")).read_text().strip()
    _user, token = login(email, password)
    channel_id = topology[saved["channel"]]
    deadline = time.monotonic() + (30 if expect_reply else 6)
    responses: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        posts = request(MM_BASE, _mm_context(), "GET", f"/channels/{channel_id}/posts?per_page=100", token=token)[0]
        responses = [
            p for p in posts.get("posts", {}).values()
            if p.get("root_id") == saved["root"] and p.get("user_id") == topology["bot_id"]
        ]
        if responses:
            break
        time.sleep(0.25)
    response = responses[0] if len(responses) == 1 else None
    saved["post_count"] = len(responses)
    (STATE / f"post-{label}.json").write_text(json.dumps(saved), encoding="ascii")
    if expect_reply:
        expected = "Next appointment: 2099-01-01 at 09:30 America/New_York (scheduled, 30 minutes)."
        if len(responses) != 1 or not response or response.get("message") != expected or set(response) < {"id", "channel_id", "root_id", "message"}:
            raise RuntimeError("minimal deterministic clinical response missing; source_shape=" + json.dumps(saved["shape"], sort_keys=True))
    elif responses:
        raise RuntimeError("denied clinical scenario disclosed a response")


def post_count(label: str) -> int:
    saved = json.loads((STATE / f"post-{label}.json").read_text())
    return int(saved.get("post_count", -1))


def _uds_exchange(body: dict[str, Any], endpoint: str, *, uid: int, gid: int, groups: list[int]) -> tuple[int, dict[str, Any]]:
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            os.setgroups(groups)
            os.setgid(gid)
            os.setuid(uid)
            raw = jcs_bytes(body)
            request_bytes = (
                f"POST {endpoint} HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw
            )
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(15)
            client.connect("/run/restricted-clinical/query.sock")
            client.sendall(request_bytes)
            chunks = []
            while True:
                chunk = client.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
            os.write(write_fd, b"".join(chunks))
            os._exit(0)
        except Exception as exc:
            os.write(write_fd, ("ERROR:" + type(exc).__name__).encode("ascii"))
            os._exit(1)
    os.close(write_fd)
    raw_response = b""
    while True:
        chunk = os.read(read_fd, 8192)
        if not chunk:
            break
        raw_response += chunk
    _, status = os.waitpid(pid, 0)
    os.close(read_fd)
    if os.waitstatus_to_exitcode(status) != 0:
        return 0, {"error": raw_response.decode("ascii", "replace")}
    head, raw_body = raw_response.split(b"\r\n\r\n", 1)
    return int(head.split(b" ", 2)[1]), json.loads(raw_body)


def uds_controls() -> None:
    topology = json.loads((STATE / "topology.json").read_text())
    policy = json.loads((INGRESS / "policy.json").read_text())
    base = {
        "mattermostActorId": topology["actor_id"], "patientId": PATIENT_ID,
        "requestId": "probe_request_01", "integrationId": INTEGRATION_ID,
        "clinicalPolicyId": CLINICAL_POLICY_ID, "policyEpoch": policy["policy_epoch"],
        "policyDigest": hashlib.sha256(jcs_bytes(policy)).hexdigest(),
    }
    status, result = _uds_exchange(base, "/v1/clinical/query", uid=10007, gid=20005, groups=[20006])
    if status != 200 or not isinstance(result.get("responseDigest"), str):
        raise RuntimeError("production adapter query control failed")
    delivery = {**base, "responseDigest": result["responseDigest"]}
    swapped = {**delivery, "responseDigest": "f" * 64}
    patient_cross = {**delivery, "patientId": OTHER_PATIENT_ID}
    for candidate in (swapped, patient_cross):
        denied, _ = _uds_exchange(candidate, "/v1/clinical/reauthorize-delivery", uid=10007, gid=20005, groups=[20006])
        if denied == 200:
            raise RuntimeError("swapped digest/patient control was authorized")
    denied, detail = _uds_exchange(base, "/v1/clinical/query", uid=10009, gid=10009, groups=[])
    if denied != 0 or "PermissionError" not in detail.get("error", ""):
        raise RuntimeError("unrelated UID reached the clinical socket")


def hrh_route_control() -> None:
    topology = json.loads((STATE / "topology.json").read_text())
    policy = json.loads((INGRESS / "policy.json").read_text())
    body = {
        "mattermostActorId": topology["actor_id"], "patientId": PATIENT_ID,
        "requestId": "route_request_01", "integrationId": INTEGRATION_ID,
        "clinicalPolicyId": CLINICAL_POLICY_ID, "policyEpoch": policy["policy_epoch"],
        "policyDigest": hashlib.sha256(jcs_bytes(policy)).hexdigest(),
    }
    try:
        result, _headers = request(HRH_BASE, _hrh_context(), "POST", "/api/restricted-hermes/clinical/next-appointment", body, (SEED / "hrh_api_key").read_text().strip())
    except ApiError as exc:
        raise RuntimeError(f"HRH production route denied status={exc.status} code={exc.code} message={exc.message}") from None
    if set(result) != {"clinicTimezone", "appointment", "responseDigest"}:
        raise RuntimeError("HRH production route returned a widened response")


def mutate(name: str) -> None:
    with db() as connection, connection.cursor() as cursor:
        if name == "reset":
            topology = json.loads((STATE / "topology.json").read_text())
            cursor.execute("""INSERT INTO restricted_hermes_actor_bindings (id,api_key_id,mattermost_actor_id,integration_id,clinical_policy_id,staff_user_id,active)
                VALUES ('binding-clinical','key-clinical',%s,%s,%s,'staff-clinical',true)
                ON CONFLICT (api_key_id,mattermost_actor_id) DO UPDATE SET active=true,integration_id=EXCLUDED.integration_id,clinical_policy_id=EXCLUDED.clinical_policy_id""",
                (topology["actor_id"], INTEGRATION_ID, CLINICAL_POLICY_ID))
            cursor.execute("DELETE FROM user_permission_overrides")
            cursor.execute("INSERT INTO user_permission_overrides (id,user_id,permission) VALUES ('perm-patient','staff-clinical','patients_view'),('perm-appointment','staff-clinical','appointments_view')")
        elif name == "unbound":
            cursor.execute("DELETE FROM restricted_hermes_actor_bindings")
        elif name == "disabled":
            cursor.execute("UPDATE restricted_hermes_actor_bindings SET active=false")
        elif name == "missing-patients":
            cursor.execute("DELETE FROM user_permission_overrides WHERE permission='patients_view'")
        elif name == "missing-appointments":
            cursor.execute("DELETE FROM user_permission_overrides WHERE permission='appointments_view'")
        elif name == "revoke-on-finalize":
            cursor.execute("""CREATE OR REPLACE FUNCTION clinical_e2e_revoke() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE restricted_hermes_actor_bindings SET active=false; RETURN NEW; END $$""")
            cursor.execute("""CREATE TRIGGER clinical_e2e_revoke AFTER UPDATE OF response_digest ON restricted_hermes_clinical_read_grants FOR EACH ROW WHEN (NEW.response_digest IS NOT NULL) EXECUTE FUNCTION clinical_e2e_revoke()""")
        elif name == "drop-revoke-trigger":
            cursor.execute("DROP TRIGGER IF EXISTS clinical_e2e_revoke ON restricted_hermes_clinical_read_grants")
            cursor.execute("DROP FUNCTION IF EXISTS clinical_e2e_revoke()")
        elif name == "crash-delay":
            cursor.execute("""CREATE OR REPLACE FUNCTION clinical_e2e_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='restricted_hermes_delivery_reauthorized' THEN PERFORM pg_sleep(20); END IF; RETURN NEW; END $$""")
            cursor.execute("CREATE TRIGGER clinical_e2e_delay BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION clinical_e2e_delay()")
        elif name == "drop-crash-delay":
            cursor.execute("DROP TRIGGER IF EXISTS clinical_e2e_delay ON audit_logs")
            cursor.execute("DROP FUNCTION IF EXISTS clinical_e2e_delay()")
        else:
            raise RuntimeError("unknown clinical mutation")


def grant_count() -> int:
    with db() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM restricted_hermes_clinical_read_grants WHERE response_digest IS NOT NULL")
        return int(cursor.fetchone()[0])


def clinical_db_summary() -> dict[str, Any]:
    with db() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM restricted_hermes_clinical_read_grants WHERE response_digest IS NOT NULL")
        grants = int(cursor.fetchone()[0])
        cursor.execute("SELECT active FROM restricted_hermes_actor_bindings WHERE id='binding-clinical'")
        binding = cursor.fetchone()
        cursor.execute("SELECT action, count(*) FROM audit_logs WHERE action LIKE 'restricted_hermes_%' GROUP BY action")
        audits = {action: int(count) for action, count in cursor.fetchall()}
    return {"grants": grants, "binding_active": bool(binding and binding[0]), "audits": audits}


def grant_evidence(label: str) -> dict[str, Any]:
    saved = json.loads((STATE / f"post-{label}.json").read_text())
    topology = json.loads((STATE / "topology.json").read_text())
    request_id = request_identity(
        "clinicaltenant", "https://mattermost:8065", topology[saved["channel"]], saved["root"]
    )
    with db() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT response_digest FROM restricted_hermes_clinical_read_grants WHERE request_id=%s",
            (request_id,),
        )
        row = cursor.fetchone()
        cursor.execute(
            "SELECT action, count(*) FROM audit_logs WHERE request_id=%s AND action LIKE %s GROUP BY action",
            (request_id, "restricted_hermes_%"),
        )
        audits = {action: int(count) for action, count in cursor.fetchall()}
    return {"response_digest": row[0] if row else None, "audits": audits}


def outbox_summary() -> dict[str, int]:
    with sqlite3.connect(OUTBOX / "mattermost-outbox.sqlite3") as connection:
        rows = connection.execute("SELECT state, COALESCE(reason,''), count(*) FROM records GROUP BY state, reason").fetchall()
    return {f"{state}:{reason}": count for state, reason, count in rows}


def main() -> None:
    command = sys.argv[1]
    if command == "seed-volumes":
        seed_volumes()
    elif command == "wait-mm":
        wait_https(MM_BASE, _mm_context(), "/system/ping")
    elif command == "wait-hrh":
        wait_https(HRH_BASE, _hrh_context(), "/api/health")
    elif command == "bootstrap-mm":
        bootstrap_mattermost()
    elif command == "seed-hrh":
        seed_hrh()
    elif command == "policy":
        activate_policy(
            sys.argv[2] if len(sys.argv) > 2 else "clinical-e1",
            int(sys.argv[3]) if len(sys.argv) > 3 else 3600,
        )
    elif command == "policy-digest":
        print(policy_digest())
    elif command == "policy-verify":
        print(policy_digest())
    elif command == "policy-live":
        print(policy_live())
    elif command == "public-key":
        print((STATE / "policy-public").read_text())
    elif command == "outbox-init":
        initialize_outbox()
    elif command == "send":
        send_post(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif command == "expect":
        expect_post(sys.argv[2], expect_reply=sys.argv[3] == "reply")
    elif command == "uds-controls":
        uds_controls()
    elif command == "hrh-route-control":
        hrh_route_control()
    elif command == "mutate":
        mutate(sys.argv[2])
    elif command == "grant-count":
        print(grant_count())
    elif command == "clinical-db-summary":
        print(json.dumps(clinical_db_summary(), sort_keys=True))
    elif command == "grant-evidence":
        print(json.dumps(grant_evidence(sys.argv[2]), sort_keys=True))
    elif command == "post-count":
        print(post_count(sys.argv[2]))
    elif command == "outbox-summary":
        print(json.dumps(outbox_summary(), sort_keys=True))
    else:
        raise RuntimeError("unknown clinical E2E control command")


if __name__ == "__main__":
    main()
