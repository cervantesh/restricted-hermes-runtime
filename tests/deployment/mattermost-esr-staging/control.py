"""HTTPS-only synthetic control plane for the exact Mattermost ESR harness."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


STATE = Path("/state")
INGRESS = Path("/ingress")
TLS = Path("/tls")
WITNESS = Path("/witness/counters.json")
BASE = "https://mattermost:8065/api/v4"
_NAMESPACE = uuid.UUID("024af157-bd86-4bcc-82bf-92890130c620")
_MISSING = object()


class ApiError(RuntimeError):
    def __init__(self, method: str, path: str, status: int):
        super().__init__(f"Mattermost HTTPS API rejected {method} {path}: {status}")
        self.status = status


def _atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, path)


def _secret(name: str) -> str:
    return (STATE / name).read_text(encoding="utf-8").strip()


def _context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(TLS / "ca.crt"))


def request(
    method: str,
    path: str,
    body: Any = _MISSING,
    token: str | None = None,
    *,
    content_type: str = "application/json",
) -> tuple[Any, dict[str, str]]:
    payload = None
    if body is not _MISSING:
        payload = body if isinstance(body, bytes) else json.dumps(body, separators=(",", ":")).encode()
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = content_type
    if token:
        headers["Authorization"] = "Bearer " + token
    operation = urllib.request.Request(BASE + path, data=payload, method=method, headers=headers)
    try:
        with urllib.request.urlopen(operation, context=_context(), timeout=15) as response:
            raw = response.read()
            value = json.loads(raw) if raw else {}
            return value, {key.lower(): item for key, item in response.headers.items()}
    except urllib.error.HTTPError as exc:
        exc.read()
        raise ApiError(method, path, exc.code) from None
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise RuntimeError(f"Mattermost HTTPS API unavailable for {method} {path}") from exc


def optional_get(path: str, token: str) -> Any | None:
    try:
        return request("GET", path, token=token)[0]
    except ApiError as exc:
        if exc.status == 404:
            return None
        raise


def login(email: str, password: str) -> tuple[dict[str, Any], str]:
    value, headers = request("POST", "/users/login", {"login_id": email, "password": password})
    token = headers.get("token")
    if not isinstance(value, dict) or not isinstance(token, str) or not token:
        raise RuntimeError("Mattermost HTTPS login returned no usable identity")
    return value, token


def _copy(source: Path, destination: Path, *, mode: int, uid: int, gid: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chmod(destination, mode)
    os.chown(destination, uid, gid)


def seed() -> None:
    marker = STATE / "seeded"
    if marker.exists() or any(STATE.iterdir()) or any(INGRESS.iterdir()) or any(TLS.iterdir()):
        raise RuntimeError("staging seed volumes are not empty")
    for name in ("admin_password", "actor_password", "denied_password", "run_salt", "wrong_token"):
        _copy(Path("/seed") / name, STATE / name, mode=0o600, uid=0, gid=0)
    _copy(Path("/seed/postgres_password"), Path("/postgres-secret/postgres_password"), mode=0o440, uid=999, gid=999)
    for name in ("ca.crt", "server-good.crt", "server-good.key", "server-wrong.crt", "server-wrong.key"):
        mode = 0o440 if name.endswith(".key") else 0o444
        _copy(Path("/seed") / name, TLS / name, mode=mode, uid=2000, gid=2000)
    _copy(TLS / "server-good.crt", TLS / "server.crt", mode=0o444, uid=2000, gid=2000)
    _copy(TLS / "server-good.key", TLS / "server.key", mode=0o440, uid=2000, gid=2000)
    _copy(Path("/seed/ca.crt"), INGRESS / "correct-ca.crt", mode=0o444, uid=10007, gid=20005)
    _copy(Path("/seed/ca.crt"), INGRESS / "ca.crt", mode=0o444, uid=10007, gid=20005)
    _copy(Path("/seed/wrong-ca.crt"), INGRESS / "wrong-ca.crt", mode=0o444, uid=10007, gid=20005)
    marker.write_text("seeded", encoding="ascii")
    os.chmod(marker, 0o600)


def wait_ready() -> None:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            value, _ = request("GET", "/system/ping")
            if isinstance(value, dict) and value.get("status") == "OK":
                return
        except (ApiError, RuntimeError):
            pass
        time.sleep(0.5)
    raise RuntimeError("Mattermost authenticated HTTPS readiness deadline exceeded")


def ensure_user(username: str, email: str, password: str, admin_token: str) -> dict[str, Any]:
    found = optional_get("/users/username/" + urllib.parse.quote(username, safe=""), admin_token)
    if found is None:
        found, _ = request(
            "POST",
            "/users",
            {"username": username, "email": email, "password": password, "email_verified": True},
            admin_token,
        )
    if not isinstance(found, dict) or found.get("username") != username or not isinstance(found.get("id"), str):
        raise RuntimeError("Mattermost user convergence failed")
    return found


def ensure_bot(admin: dict[str, Any], admin_token: str) -> dict[str, Any]:
    found = optional_get("/users/username/esrbot", admin_token)
    if found is None:
        bot, _ = request(
            "POST",
            "/bots",
            {
                "username": "esrbot",
                "display_name": "ESR staging bot",
                "description": "Synthetic exact-digest staging bot",
                "owner_id": admin["id"],
            },
            admin_token,
        )
        bot_id = bot.get("user_id") if isinstance(bot, dict) else None
        found = optional_get("/users/" + str(bot_id), admin_token) if isinstance(bot_id, str) else None
    if not isinstance(found, dict) or found.get("username") != "esrbot" or not isinstance(found.get("id"), str):
        raise RuntimeError("Mattermost bot convergence failed")
    bot_record = optional_get("/bots/" + found["id"], admin_token)
    if not isinstance(bot_record, dict) or bot_record.get("user_id") != found["id"]:
        raise RuntimeError("Mattermost bot identity is not a real bot account")
    return found


def ensure_team(admin_token: str) -> dict[str, Any]:
    team = optional_get("/teams/name/esrstaging", admin_token)
    if team is None:
        team, _ = request(
            "POST", "/teams", {"name": "esrstaging", "display_name": "ESR staging", "type": "O"}, admin_token
        )
    if not isinstance(team, dict) or team.get("name") != "esrstaging" or not isinstance(team.get("id"), str):
        raise RuntimeError("Mattermost team convergence failed")
    return team


def ensure_team_member(team_id: str, user_id: str, admin_token: str) -> None:
    path = f"/teams/{team_id}/members/{user_id}"
    if optional_get(path, admin_token) is None:
        request("POST", f"/teams/{team_id}/members", {"team_id": team_id, "user_id": user_id}, admin_token)
    if optional_get(path, admin_token) is None:
        raise RuntimeError("Mattermost team membership convergence failed")


def ensure_channel(name: str, channel_type: str, team_id: str, admin_token: str) -> dict[str, Any]:
    channel = optional_get(f"/teams/{team_id}/channels/name/{name}", admin_token)
    if channel is None:
        channel, _ = request(
            "POST",
            "/channels",
            {"team_id": team_id, "name": name, "display_name": name, "type": channel_type},
            admin_token,
        )
    if (
        not isinstance(channel, dict)
        or channel.get("name") != name
        or channel.get("type") != channel_type
        or channel.get("team_id") != team_id
        or not isinstance(channel.get("id"), str)
    ):
        raise RuntimeError("Mattermost channel convergence failed")
    return channel


def ensure_channel_member(channel_id: str, user_id: str, admin_token: str) -> None:
    path = f"/channels/{channel_id}/members/{user_id}"
    if optional_get(path, admin_token) is None:
        request("POST", f"/channels/{channel_id}/members", {"user_id": user_id}, admin_token)
    if optional_get(path, admin_token) is None:
        raise RuntimeError("Mattermost channel membership convergence failed")


def remove_channel_member(channel_id: str, user_id: str, admin_token: str) -> None:
    path = f"/channels/{channel_id}/members/{user_id}"
    if optional_get(path, admin_token) is not None:
        request("DELETE", path, token=admin_token)
    if optional_get(path, admin_token) is not None:
        raise RuntimeError("Mattermost temporary channel membership removal failed")


def _digest(value: str) -> str:
    return hashlib.sha256((_secret("run_salt") + "\x00" + value).encode()).hexdigest()


def _bot_memberships(bot_id: str, team_id: str, allowed_id: str, admin_token: str) -> dict[str, int]:
    channels, _ = request("GET", f"/users/{bot_id}/teams/{team_id}/channels", token=admin_token)
    if not isinstance(channels, list):
        raise RuntimeError("Mattermost bot membership enumeration failed")
    return {
        "allowed_private": sum(item.get("id") == allowed_id and item.get("type") == "P" for item in channels),
        "other_private": sum(item.get("id") != allowed_id and item.get("type") == "P" for item in channels),
        "public": sum(item.get("type") == "O" for item in channels),
        "direct_or_group": sum(item.get("type") in {"D", "G"} for item in channels),
    }


def bootstrap() -> None:
    wait_ready()
    admin, admin_token = login("admin@esr.invalid", _secret("admin_password"))
    actor = ensure_user("esractor", "actor@esr.invalid", _secret("actor_password"), admin_token)
    denied = ensure_user("esrdenied", "denied@esr.invalid", _secret("denied_password"), admin_token)
    bot = ensure_bot(admin, admin_token)
    team = ensure_team(admin_token)
    for user in (actor, denied, bot):
        ensure_team_member(team["id"], user["id"], admin_token)
    allowed = ensure_channel("esrprivate", "P", team["id"], admin_token)
    denied_private = ensure_channel("esrdeniedprivate", "P", team["id"], admin_token)
    public = ensure_channel("esrpublic", "O", team["id"], admin_token)
    for user in (actor, denied, bot):
        ensure_channel_member(allowed["id"], user["id"], admin_token)
    ensure_channel_member(denied_private["id"], actor["id"], admin_token)
    remove_channel_member(denied_private["id"], bot["id"], admin_token)
    remove_channel_member(public["id"], bot["id"], admin_token)

    topology = {
        "team_id": team["id"],
        "allowed_channel_id": allowed["id"],
        "denied_channel_id": denied_private["id"],
        "public_channel_id": public["id"],
        "actor_id": actor["id"],
        "denied_id": denied["id"],
        "bot_id": bot["id"],
    }
    topology_path = STATE / "topology.json"
    if topology_path.exists() and json.loads(topology_path.read_text(encoding="utf-8")) != topology:
        raise RuntimeError("Mattermost bootstrap changed stable topology IDs")
    _atomic_json(topology_path, topology)

    token_path = INGRESS / "bot_token"
    tokens, _ = request("GET", f"/users/{bot['id']}/tokens", token=admin_token)
    if not isinstance(tokens, list):
        raise RuntimeError("Mattermost bot token inventory rejected")
    matching = [item for item in tokens if isinstance(item, dict) and item.get("description") == "esr-staging"]
    if token_path.exists():
        me, _ = request("GET", "/users/me", token=token_path.read_text(encoding="utf-8").strip())
        if not isinstance(me, dict) or me.get("id") != bot["id"]:
            raise RuntimeError("Mattermost bot token is not usable")
    else:
        if matching:
            raise RuntimeError("Mattermost bootstrap cannot recover a pre-existing token secret")
        created, _ = request(
            "POST", f"/users/{bot['id']}/tokens", {"description": "esr-staging"}, admin_token
        )
        token = created.get("token") if isinstance(created, dict) else None
        if not isinstance(token, str) or not token:
            raise RuntimeError("Mattermost bot token creation failed")
        token_path.write_text(token, encoding="utf-8")
        os.chmod(token_path, 0o440)
        os.chown(token_path, 10007, 20005)
        tokens, _ = request("GET", f"/users/{bot['id']}/tokens", token=admin_token)
        matching = [item for item in tokens if isinstance(item, dict) and item.get("description") == "esr-staging"]
    if len(tokens) != 1 or len(matching) != 1:
        raise RuntimeError("Mattermost bootstrap did not converge to exactly one bot token")

    memberships = _bot_memberships(bot["id"], team["id"], allowed["id"], admin_token)
    if memberships["allowed_private"] != 1 or memberships["other_private"] != 0:
        raise RuntimeError("Mattermost bot has an unauthorized private-channel membership")
    receipt = {
        "ids": {name: _digest(value) for name, value in sorted(topology.items())},
        "bot_token_count": len(tokens),
        "bot_token_usable": True,
        "bot_memberships": memberships,
    }
    receipt_path = STATE / "bootstrap-receipt.json"
    if receipt_path.exists() and json.loads(receipt_path.read_text(encoding="utf-8")) != receipt:
        raise RuntimeError("Mattermost bootstrap receipt changed on a second invocation")
    _atomic_json(receipt_path, receipt)


def _policy_private() -> Ed25519PrivateKey:
    path = STATE / "policy-private"
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    private = Ed25519PrivateKey.generate()
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)
    return private


def activate_policy(origin: str, ca_mode: str, token_mode: str) -> None:
    topology = json.loads((STATE / "topology.json").read_text(encoding="utf-8"))
    now = datetime.now(UTC).replace(microsecond=0)
    value = {
        "schema_version": "restricted-mattermost-ingress-policy.v1",
        "policy_epoch": "esr-e1",
        "inference_policy_epoch": "esr-e1",
        "inference_policy_digest": "a" * 64,
        "tenant_id": "esrtenant",
        "origin": origin,
        "team_id": topology["team_id"],
        "allowed_channel_ids": [topology["allowed_channel_id"]],
        "allowed_user_ids": [topology["actor_id"]],
        "bot_user_id": topology["bot_id"],
        "bot_username": "esrbot",
        "allowed_modality": "text",
        "dms_allowed": False,
        "files_allowed": False,
        "delivery_mode": "thread-only",
        "initiation_mode": "explicit-mention",
        "max_message_utf8_bytes": 4096,
        "not_before": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "clock_skew_seconds": 30,
        "websocket_timeout_seconds": 10,
        "rest_timeout_seconds": 10,
        "uds_timeout_seconds": 20,
        "conversation_deadline_seconds": 15,
    }
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    private = _policy_private()
    (INGRESS / "policy.json").write_bytes(raw)
    (INGRESS / "policy.sig").write_text(base64.b64encode(private.sign(raw)).decode("ascii"), encoding="ascii")
    public = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
    (STATE / "policy-public").write_text(public, encoding="ascii")
    ca_source = INGRESS / ("correct-ca.crt" if ca_mode == "correct" else "wrong-ca.crt")
    shutil.copyfile(ca_source, INGRESS / "active-ca.crt")
    os.replace(INGRESS / "active-ca.crt", INGRESS / "ca.crt")
    if token_mode == "wrong":
        (INGRESS / "bot_token").write_text(_secret("wrong_token"), encoding="utf-8")
    elif token_mode == "correct":
        # The raw token is intentionally retained only in the ingress volume. Wrong-token
        # activation saves it in the controller volume for immediate restoration.
        backup = STATE / "bot-token-backup"
        if backup.exists():
            shutil.copyfile(backup, INGRESS / "bot_token")
        else:
            _, admin_token = login("admin@esr.invalid", _secret("admin_password"))
            topology = json.loads((STATE / "topology.json").read_text(encoding="utf-8"))
            tokens, _ = request("GET", f"/users/{topology['bot_id']}/tokens", token=admin_token)
            if not isinstance(tokens, list) or len(tokens) != 1:
                raise RuntimeError("Mattermost bot token inventory changed")
            shutil.copyfile(INGRESS / "bot_token", backup)
            os.chmod(backup, 0o600)
    else:
        raise RuntimeError("unknown token activation mode")
    for name, mode in (("policy.json", 0o440), ("policy.sig", 0o440), ("ca.crt", 0o444), ("bot_token", 0o440)):
        os.chmod(INGRESS / name, mode)
        os.chown(INGRESS / name, 10007, 20005)


def switch_tls(mode: str) -> None:
    if mode not in {"good", "wrong"}:
        raise RuntimeError("unknown TLS certificate mode")
    _copy(TLS / f"server-{mode}.crt", TLS / "server.crt", mode=0o444, uid=2000, gid=2000)
    _copy(TLS / f"server-{mode}.key", TLS / "server.key", mode=0o440, uid=2000, gid=2000)


def websocket_wrong_token() -> None:
    from websockets.sync.client import connect
    from websockets.exceptions import ConnectionClosed

    connection = connect(
        "wss://mattermost:8065/api/v4/websocket",
        ssl=_context(),
        proxy=None,
        open_timeout=10,
        close_timeout=10,
        compression=None,
    )

    def record(outcome: str) -> None:
        run = _load_run()
        run["wrong_token_challenge_evidence"] = outcome
        _save_run(run)

    try:
        connection.send(
            json.dumps(
                {
                    "seq": 1,
                    "action": "authentication_challenge",
                    "data": {"token": _secret("wrong_token")},
                },
                separators=(",", ":"),
            )
        )
        deadline = time.monotonic() + 10
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("Mattermost wrong-token WebSocket result deadline exceeded")
            try:
                raw = connection.recv(timeout=remaining)
            except ConnectionClosed as exc:
                close_reasons = " ".join(
                    str(getattr(frame, "reason", ""))
                    for frame in (getattr(exc, "rcvd", None), getattr(exc, "sent", None))
                    if frame is not None
                ).lower()
                if any(marker in close_reasons for marker in ("auth", "token", "unauthor", "forbidden")):
                    record("websocket_authentication_close")
                    return
                try:
                    request("GET", "/users/me", token=_secret("wrong_token"))
                except ApiError as rejection:
                    if rejection.status == 401:
                        record("unframed_websocket_close_plus_rest_401")
                        return
                raise RuntimeError("Mattermost wrong-token WebSocket closed without an authentication rejection") from exc
            value = json.loads(raw)
            if isinstance(value, dict) and value.get("seq_reply") == 1:
                if value.get("status") == "OK":
                    raise RuntimeError("Mattermost real WebSocket accepted the wrong token")
                record("websocket_non_ok_response")
                return
    finally:
        connection.close()


def secret_scan(paths: list[str]) -> None:
    topology = _topology()
    needles = [
        _secret("admin_password").encode(),
        _secret("actor_password").encode(),
        _secret("denied_password").encode(),
        _secret("wrong_token").encode(),
        (STATE / "policy-private").read_bytes(),
        (TLS / "server-good.key").read_bytes(),
        (TLS / "server-wrong.key").read_bytes(),
        b"MM_ESR_SYNTHETIC_FILE_CANARY_5f3c",
        b"synthetic response",
        b"synthetic root",
        b"synthetic continuation",
    ]
    needles.extend(value.encode() for value in topology.values())
    for token_path in (INGRESS / "bot_token", STATE / "bot-token-backup"):
        if token_path.exists():
            needles.append(token_path.read_bytes().strip())
    for name in paths:
        path = Path(name).resolve()
        if Path("/seed") not in path.parents:
            raise RuntimeError("secret scan path escaped the staging evidence directory")
        raw = path.read_bytes()
        if any(needle and needle in raw for needle in needles):
            raise RuntimeError("staging log or evidence contains a prohibited secret, identifier, or content value")


def _topology() -> dict[str, str]:
    return json.loads((STATE / "topology.json").read_text(encoding="utf-8"))


def _admin() -> tuple[dict[str, Any], str]:
    return login("admin@esr.invalid", _secret("admin_password"))


def _witness() -> dict[str, Any]:
    return json.loads(WITNESS.read_text(encoding="utf-8"))


def _posts(channel_id: str, token: str) -> list[dict[str, Any]]:
    value, _ = request("GET", f"/channels/{channel_id}/posts?page=0&per_page=200", token=token)
    if not isinstance(value, dict) or not isinstance(value.get("posts"), dict):
        raise RuntimeError("Mattermost post inventory rejected")
    return list(value["posts"].values())


def _bot_posts(channel_id: str, bot_id: str, token: str, *, root_id: str | None = None) -> list[dict[str, Any]]:
    posts = [item for item in _posts(channel_id, token) if item.get("user_id") == bot_id]
    if root_id is not None:
        posts = [item for item in posts if item.get("root_id") == root_id]
    return posts


def assert_counts(turns: int, replies: int, *, root_id: str | None = None) -> None:
    topology = _topology()
    _, admin_token = _admin()
    actual_turns = _witness().get("turns")
    actual_replies = len(
        _bot_posts(topology["allowed_channel_id"], topology["bot_id"], admin_token, root_id=root_id)
    )
    if (actual_turns, actual_replies) != (turns, replies):
        raise RuntimeError("Mattermost staging counters do not match the closed scenario")


def wait_counts(turns: int, replies: int, *, root_id: str) -> list[dict[str, Any]]:
    deadline = time.monotonic() + 30
    topology = _topology()
    _, admin_token = _admin()
    while time.monotonic() < deadline:
        actual_turns = _witness().get("turns")
        posts = _bot_posts(topology["allowed_channel_id"], topology["bot_id"], admin_token, root_id=root_id)
        if actual_turns == turns and len(posts) == replies:
            return posts
        if isinstance(actual_turns, int) and (actual_turns > turns or len(posts) > replies):
            break
        time.sleep(0.2)
    raise RuntimeError("Mattermost staging effect deadline exceeded")


def quiet(turns: int, replies: int, *, root_id: str | None = None) -> None:
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        assert_counts(turns, replies, root_id=root_id)
        time.sleep(0.2)


def _create_post(token: str, channel_id: str, message: str, *, root_id: str = "", file_ids: list[str] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"channel_id": channel_id, "message": message}
    if root_id:
        body["root_id"] = root_id
    if file_ids:
        body["file_ids"] = file_ids
    value, _ = request("POST", "/posts", body, token)
    if not isinstance(value, dict) or not isinstance(value.get("id"), str):
        raise RuntimeError("Mattermost post creation rejected")
    return value


def _shape(value: dict[str, Any]) -> dict[str, str]:
    return {key: type(item).__name__ for key, item in sorted(value.items())}


def _load_run() -> dict[str, Any]:
    path = STATE / "run.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _save_run(value: dict[str, Any]) -> None:
    _atomic_json(STATE / "run.json", value)


def _save_shapes(value: dict[str, Any]) -> None:
    _atomic_json(STATE / "shape-manifest.json", value)


def pending_probe() -> None:
    topology = _topology()
    actor, actor_token = login("actor@esr.invalid", _secret("actor_password"))
    if actor.get("id") != topology["actor_id"]:
        raise RuntimeError("Mattermost pending probe actor identity changed")
    pending = str(uuid.uuid5(_NAMESPACE, "pending-probe\x00" + topology["allowed_channel_id"]))
    outbound = {
        "channel_id": topology["allowed_channel_id"],
        "message": "synthetic pending identifier probe",
        "pending_post_id": pending,
    }
    immediate, _ = request("POST", "/posts", outbound, actor_token)
    post_id = immediate.get("id") if isinstance(immediate, dict) else None
    if not isinstance(post_id, str) or not post_id:
        raise RuntimeError("Mattermost pending probe create response rejected")
    stored, _ = request("GET", f"/posts/{post_id}", token=actor_token)
    immediate_echo = immediate.get("pending_post_id") == pending
    stored_echo = isinstance(stored, dict) and stored.get("pending_post_id") == pending
    bindings = {
        "immediate_channel": immediate.get("channel_id") == topology["allowed_channel_id"],
        "immediate_root": immediate.get("root_id") == "",
        "stored_channel": isinstance(stored, dict) and stored.get("channel_id") == topology["allowed_channel_id"],
        "stored_root": isinstance(stored, dict) and stored.get("root_id") == "",
        "same_post": isinstance(stored, dict) and stored.get("id") == post_id,
    }
    if not all(bindings.values()) or not immediate_echo or stored_echo:
        safe = {"bindings": bindings, "immediate_echo": immediate_echo, "stored_echo": stored_echo}
        raise RuntimeError("Mattermost 11.7.10 pending probe behavior changed: " + json.dumps(safe, sort_keys=True))
    _save_shapes(
        {
            "pending_probe": {
                "request": _shape(outbound),
                "immediate_create_response": _shape(immediate),
                "stored_readback": _shape(stored),
                "bindings": bindings,
                "immediate_pending_post_id_echoed": immediate_echo,
                "stored_pending_post_id_echoed": stored_echo,
                "production_echo_requirement_accepts_immediate": immediate_echo,
            }
        }
    )


def effect_counters() -> None:
    topology = _topology()
    _, admin_token = _admin()
    value = {
        "turns": _witness().get("turns"),
        "allowed_replies": len(_bot_posts(topology["allowed_channel_id"], topology["bot_id"], admin_token)),
        "denied_replies": len(_bot_posts(topology["denied_channel_id"], topology["bot_id"], admin_token)),
    }
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _upload_file(token: str, channel_id: str) -> tuple[str, dict[str, Any]]:
    boundary = "mmesr-boundary"
    canary = b"MM_ESR_SYNTHETIC_FILE_CANARY_5f3c"
    segments = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"channel_id\"\r\n\r\n{channel_id}\r\n".encode(),
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"synthetic.txt\"\r\nContent-Type: text/plain\r\n\r\n".encode()
        + canary
        + b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ]
    value, _ = request(
        "POST",
        "/files",
        b"".join(segments),
        token,
        content_type=f"multipart/form-data; boundary={boundary}",
    )
    infos = value.get("file_infos") if isinstance(value, dict) else None
    if not isinstance(infos, list) or len(infos) != 1 or not isinstance(infos[0].get("id"), str):
        raise RuntimeError("Mattermost real file upload rejected")
    return infos[0]["id"], value


def scenario(name: str) -> None:
    topology = _topology()
    run = _load_run()
    actor, actor_token = login("actor@esr.invalid", _secret("actor_password"))
    denied, denied_token = login("denied@esr.invalid", _secret("denied_password"))
    admin, admin_token = _admin()
    if actor.get("id") != topology["actor_id"] or denied.get("id") != topology["denied_id"]:
        raise RuntimeError("Mattermost scenario actor identity changed")

    if name == "root":
        root = _create_post(actor_token, topology["allowed_channel_id"], "@esrbot synthetic root")
        replies = wait_counts(1, 1, root_id=root["id"])
        run.update(root_id=root["id"], root_digest=_digest(root["id"]), main_turns=1, main_replies=1)
        witness = _witness()
        if len(witness.get("conversation_ids", [])) != 1:
            raise RuntimeError("restricted conversation identity was not recorded")
        run["conversation_digest"] = _digest(witness["conversation_ids"][0])
        bindings = {
            "channel_id": replies[0].get("channel_id") == topology["allowed_channel_id"],
            "root_id": replies[0].get("root_id") == root["id"],
        }
        if not all(bindings.values()):
            raise RuntimeError("Mattermost stored reply bindings changed: " + json.dumps(bindings, sort_keys=True))
        shapes = json.loads((STATE / "shape-manifest.json").read_text(encoding="utf-8"))
        shapes.update({
            "root": _shape(root),
            "stored_reply_readback": _shape(replies[0]),
            "stored_reply_bindings": bindings,
            "stored_reply_pending_post_id_preserved": replies[0].get("pending_post_id")
            == str(uuid.uuid5(_NAMESPACE, "delivery\x00" + root["id"])),
        })
        _save_shapes(shapes)
    elif name == "continuation":
        root_id = run["root_id"]
        reply = _create_post(actor_token, topology["allowed_channel_id"], "synthetic continuation", root_id=root_id)
        wait_counts(2, 2, root_id=root_id)
        shapes = json.loads((STATE / "shape-manifest.json").read_text(encoding="utf-8"))
        shapes["reply"] = _shape(reply)
        _save_shapes(shapes)
        witness = _witness()
        if len(set(witness.get("conversation_ids", []))) != 1:
            raise RuntimeError("Mattermost continuation changed restricted conversation identity")
        run.update(main_turns=2, main_replies=2)
    elif name == "denied-user":
        _create_post(denied_token, topology["allowed_channel_id"], "@esrbot denied actor")
        quiet(2, 2, root_id=run["root_id"])
    elif name == "denied-channel":
        ensure_channel_member(topology["denied_channel_id"], topology["bot_id"], admin_token)
        try:
            _create_post(actor_token, topology["denied_channel_id"], "@esrbot denied private")
            quiet(2, 2, root_id=run["root_id"])
        finally:
            remove_channel_member(topology["denied_channel_id"], topology["bot_id"], admin_token)
    elif name == "public":
        ensure_channel_member(topology["public_channel_id"], topology["actor_id"], admin_token)
        ensure_channel_member(topology["public_channel_id"], topology["bot_id"], admin_token)
        try:
            _create_post(actor_token, topology["public_channel_id"], "@esrbot public denied")
            quiet(2, 2, root_id=run["root_id"])
        finally:
            remove_channel_member(topology["public_channel_id"], topology["bot_id"], admin_token)
    elif name in {"dm", "gm"}:
        users = [topology["actor_id"], topology["bot_id"]]
        path = "/channels/direct"
        if name == "gm":
            users.append(topology["denied_id"])
            path = "/channels/group"
        channel, _ = request("POST", path, users, admin_token)
        if not isinstance(channel, dict) or channel.get("type") != ("D" if name == "dm" else "G"):
            raise RuntimeError("Mattermost temporary direct/group channel rejected")
        _create_post(actor_token, channel["id"], "@esrbot direct denied")
        quiet(2, 2, root_id=run["root_id"])
        ephemeral = run.setdefault("ephemeral_direct_channel_digests", {})
        ephemeral[name] = _digest(channel["id"])
    elif name == "file":
        file_id, _ = _upload_file(actor_token, topology["allowed_channel_id"])
        post = _create_post(
            actor_token,
            topology["allowed_channel_id"],
            "@esrbot file denied",
            file_ids=[file_id],
        )
        quiet(2, 2, root_id=run["root_id"])
        shapes = json.loads((STATE / "shape-manifest.json").read_text(encoding="utf-8"))
        shapes["file_post"] = _shape(post)
        _save_shapes(shapes)
    elif name == "edited-and-unmentioned":
        _create_post(actor_token, topology["allowed_channel_id"], "synthetic root without mention")
        quiet(2, 2, root_id=run["root_id"])
        editable = _create_post(actor_token, topology["allowed_channel_id"], "synthetic edit base")
        request("PUT", f"/posts/{editable['id']}/patch", {"message": "@esrbot edited denied"}, actor_token)
        quiet(2, 2, root_id=run["root_id"])
    elif name == "removed-membership":
        remove_channel_member(topology["allowed_channel_id"], topology["bot_id"], admin_token)
        try:
            _create_post(actor_token, topology["allowed_channel_id"], "@esrbot removed membership")
            quiet(2, 2, root_id=run["root_id"])
        finally:
            ensure_channel_member(topology["allowed_channel_id"], topology["bot_id"], admin_token)
    elif name == "restart-reply":
        root_id = run["root_id"]
        root, _ = request("GET", f"/posts/{root_id}", token=admin_token)
        if not isinstance(root, dict) or root.get("channel_id") != topology["allowed_channel_id"]:
            raise RuntimeError("Mattermost recreation did not preserve the allowed root")
        _create_post(actor_token, topology["allowed_channel_id"], "synthetic after recreation", root_id=root_id)
        wait_counts(3, 3, root_id=root_id)
        witness = _witness()
        if len(set(witness.get("conversation_ids", []))) != 1:
            raise RuntimeError("Mattermost recreation changed restricted conversation identity")
        run.update(main_turns=3, main_replies=3, restart_preserved=True)
    elif name == "mutation-denied-channel":
        before_turns = int(_witness()["turns"])
        ensure_channel_member(topology["denied_channel_id"], topology["bot_id"], admin_token)
        try:
            post = _create_post(actor_token, topology["denied_channel_id"], "@esrbot mutation witness")
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                turns = int(_witness()["turns"])
                replies = len(_bot_posts(topology["denied_channel_id"], topology["bot_id"], admin_token, root_id=post["id"]))
                if turns == before_turns + 1 and replies == 1:
                    run["authorization_mutation_bites"] = True
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("directed channel-authorization mutation did not make the real-server negative fail")
        finally:
            remove_channel_member(topology["denied_channel_id"], topology["bot_id"], admin_token)
    else:
        raise RuntimeError("unknown staging scenario")
    _save_run(run)


def report() -> None:
    topology = _topology()
    _, admin_token = _admin()
    receipt = json.loads((STATE / "bootstrap-receipt.json").read_text(encoding="utf-8"))
    shapes = json.loads((STATE / "shape-manifest.json").read_text(encoding="utf-8"))
    run = _load_run()
    wrong_token_evidence = run.get("wrong_token_challenge_evidence")
    if wrong_token_evidence not in {
        "websocket_authentication_close",
        "unframed_websocket_close_plus_rest_401",
        "websocket_non_ok_response",
    }:
        raise RuntimeError("wrong-token authentication evidence missing")
    bindings = shapes.get("stored_reply_bindings")
    if not isinstance(bindings, dict) or set(bindings) != {"channel_id", "root_id"} or not all(bindings.values()):
        safe_bindings = bindings if isinstance(bindings, dict) else {"shape": False}
        raise RuntimeError("Mattermost stored reply bindings changed: " + json.dumps(safe_bindings, sort_keys=True))
    if shapes.get("stored_reply_pending_post_id_preserved") is not False:
        raise RuntimeError("Mattermost 11.7.10 pending_post_id behavior changed")
    pending = shapes.get("pending_probe")
    if (
        not isinstance(pending, dict)
        or pending.get("immediate_pending_post_id_echoed") is not True
        or pending.get("stored_pending_post_id_echoed") is not False
        or pending.get("production_echo_requirement_accepts_immediate") is not True
        or not all(pending.get("bindings", {}).values())
    ):
        raise RuntimeError("Mattermost pending probe evidence changed")
    memberships = _bot_memberships(topology["bot_id"], topology["team_id"], topology["allowed_channel_id"], admin_token)
    ephemeral = run.get("ephemeral_direct_channel_digests")
    if (
        memberships["other_private"] != 0
        or not isinstance(ephemeral, dict)
        or set(ephemeral) != {"dm", "gm"}
        or not all(isinstance(value, str) and len(value) == 64 for value in ephemeral.values())
    ):
        raise RuntimeError("ephemeral bot membership accounting changed")
    safe = {
        "bootstrap": receipt,
        "main_counters": {"turns": run.get("main_turns"), "replies": run.get("main_replies")},
        "root_digest": run.get("root_digest"),
        "conversation_digest": run.get("conversation_digest"),
        "restart_preserved": run.get("restart_preserved"),
        "authorization_mutation_bites": run.get("authorization_mutation_bites"),
        "wrong_token_challenge_evidence": wrong_token_evidence,
        "ephemeral_direct_channel_digests": ephemeral,
        "final_bot_memberships": memberships,
        "shape_manifest": shapes,
    }
    print(json.dumps(safe, sort_keys=True, separators=(",", ":")))


def main() -> None:
    command = sys.argv[1]
    if command == "seed":
        seed()
    elif command == "wait-ready":
        wait_ready()
    elif command == "bootstrap":
        bootstrap()
    elif command == "policy":
        activate_policy(sys.argv[2], sys.argv[3], sys.argv[4])
    elif command == "pending-probe":
        pending_probe()
    elif command == "effect-counters":
        effect_counters()
    elif command == "public-key":
        print((STATE / "policy-public").read_text(encoding="ascii").strip())
    elif command == "tls":
        switch_tls(sys.argv[2])
    elif command == "websocket-wrong-token":
        websocket_wrong_token()
    elif command == "assert-zero":
        assert_counts(0, 0)
    elif command == "scenario":
        scenario(sys.argv[2])
    elif command == "report":
        report()
    elif command == "secret-scan":
        secret_scan(sys.argv[2:])
    else:
        raise RuntimeError("unknown staging control command")


if __name__ == "__main__":
    main()
