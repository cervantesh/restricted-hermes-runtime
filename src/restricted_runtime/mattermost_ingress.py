"""Standalone restricted Mattermost edge; no normal Hermes runtime is imported."""
from __future__ import annotations

import http.client
import logging
import re
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

from .contracts import ContractError, jcs_bytes, load_closed_json
from .mattermost_policy import MAX_EVENT_BYTES, MattermostPolicy

_MAX_HTTP_BYTES = 1_048_576
_POST_FIELDS = {"id", "root_id", "channel_id", "user_id", "message", "type", "file_ids", "edit_at", "delete_at"}
_NAMESPACE = uuid.UUID("024af157-bd86-4bcc-82bf-92890130c620")


def conversation_identity(tenant: str, origin: str, channel_id: str, root_id: str) -> str:
    return "mmc_" + uuid.uuid5(_NAMESPACE, "\x00".join((tenant, origin, channel_id, root_id))).hex


def request_identity(tenant: str, origin: str, channel_id: str, post_id: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, "\x00".join(("post", tenant, origin, channel_id, post_id))))


@dataclass(frozen=True)
class MattermostEvent:
    post: dict[str, Any]
    channel_type: str

    @classmethod
    def parse(cls, raw: bytes, *, max_bytes: int = MAX_EVENT_BYTES) -> "MattermostEvent":
        if not raw or len(raw) > max_bytes:
            raise ContractError("Mattermost event size rejected")
        value = load_closed_json(raw)
        if not isinstance(value, dict) or value.get("event") != "posted" or not isinstance(value.get("data"), dict):
            raise ContractError("Mattermost event rejected")
        data = value["data"]
        if not isinstance(data.get("post"), str) or not isinstance(data.get("channel_type"), str):
            raise ContractError("Mattermost event rejected")
        post = load_closed_json(data["post"])
        if not isinstance(post, dict) or not _POST_FIELDS <= set(post):
            raise ContractError("Mattermost post rejected")
        return cls(post, data["channel_type"])


class MattermostApi(Protocol):
    def get_me(self) -> dict[str, Any]: ...
    def get_channel(self, channel_id: str) -> dict[str, Any]: ...
    def get_post(self, post_id: str) -> dict[str, Any]: ...
    def create_post(self, body: dict[str, Any]) -> dict[str, Any]: ...


class ConversationApi(Protocol):
    def ready(self) -> dict[str, Any]: ...
    def submit(self, *, conversation_id: str, client_request_id: str, message: str) -> dict[str, Any]: ...


def _ordinary(post: dict[str, Any], *, policy: MattermostPolicy, require_mention: bool) -> bool:
    try:
        if not _POST_FIELDS <= set(post):
            return False
        message = post["message"]
        if (
            not all(isinstance(post[name], str) for name in ("id", "root_id", "channel_id", "user_id", "message", "type"))
            or not post["id"] or post["type"] != "" or post["user_id"] == policy.values["bot_user_id"]
            or post["user_id"] not in policy.values["allowed_user_ids"]
            or post["channel_id"] not in policy.values["allowed_channel_ids"]
            or not isinstance(post["file_ids"], list) or post["file_ids"]
            or post["edit_at"] != 0 or post["delete_at"] != 0
            or not message or len(message.encode("utf-8")) > policy.values["max_message_utf8_bytes"]
        ):
            return False
        if require_mention:
            username = re.escape(policy.values["bot_username"])
            return re.search(rf"(?<![A-Za-z0-9._-])@{username}(?![A-Za-z0-9._-])", message) is not None
        return True
    except (KeyError, TypeError, UnicodeError):
        return False


class Ingress:
    """Validate fresh Mattermost state before a single restricted turn and reply attempt."""
    def __init__(self, policy: MattermostPolicy, rest: MattermostApi, conversation: ConversationApi):
        policy.validate()
        self.policy, self.rest, self.conversation = policy, rest, conversation
        self._authenticated = False
        self._claims: set[str] = set()
        self._claim_lock = threading.Lock()

    def preflight(self) -> None:
        readiness = self.conversation.ready()
        expected = {
            "schema_version": "restricted-conversation-readiness.v1", "status": "ready",
            "policy_epoch": self.policy.values["inference_policy_epoch"],
            "policy_digest": self.policy.values["inference_policy_digest"],
            "classification": "PHI", "system_instruction_version": "restricted-phi-system.v1",
            "allowed_modalities": ["text"], "tools_allowed": False, "fallbacks": [],
            "max_provider_attempts": 1, "streaming": False, "max_output_tokens": 4096,
            "max_canonical_input_utf8_bytes": 131072,
            "response_profile": "restricted-local-text-response.v1",
        }
        if readiness != expected:
            raise ContractError("restricted conversation readiness binding rejected")
        me = self.rest.get_me()
        if not isinstance(me, dict) or me.get("id") != self.policy.values["bot_user_id"] or me.get("username") != self.policy.values["bot_username"]:
            raise ContractError("Mattermost bot identity rejected")
        for channel_id in self.policy.values["allowed_channel_ids"]:
            self._private_channel(channel_id)

    def mark_authenticated(self) -> None:
        self._authenticated = True

    def _private_channel(self, channel_id: str) -> dict[str, Any]:
        channel = self.rest.get_channel(channel_id)
        if (
            not isinstance(channel, dict) or channel.get("id") != channel_id
            or channel.get("team_id") != self.policy.values["team_id"] or channel.get("type") != "P"
            or channel_id not in self.policy.values["allowed_channel_ids"]
        ):
            raise ContractError("Mattermost private channel binding rejected")
        return channel

    def _validated_root(self, post: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        root_id = post["root_id"] or post["id"]
        root = self.rest.get_post(root_id)
        if (
            not _ordinary(root, policy=self.policy, require_mention=True)
            or root.get("id") != root_id or root.get("root_id") not in {"", root_id}
            or root.get("channel_id") != post["channel_id"]
        ):
            raise ContractError("Mattermost root binding rejected")
        return root_id, root

    def handle(self, event: MattermostEvent) -> None:
        try:
            if not self._authenticated or event.channel_type != "P":
                return
            post = event.post
            if not _ordinary(post, policy=self.policy, require_mention=not bool(post.get("root_id"))):
                return
            self._private_channel(post["channel_id"])
            root_id, _ = self._validated_root(post)
            source_id = post["id"]
            with self._claim_lock:
                if source_id in self._claims:
                    return
                if len(self._claims) >= 100_000:
                    raise ContractError("Mattermost live claim capacity reached")
                self._claims.add(source_id)
            conversation_id = conversation_identity(
                self.policy.values["tenant_id"], self.policy.origin, post["channel_id"], root_id
            )
            result = self.conversation.submit(
                conversation_id=conversation_id,
                client_request_id=request_identity(
                    self.policy.values["tenant_id"], self.policy.origin, post["channel_id"], source_id
                ),
                message=post["message"],
            )
            if not isinstance(result, dict) or result.get("status") != "COMMITTED" or not isinstance(result.get("message"), str) or not result["message"]:
                raise ContractError("restricted conversation did not commit a response")
            pending = str(uuid.uuid5(_NAMESPACE, "delivery\x00" + source_id))
            outbound = {
                "channel_id": post["channel_id"], "root_id": root_id,
                "message": result["message"], "pending_post_id": pending,
            }
            delivered = self.rest.create_post(outbound)
            if (
                not isinstance(delivered, dict) or delivered.get("channel_id") != post["channel_id"]
                or delivered.get("root_id") != root_id or delivered.get("pending_post_id") != pending
            ):
                raise ContractError("Mattermost delivery binding rejected")
        except (ContractError, KeyError, OSError, TimeoutError, UnicodeError, ValueError):
            logging.getLogger("restricted_mattermost").warning("mattermost_event_outcome=rejected")


class MattermostRestClient:
    """One-origin REST transport with no proxy discovery or redirect handling."""
    def __init__(self, policy: MattermostPolicy, token: str, *, ca_path: Path | None = None):
        self.policy, self._token = policy, token
        split = urlsplit(policy.origin)
        self._host, self._port = split.hostname or "", split.port or 443
        self._context = ssl.create_default_context(cafile=str(ca_path) if ca_path else None)

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        if not path.startswith("/api/v4/") or "//" in path or "?" in path or "#" in path:
            raise ContractError("Mattermost REST path rejected")
        payload = None if body is None else jcs_bytes(body)
        connection = http.client.HTTPSConnection(
            self._host, self._port, timeout=self.policy.values["rest_timeout_seconds"], context=self._context
        )
        try:
            headers = {"Authorization": "Bearer " + self._token, "Accept": "application/json", "Connection": "close"}
            if payload is not None:
                headers.update({"Content-Type": "application/json", "Content-Length": str(len(payload))})
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            if response.status not in {200, 201} or response.getheader("Location") is not None:
                raise ContractError("Mattermost REST response rejected")
            raw = response.read(_MAX_HTTP_BYTES + 1)
            if len(raw) > _MAX_HTTP_BYTES or response.read(1):
                raise ContractError("Mattermost REST response oversized")
            if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise ContractError("Mattermost REST content type rejected")
            value = load_closed_json(raw)
            if not isinstance(value, dict):
                raise ContractError("Mattermost REST JSON rejected")
            return value
        except ContractError:
            raise
        except (OSError, http.client.HTTPException, TimeoutError) as exc:
            raise ContractError("Mattermost REST transport failed") from exc
        finally:
            connection.close()

    def get_me(self): return self._request("GET", "/api/v4/users/me")
    def get_channel(self, channel_id): return self._request("GET", "/api/v4/channels/" + quote(channel_id, safe=""))
    def get_post(self, post_id): return self._request("GET", "/api/v4/posts/" + quote(post_id, safe=""))
    def create_post(self, body): return self._request("POST", "/api/v4/posts", body)


class ConversationUdsClient:
    """Closed client for the existing production conversation.sock API."""
    def __init__(self, policy: MattermostPolicy, path: str = "/run/restricted-inference/conversation.sock"):
        if path != "/run/restricted-inference/conversation.sock":
            raise ContractError("conversation socket path rejected")
        self.policy, self.path = policy, path

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = b"" if body is None else jcs_bytes(body)
        deadline = time.monotonic() + self.policy.values["uds_timeout_seconds"]
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(min(5, max(0.001, deadline - time.monotonic())))
                client.connect(self.path)
                wire = method.encode() + b" " + path.encode() + b" HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
                client.sendall(wire)
                chunks, total = [], 0
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    client.settimeout(min(5, remaining))
                    chunk = client.recv(min(65536, _MAX_HTTP_BYTES + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > _MAX_HTTP_BYTES:
                        raise ContractError("conversation response oversized")
            head, raw = b"".join(chunks).split(b"\r\n\r\n", 1)
            if not head.startswith(b"HTTP/1.1 200 OK\r\n"):
                raise ContractError("conversation response rejected")
            value = load_closed_json(raw)
            if not isinstance(value, dict):
                raise ContractError("conversation response rejected")
            return value
        except ContractError:
            raise
        except (OSError, TimeoutError, ValueError) as exc:
            raise ContractError("conversation transport failed") from exc

    def ready(self): return self._request("GET", "/readyz")

    def submit(self, *, conversation_id: str, client_request_id: str, message: str):
        created = self._request("POST", "/v1/restricted/conversations/" + conversation_id)
        if created.get("conversation_id") != conversation_id or not isinstance(created.get("conversation_epoch"), str):
            raise ContractError("conversation creation response rejected")
        result = self._request(
            "POST", "/v1/restricted/conversations/" + conversation_id + "/turns",
            {"schema_version": "restricted-turn.v1", "client_request_id": client_request_id,
             "conversation_epoch": created["conversation_epoch"], "message": message},
        )
        if set(result) != {"schema_version", "turn_id", "conversation_epoch", "status", "message"}:
            raise ContractError("conversation turn response rejected")
        return result
