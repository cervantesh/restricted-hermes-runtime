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
from .mattermost_outbox import DeliveryState, MattermostOutbox, OutboxRecord
from .mattermost_policy import MAX_EVENT_BYTES, MattermostPolicy

_MAX_HTTP_BYTES = 1_048_576
_POST_FIELDS = {"id", "root_id", "channel_id", "user_id", "message", "type", "file_ids", "edit_at", "delete_at"}
_POST_REQUIRED_FIELDS = _POST_FIELDS - {"file_ids"}
_UNSAFE_ATTACHMENT_SIGNAL = re.compile(r"attachment|file|image|media|upload", re.IGNORECASE)
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
        if not isinstance(post, dict) or not _POST_REQUIRED_FIELDS <= set(post):
            raise ContractError("Mattermost post rejected")
        post.setdefault("file_ids", [])
        return cls(post, data["channel_type"])


class MattermostApi(Protocol):
    def get_me(self, *, definitive: bool = False) -> dict[str, Any]: ...
    def get_channel(self, channel_id: str, *, definitive: bool = False) -> dict[str, Any]: ...
    def get_post(self, post_id: str, *, definitive: bool = False) -> dict[str, Any]: ...
    def get_channel_member(self, channel_id: str, user_id: str, *, definitive: bool = False) -> dict[str, Any]: ...
    def create_post(self, body: dict[str, Any]) -> dict[str, Any]: ...


class ConversationApi(Protocol):
    def ready(self) -> dict[str, Any]: ...
    def submit(self, *, conversation_id: str, client_request_id: str, message: str) -> dict[str, Any]: ...
    def create_conversation(self, *, conversation_id: str, deadline: float | None = None) -> dict[str, Any]: ...
    def submit_turn(self, *, conversation_id: str, conversation_epoch: str, client_request_id: str, message: str, deadline: float | None = None) -> dict[str, Any]: ...


class TransientMattermostError(ContractError):
    """A current REST transport/result cannot authorize a terminal transition."""


class DefinitiveMattermostError(ContractError):
    """An exact current source/destination authorization binding was rejected."""


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
            or bool(post.get("metadata")) or bool(post.get("props"))
            or any(name not in _POST_FIELDS and _UNSAFE_ATTACHMENT_SIGNAL.search(name) for name in post)
            or post["edit_at"] != 0 or post["delete_at"] != 0
            or not message.strip() or len(message.encode("utf-8")) > policy.values["max_message_utf8_bytes"]
        ):
            return False
        if require_mention:
            username = re.escape(policy.values["bot_username"])
            return re.search(rf"(?<![A-Za-z0-9._-])@{username}(?![A-Za-z0-9._-])", message) is not None
        return True
    except (KeyError, TypeError, UnicodeError):
        return False


class Ingress:
    """Reserve authenticated events; the sole executor owns UDS and REST effects."""
    def __init__(self, policy: MattermostPolicy, rest: MattermostApi, conversation: ConversationApi, outbox: MattermostOutbox):
        policy.validate()
        self.policy, self.rest, self.conversation, self.outbox = policy, rest, conversation, outbox
        self._authenticated = False
        self.executor = SerializedDeliveryExecutor(self)

    def preflight(self) -> None:
        self._readiness_binding()
        self._bot_identity()
        for channel_id in self.policy.values["allowed_channel_ids"]:
            self._private_channel(channel_id)
            self._member(channel_id, self.policy.values["bot_user_id"])
        self.outbox.stale_inflight_to_ambiguous()
        self.executor.drain()

    def _readiness_binding(self) -> None:
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

    def _bot_identity(self, *, definitive: bool = False) -> None:
        me = self.rest.get_me(definitive=definitive)
        if not isinstance(me, dict) or me.get("id") != self.policy.values["bot_user_id"] or me.get("username") != self.policy.values["bot_username"]:
            error = DefinitiveMattermostError if definitive else ContractError
            raise error("Mattermost bot identity rejected")

    def mark_authenticated(self) -> None:
        self._authenticated = True

    def _private_channel(self, channel_id: str, *, definitive: bool = False) -> dict[str, Any]:
        channel = self.rest.get_channel(channel_id, definitive=definitive)
        if (
            not isinstance(channel, dict) or channel.get("id") != channel_id
            or channel.get("team_id") != self.policy.values["team_id"] or channel.get("type") != "P"
            or channel_id not in self.policy.values["allowed_channel_ids"]
        ):
            error = DefinitiveMattermostError if definitive else ContractError
            raise error("Mattermost private channel binding rejected")
        return channel

    def _member(self, channel_id: str, user_id: str, *, definitive: bool = False) -> dict[str, Any]:
        member = self.rest.get_channel_member(channel_id, user_id, definitive=definitive)
        if not isinstance(member, dict) or member.get("channel_id") != channel_id or member.get("user_id") != user_id:
            error = DefinitiveMattermostError if definitive else ContractError
            raise error("Mattermost channel membership rejected")
        return member

    def _validated_root(self, post: dict[str, Any], *, definitive: bool = False) -> tuple[str, dict[str, Any]]:
        root_id = post["root_id"] or post["id"]
        root = self.rest.get_post(root_id, definitive=definitive)
        if isinstance(root, dict) and "file_ids" not in root:
            root = {**root, "file_ids": []}
        if (
            not _ordinary(root, policy=self.policy, require_mention=True)
            or root.get("id") != root_id or root.get("root_id") not in {"", root_id}
            or root.get("channel_id") != post["channel_id"]
        ):
            error = DefinitiveMattermostError if definitive else ContractError
            raise error("Mattermost root binding rejected")
        return root_id, root

    def _authorize_source(self, post: dict[str, Any], *, definitive: bool = False) -> str:
        self.policy.validate()
        if not _ordinary(post, policy=self.policy, require_mention=not bool(post.get("root_id"))):
            raise DefinitiveMattermostError("Mattermost source binding rejected")
        self._private_channel(post["channel_id"], definitive=definitive)
        self._member(post["channel_id"], post["user_id"], definitive=definitive)
        self._member(post["channel_id"], self.policy.values["bot_user_id"], definitive=definitive)
        root_id, _ = self._validated_root(post, definitive=definitive)
        return root_id

    def _envelope(self, post: dict[str, Any], root_id: str) -> dict[str, Any]:
        from datetime import datetime
        expires = int(datetime.fromisoformat(self.policy.values["expires_at"].replace("Z", "+00:00")).timestamp())
        now = int(time.time())
        return {
            "schema_version": "restricted-mattermost-outbox.v1",
            "tenant_id": self.policy.values["tenant_id"], "origin": self.policy.origin,
            "channel_id": post["channel_id"], "root_id": root_id, "source_id": post["id"],
            "actor_id": post["user_id"], "message": post["message"],
            "conversation_id": conversation_identity(self.policy.values["tenant_id"], self.policy.origin, post["channel_id"], root_id),
            "conversation_epoch": None,
            "client_request_id": request_identity(self.policy.values["tenant_id"], self.policy.origin, post["channel_id"], post["id"]),
            "policy_epoch": self.policy.values["policy_epoch"], "policy_digest": self.policy.digest,
            "key_fingerprint": self.policy.values["outbox_key_fingerprint"],
            "policy_expires_at": expires,
            "payload_expires_at": min(expires, now + self.policy.values["outbox_payload_retention_seconds"]),
            "response": None, "pending_post_id": str(uuid.uuid5(_NAMESPACE, "delivery\x00" + post["id"])), "returned_post_id": None,
        }

    def _revalidate_envelope(self, envelope: dict[str, Any]) -> None:
        if (
            envelope["policy_epoch"] != self.policy.values["policy_epoch"]
            or envelope["policy_digest"] != self.policy.digest
            or envelope["key_fingerprint"] != self.policy.values["outbox_key_fingerprint"]
        ):
            raise DefinitiveMattermostError("Mattermost outbox policy binding changed")
        self._bot_identity(definitive=True)
        source = self.rest.get_post(envelope["source_id"], definitive=True)
        if isinstance(source, dict) and "file_ids" not in source:
            source = {**source, "file_ids": []}
        if not isinstance(source, dict) or source.get("id") != envelope["source_id"] or source.get("channel_id") != envelope["channel_id"] or source.get("user_id") != envelope["actor_id"]:
            raise DefinitiveMattermostError("Mattermost source replay binding rejected")
        root_id = self._authorize_source(source, definitive=True)
        if root_id != envelope["root_id"] or source.get("message") != envelope["message"]:
            raise DefinitiveMattermostError("Mattermost source/root replay binding rejected")

    def handle(self, event: MattermostEvent) -> None:
        try:
            self.policy.validate()
            if not self._authenticated or event.channel_type != "P":
                return
            post = event.post
            root_id = self._authorize_source(post)
            envelope = self._envelope(post, root_id)
            record, _ = self.outbox.reserve(
                envelope,
                payload_capacity=self.policy.values["outbox_payload_capacity"],
                tombstone_capacity=self.policy.values["outbox_tombstone_capacity"],
            )
            self.executor.signal(record.record_tag)
        except (ContractError, KeyError, OSError, TimeoutError, UnicodeError, ValueError):
            logging.getLogger("restricted_mattermost").warning("mattermost_event_outcome=rejected")

    def start_periodic_recovery(self) -> tuple[threading.Event, threading.Thread]:
        """Schedule bounded scans through the existing single serialized executor."""
        stop = threading.Event()

        def run() -> None:
            while not stop.wait(self.policy.values["outbox_scan_interval_seconds"]):
                self.executor.drain()

        worker = threading.Thread(target=run, name="restricted-mattermost-outbox-scan", daemon=True)
        worker.start()
        return stop, worker

    def stop_periodic_recovery(self, handle: tuple[threading.Event, threading.Thread]) -> None:
        stop, worker = handle
        stop.set()
        worker.join(timeout=self.policy.values["outbox_scan_interval_seconds"] + 1)


class SerializedDeliveryExecutor:
    """The only code path which can call conversation UDS or Mattermost POST."""
    def __init__(self, ingress: Ingress):
        self.ingress = ingress
        self._lock = threading.Lock()

    def signal(self, _record_tag: str) -> None:
        # Signalling synchronously keeps the existing edge event loop bounded;
        # the lock is the single global executor and no ingress code dispatches around it.
        self.drain()

    def drain(self) -> None:
        with self._lock:
            for record in self.ingress.outbox.candidates(self.ingress.policy.values["outbox_scan_limit"]):
                self._process(record)

    def _block_or_expire(self, record: OutboxRecord, reason: str) -> None:
        target = DeliveryState.EXPIRED if reason == "payload_expired" else DeliveryState.BLOCKED
        self.ingress.outbox.terminal(record, target, reason=reason)

    def _expiry_fence(self, record: OutboxRecord) -> bool:
        """Fence every outbound boundary against expiry after slow local checks."""
        envelope = record.envelope
        if envelope is None:
            return False
        now = int(time.time())
        if now >= envelope["payload_expires_at"]:
            self._block_or_expire(record, "payload_expired")
            return False
        if now >= envelope["policy_expires_at"]:
            self._block_or_expire(record, "policy_expired")
            return False
        return True

    def _process(self, record: OutboxRecord) -> None:
        if record.state is DeliveryState.IN_FLIGHT:
            self.ingress.outbox.terminal(record, DeliveryState.AMBIGUOUS, reason="stale_in_flight")
            return
        envelope = record.envelope
        if envelope is None:
            return
        if not self._expiry_fence(record):
            return
        try:
            self.ingress._revalidate_envelope(envelope)
            self.ingress._readiness_binding()
        except DefinitiveMattermostError:
            self._block_or_expire(record, "current_authorization_rejected")
            return
        except (ContractError, OSError, TimeoutError, ValueError):
            return
        if record.state is DeliveryState.WAITING_COMMIT:
            try:
                deadline = time.monotonic() + self.ingress.policy.values["conversation_deadline_seconds"]
                if envelope["conversation_epoch"] is None:
                    if not self._expiry_fence(record):
                        return
                    created = self.ingress.conversation.create_conversation(
                        conversation_id=envelope["conversation_id"], deadline=deadline
                    )
                    epoch = created.get("conversation_epoch") if isinstance(created, dict) else None
                    if created.get("conversation_id") != envelope["conversation_id"] or not isinstance(epoch, str) or not epoch:
                        self.ingress.outbox.terminal(record, DeliveryState.FAILED, reason="conversation_create_shape")
                        return
                    envelope = {**envelope, "conversation_epoch": epoch}
                    record = self.ingress.outbox.update_waiting(record, envelope)
                if not self._expiry_fence(record):
                    return
                if deadline - time.monotonic() <= 0:
                    raise TimeoutError
                result = self.ingress.conversation.submit_turn(
                    conversation_id=envelope["conversation_id"], conversation_epoch=envelope["conversation_epoch"],
                    client_request_id=envelope["client_request_id"], message=envelope["message"], deadline=deadline,
                )
            except (ContractError, OSError, TimeoutError, ValueError):
                return
            if not self._expiry_fence(record):
                return
            status = result.get("status") if isinstance(result, dict) else None
            if status == "COMMITTED" and isinstance(result.get("message"), str) and result["message"] and result.get("conversation_epoch") == envelope["conversation_epoch"]:
                self.ingress.outbox.mark_ready(record, {**envelope, "response": result["message"]})
                record = self.ingress.outbox.get(record.record_tag)
                if record is None:
                    return
            elif status in {"FAILED", "REJECTED", "INDETERMINATE"}:
                self.ingress.outbox.terminal(record, DeliveryState.FAILED, reason="conversation_terminal")
                return
            else:
                return
        if record.state is not DeliveryState.READY or record.envelope is None:
            return
        try:
            self.ingress._revalidate_envelope(record.envelope)
            self.ingress._readiness_binding()
        except DefinitiveMattermostError:
            self._block_or_expire(record, "current_authorization_rejected")
            return
        except (ContractError, OSError, TimeoutError, ValueError):
            return
        if not self._expiry_fence(record):
            return
        claimed = self.ingress.outbox.claim_delivery(record)
        if claimed is None or claimed.envelope is None:
            return
        if not self._expiry_fence(claimed):
            return
        outbound = {"channel_id": claimed.envelope["channel_id"], "root_id": claimed.envelope["root_id"], "message": claimed.envelope["response"], "pending_post_id": claimed.envelope["pending_post_id"]}
        try:
            delivered = self.ingress.rest.create_post(outbound)
            if not isinstance(delivered, dict) or not isinstance(delivered.get("id"), str) or not delivered["id"] or delivered.get("channel_id") != outbound["channel_id"] or delivered.get("root_id") != outbound["root_id"] or delivered.get("pending_post_id") != outbound["pending_post_id"]:
                raise ContractError("Mattermost delivery binding rejected")
        except (ContractError, OSError, TimeoutError, ValueError):
            logging.getLogger("restricted_mattermost").warning("mattermost_delivery_outcome=rejected_binding")
            self.ingress.outbox.terminal(claimed, DeliveryState.AMBIGUOUS, reason="post_attempt_unconfirmed")
            return
        self.ingress.outbox.delivered(claimed, returned_post_id=delivered["id"])


class MattermostRestClient:
    """One-origin REST transport with no proxy discovery or redirect handling."""
    def __init__(self, policy: MattermostPolicy, token: str, *, ca_path: Path | None = None):
        self.policy, self._token = policy, token
        split = urlsplit(policy.origin)
        self._host, self._port = split.hostname or "", split.port or 443
        self._context = ssl.create_default_context(cafile=str(ca_path) if ca_path else None)

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None, *, definitive_shape: bool = False) -> dict[str, Any]:
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
                if response.status in {403, 404}:
                    raise DefinitiveMattermostError("Mattermost REST current resource rejected")
                raise TransientMattermostError("Mattermost REST response unavailable")
            try:
                raw = response.read(_MAX_HTTP_BYTES + 1)
                if len(raw) > _MAX_HTTP_BYTES or response.read(1):
                    raise ContractError("Mattermost REST response oversized")
                if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                    raise ContractError("Mattermost REST response content type rejected")
                value = load_closed_json(raw)
                if not isinstance(value, dict):
                    raise ContractError("Mattermost REST response JSON rejected")
            except ContractError as exc:
                if definitive_shape:
                    raise DefinitiveMattermostError("Mattermost REST current resource response rejected") from exc
                raise
            return value
        except ContractError:
            raise
        except (OSError, http.client.HTTPException, TimeoutError) as exc:
            raise TransientMattermostError("Mattermost REST transport failed") from exc
        finally:
            connection.close()

    def get_me(self, *, definitive: bool = False): return self._request("GET", "/api/v4/users/me", definitive_shape=definitive)
    def get_channel(self, channel_id, *, definitive: bool = False): return self._request("GET", "/api/v4/channels/" + quote(channel_id, safe=""), definitive_shape=definitive)
    def get_channel_member(self, channel_id, user_id, *, definitive: bool = False): return self._request("GET", "/api/v4/channels/" + quote(channel_id, safe="") + "/members/" + quote(user_id, safe=""), definitive_shape=definitive)
    def get_post(self, post_id, *, definitive: bool = False): return self._request("GET", "/api/v4/posts/" + quote(post_id, safe=""), definitive_shape=definitive)
    def create_post(self, body): return self._request("POST", "/api/v4/posts", body)


class ConversationUdsClient:
    """Closed client for the existing production conversation.sock API."""
    def __init__(self, policy: MattermostPolicy, path: str = "/run/restricted-inference/conversation.sock"):
        if path != "/run/restricted-inference/conversation.sock":
            raise ContractError("conversation socket path rejected")
        self.policy, self.path = policy, path

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        payload = b"" if body is None else jcs_bytes(body)
        request_deadline = time.monotonic() + self.policy.values["uds_timeout_seconds"]
        if deadline is not None:
            request_deadline = min(request_deadline, deadline)

        def remaining_timeout() -> float:
            remaining = request_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            # Preserve the existing five-second socket-operation cap while
            # never allowing an operation beyond its request/shared deadline.
            return min(5, remaining)

        try:
            remaining_timeout()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(remaining_timeout())
                client.connect(self.path)
                wire = method.encode() + b" " + path.encode() + b" HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
                client.settimeout(remaining_timeout())
                client.sendall(wire)
                chunks, total = [], 0
                while True:
                    client.settimeout(remaining_timeout())
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
            # Decoding/shape validation can itself consume the last budget.
            # Do not let a valid-but-late response escape this request.
            remaining_timeout()
            return value
        except ContractError:
            raise
        except (OSError, TimeoutError, ValueError) as exc:
            raise ContractError("conversation transport failed") from exc

    def ready(self): return self._request("GET", "/readyz")

    def create_conversation(self, *, conversation_id: str, deadline: float | None = None) -> dict[str, Any]:
        return self._request("POST", "/v1/restricted/conversations/" + conversation_id, deadline=deadline)

    def submit_turn(self, *, conversation_id: str, conversation_epoch: str, client_request_id: str, message: str, deadline: float | None = None) -> dict[str, Any]:
        deadline = deadline if deadline is not None else time.monotonic() + self.policy.values["conversation_deadline_seconds"]
        result = self._request(
            "POST", "/v1/restricted/conversations/" + conversation_id + "/turns",
            {"schema_version": "restricted-turn.v1", "client_request_id": client_request_id,
             "conversation_epoch": conversation_epoch, "message": message}, deadline=deadline,
        )
        if set(result) != {"schema_version", "turn_id", "conversation_epoch", "status", "message"}:
            raise ContractError("conversation turn response rejected")
        if deadline - time.monotonic() <= 0:
            raise ContractError("conversation transport failed")
        return result

    def submit(self, *, conversation_id: str, client_request_id: str, message: str):
        deadline = time.monotonic() + self.policy.values["conversation_deadline_seconds"]
        created = self.create_conversation(conversation_id=conversation_id, deadline=deadline)
        if created.get("conversation_id") != conversation_id or not isinstance(created.get("conversation_epoch"), str):
            raise ContractError("conversation creation response rejected")
        if deadline - time.monotonic() <= 0:
            raise ContractError("conversation transport failed")
        # Keep the legacy public helper as one shared-budget call path; the
        # outbox executor uses the split methods to persist the original epoch.
        result = self._request(
            "POST", "/v1/restricted/conversations/" + conversation_id + "/turns",
            {"schema_version": "restricted-turn.v1", "client_request_id": client_request_id,
             "conversation_epoch": created["conversation_epoch"], "message": message}, deadline=deadline,
        )
        if set(result) != {"schema_version", "turn_id", "conversation_epoch", "status", "message"}:
            raise ContractError("conversation turn response rejected")
        if deadline - time.monotonic() <= 0:
            raise ContractError("conversation transport failed")
        return result
