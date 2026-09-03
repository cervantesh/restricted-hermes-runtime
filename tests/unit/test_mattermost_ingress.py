from __future__ import annotations

import base64
import json
import http.client
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from restricted_runtime.contracts import ContractError, jcs_bytes
from restricted_runtime.mattermost_ingress import (
    MattermostRestClient,
    Ingress,
    MattermostEvent,
    conversation_identity,
    request_identity,
)
from restricted_runtime.mattermost_policy import load_signed_mattermost_policy, load_token


ORIGIN = "https://mattermost.internal.example"
TEAM = "team0000000000000000000000"
CHANNEL = "chan0000000000000000000000"
USER = "user0000000000000000000000"
BOT = "bot00000000000000000000000"
ROOT = "root0000000000000000000000"


def policy_values(now: datetime | None = None) -> dict:
    now = (now or datetime.now(UTC)).replace(microsecond=0)
    return {
        "schema_version": "restricted-mattermost-ingress-policy.v1",
        "policy_epoch": "mattermost-e1",
        "inference_policy_epoch": "inference-e1",
        "inference_policy_digest": "a" * 64,
        "tenant_id": "tenant-one",
        "origin": ORIGIN,
        "team_id": TEAM,
        "allowed_channel_ids": [CHANNEL],
        "allowed_user_ids": [USER],
        "bot_user_id": BOT,
        "bot_username": "restricted-bot",
        "allowed_modality": "text",
        "dms_allowed": False,
        "files_allowed": False,
        "delivery_mode": "thread-only",
        "initiation_mode": "explicit-mention",
        "max_message_utf8_bytes": 4096,
        "not_before": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "clock_skew_seconds": 30,
        "websocket_timeout_seconds": 10,
        "rest_timeout_seconds": 8,
        "uds_timeout_seconds": 45,
        "conversation_deadline_seconds": 40,
    }


def signed_policy(tmp_path: Path, values: dict | None = None, now: datetime | None = None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    values = values or policy_values(now)
    private = Ed25519PrivateKey.generate()
    policy = tmp_path / "ingress.json"
    signature = tmp_path / "ingress.sig"
    policy.write_bytes(jcs_bytes(values))
    signature.write_text(base64.b64encode(private.sign(jcs_bytes(values))).decode("ascii"), encoding="ascii")
    public = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
    return load_signed_mattermost_policy(policy, signature, public, now=now)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(origin="http://mattermost.internal.example"),
        lambda value: value.update(origin=ORIGIN + "/path"),
        lambda value: value.update(allowed_channel_ids=[]),
        lambda value: value.update(allowed_user_ids=[]),
        lambda value: value.update(max_message_utf8_bytes=131073),
        lambda value: value.update(inference_policy_digest="bad"),
        lambda value: value.update(uds_timeout_seconds=39, conversation_deadline_seconds=40),
        lambda value: value.update(rest_timeout_seconds=31),
        lambda value: value.update(extra=True),
    ],
)
def test_policy_is_closed_signed_and_canonical(tmp_path, mutation):
    value = policy_values()
    mutation(value)
    with pytest.raises(ContractError):
        signed_policy(tmp_path, value)


def test_policy_rejects_unsigned_and_invalid_signature(tmp_path):
    value = policy_values()
    policy = tmp_path / "policy.json"
    signature = tmp_path / "policy.sig"
    policy.write_bytes(jcs_bytes(value))
    signature.write_text("", encoding="ascii")
    with pytest.raises(ContractError):
        load_signed_mattermost_policy(policy, signature, base64.b64encode(b"x" * 32).decode())
    signature.write_text(base64.b64encode(b"x" * 64).decode(), encoding="ascii")
    with pytest.raises(ContractError):
        load_signed_mattermost_policy(policy, signature, base64.b64encode(b"x" * 32).decode())


def test_policy_time_boundaries_include_only_bounded_skew(tmp_path):
    now = datetime(2026, 9, 2, tzinfo=UTC)
    value = policy_values(now)
    value["not_before"] = (now + timedelta(seconds=31)).isoformat().replace("+00:00", "Z")
    with pytest.raises(ContractError):
        signed_policy(tmp_path / "early", value, now)
    value = policy_values(now)
    value["expires_at"] = (now - timedelta(seconds=31)).isoformat().replace("+00:00", "Z")
    with pytest.raises(ContractError):
        signed_policy(tmp_path / "late", value, now)
    for offset in (-30, 30):
        target = tmp_path / str(offset)
        target.mkdir()
        value = policy_values(now)
        if offset > 0:
            value["not_before"] = (now + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")
        else:
            value["expires_at"] = (now + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")
        signed_policy(target, value, now)


def test_token_is_regular_nonsymlink_bounded_and_read_once(tmp_path):
    token = tmp_path / "token"
    token.write_text("secret-token\n", encoding="utf-8")
    assert load_token(token) == "secret-token"
    link = tmp_path / "link"
    try:
        link.symlink_to(token)
    except OSError:
        pytest.skip("symlink unavailable")
    with pytest.raises(ContractError):
        load_token(link)
    token.write_bytes(b"x" * 4097)
    with pytest.raises(ContractError):
        load_token(token)


class Rest:
    def __init__(self):
        self.channels = {CHANNEL: {"id": CHANNEL, "team_id": TEAM, "type": "P"}}
        self.posts = {}
        self.created = []
        self.me = {"id": BOT, "username": "restricted-bot"}

    def get_me(self):
        return self.me

    def get_channel(self, channel_id):
        return self.channels[channel_id]

    def get_post(self, post_id):
        return self.posts[post_id]

    def create_post(self, body):
        self.created.append(body)
        return {"id": "reply000000000000000000000", **body}


class Conversation:
    def __init__(self):
        self.calls = []
        self.readiness = {
            "schema_version": "restricted-conversation-readiness.v1",
            "status": "ready",
            "policy_epoch": "inference-e1",
            "policy_digest": "a" * 64,
            "classification": "PHI",
            "system_instruction_version": "restricted-phi-system.v1",
            "allowed_modalities": ["text"],
            "tools_allowed": False,
            "fallbacks": [],
            "max_provider_attempts": 1,
            "streaming": False,
            "max_output_tokens": 4096,
            "max_canonical_input_utf8_bytes": 131072,
            "response_profile": "restricted-local-text-response.v1",
        }

    def ready(self):
        return self.readiness

    def submit(self, *, conversation_id, client_request_id, message):
        self.calls.append((conversation_id, client_request_id, message))
        return {"status": "COMMITTED", "message": "synthetic response"}


def post(post_id=ROOT, *, root_id="", user_id=USER, channel_id=CHANNEL, message="@restricted-bot hello", **changes):
    value = {
        "id": post_id,
        "root_id": root_id,
        "channel_id": channel_id,
        "user_id": user_id,
        "message": message,
        "type": "",
        "file_ids": [],
        "edit_at": 0,
        "delete_at": 0,
    }
    value.update(changes)
    return value


def event(value: dict, *, channel_type="P") -> MattermostEvent:
    return MattermostEvent.parse(
        jcs_bytes({"event": "posted", "data": {"post": json.dumps(value), "channel_type": channel_type}}),
        max_bytes=65536,
    )


def test_rest_root_without_file_ids_is_normalized_to_text_only_and_reaches_exact_thread(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    del rest.posts[ROOT]["file_ids"]
    service.handle(event(post()))
    assert len(conversation.calls) == 1
    assert len(rest.created) == 1
    assert rest.created[0]["channel_id"] == CHANNEL
    assert rest.created[0]["root_id"] == ROOT


@pytest.mark.parametrize(
    "attachment_state",
    [
        {"file_ids": ["file000000000000000000000"]},
        {"metadata": {"files": [{"id": "hidden"}]}},
        {"props": {"attachments": [{"id": "hidden"}]}},
        {"attachment_manifest": {"id": "hidden"}},
    ],
)
def test_rest_root_attachment_representations_have_zero_side_effects(tmp_path, attachment_state):
    service, rest, conversation = ingress(tmp_path)
    root = post()
    root.update(attachment_state)
    rest.posts[ROOT] = root
    service.handle(event(post("reply00000000000000000000", root_id=ROOT, message="reply")))
    assert conversation.calls == []
    assert rest.created == []


def test_whitespace_is_rejected_and_exact_mention_accepts_ordinary_punctuation(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    service.handle(event(post("blankreply000000000000000000", root_id=ROOT, message="   \t")))
    service.handle(event(post("substring000000000000000000", message="@restricted-bot-extra hello")))
    assert conversation.calls == []
    punctuated = post("punctuation00000000000000000", message="Hello, @restricted-bot: help.")
    rest.posts[punctuated["id"]] = punctuated
    service.handle(event(punctuated))
    assert len(conversation.calls) == 1


def test_expired_policy_stops_admission_in_a_live_process(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    now = datetime.now(UTC).replace(microsecond=0)
    service.policy.values["expires_at"] = (now - timedelta(seconds=31)).isoformat().replace("+00:00", "Z")
    service.handle(event(post()))
    assert conversation.calls == []


def ingress(tmp_path):
    policy = signed_policy(tmp_path)
    rest, conversation = Rest(), Conversation()
    root = post()
    rest.posts[ROOT] = root
    service = Ingress(policy, rest, conversation)
    service.preflight()
    service.mark_authenticated()
    return service, rest, conversation


def test_preflight_binds_readiness_bot_and_all_private_channels(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    conversation.readiness["policy_digest"] = "b" * 64
    with pytest.raises(ContractError):
        service.preflight()
    conversation.readiness["policy_digest"] = "a" * 64
    rest.channels[CHANNEL]["type"] = "O"
    with pytest.raises(ContractError):
        service.preflight()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(user_id="other000000000000000000000"),
        lambda value: value.update(channel_id="other00000000000000000000"),
        lambda value: value.update(user_id=BOT),
        lambda value: value.update(type="system_join_channel"),
        lambda value: value.update(file_ids=["file"]),
        lambda value: value.update(edit_at=1),
        lambda value: value.update(delete_at=1),
        lambda value: value.update(message=""),
        lambda value: value.update(message="x" * 4097),
    ],
)
def test_prohibited_posts_have_zero_side_effects(tmp_path, mutation):
    service, rest, conversation = ingress(tmp_path)
    value = post()
    mutation(value)
    service.handle(event(value))
    assert conversation.calls == []
    assert rest.created == []


@pytest.mark.parametrize("channel_type", ["D", "G", "O", ""])
def test_nonprivate_event_types_have_zero_side_effects(tmp_path, channel_type):
    service, rest, conversation = ingress(tmp_path)
    service.handle(event(post(), channel_type=channel_type))
    assert conversation.calls == []
    assert rest.created == []


def test_malformed_events_and_cross_channel_roots_have_zero_side_effects(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    with pytest.raises(ContractError):
        MattermostEvent.parse(b'{"event":"posted","data":{}}')
    rest.posts[ROOT]["channel_id"] = "other00000000000000000000"
    service.handle(event(post("reply30000000000000000000", root_id=ROOT, message="reply")))
    assert conversation.calls == []
    assert rest.created == []


def test_rest_transport_rejects_redirect_error_malformed_and_oversize_without_proxy(monkeypatch, tmp_path):
    policy = signed_policy(tmp_path)

    class Response:
        def __init__(self, status=200, body=b"{}", headers=None):
            self.status, self.body, self.headers = status, body, headers or {"Content-Type": "application/json"}
            self.offset = 0

        def getheader(self, name, default=None):
            return self.headers.get(name, default)

        def read(self, size=-1):
            if size < 0:
                size = len(self.body) - self.offset
            result = self.body[self.offset:self.offset + size]
            self.offset += len(result)
            return result

    class Connection:
        response = Response()
        calls = []

        def __init__(self, host, port, **kwargs):
            assert (host, port) == ("mattermost.internal.example", 443)
            self.calls.append((host, port, kwargs))

        def request(self, method, path, body=None, headers=None):
            assert path.startswith("/api/v4/")

        def getresponse(self):
            return self.response

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPSConnection", Connection)
    client = MattermostRestClient(policy, "secret")
    assert client.get_me() == {}
    assert Connection.calls[-1][:2] == ("mattermost.internal.example", 443)
    for response in (
        Response(302, b"{}", {"Content-Type": "application/json", "Location": "https://elsewhere"}),
        Response(401, b'{"error":"secret-body"}'),
        Response(200, b"not-json"),
        Response(200, b"x" * 1_048_577),
    ):
        Connection.response = response
        with pytest.raises(ContractError):
            client.get_me()


def test_events_before_websocket_auth_success_have_zero_side_effects(tmp_path):
    policy = signed_policy(tmp_path)
    rest, conversation = Rest(), Conversation()
    rest.posts[ROOT] = post()
    service = Ingress(policy, rest, conversation)
    service.preflight()
    service.handle(event(post()))
    assert not conversation.calls and not rest.created


def test_fresh_root_and_channel_validation_and_thread_only_delivery(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    reply = post("reply00000000000000000000", root_id=ROOT, message="follow up")
    service.handle(event(reply))
    assert len(conversation.calls) == 1
    assert rest.created[0]["channel_id"] == CHANNEL
    assert rest.created[0]["root_id"] == ROOT
    rest.created.clear()
    rest.posts[ROOT]["edit_at"] = 1
    service.handle(event(post("reply20000000000000000000", root_id=ROOT, message="again")))
    assert len(conversation.calls) == 1
    assert rest.created == []


def test_identity_is_deterministic_and_partitioned_by_channel_and_root():
    first = conversation_identity("tenant", ORIGIN, CHANNEL, ROOT)
    assert first == conversation_identity("tenant", ORIGIN, CHANNEL, ROOT)
    assert first != conversation_identity("tenant", ORIGIN, CHANNEL, "other")
    assert first != conversation_identity("tenant", ORIGIN, "other", ROOT)
    assert request_identity("tenant", ORIGIN, CHANNEL, ROOT) == request_identity("tenant", ORIGIN, CHANNEL, ROOT)


def test_concurrent_duplicates_infer_and_attempt_post_once(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    incoming = event(post())
    threads = [threading.Thread(target=service.handle, args=(incoming,)) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(conversation.calls) == 1
    assert len(rest.created) == 1


def test_delivery_timeout_after_accept_is_not_retried_or_flattened(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    attempts = []

    def ambiguous(body):
        attempts.append(body)
        raise TimeoutError

    rest.create_post = ambiguous
    incoming = event(post())
    service.handle(incoming)
    service.handle(incoming)
    assert len(conversation.calls) == 1
    assert len(attempts) == 1


def test_delivery_response_mismatch_never_falls_back_to_flat_post(tmp_path, caplog):
    service, rest, conversation = ingress(tmp_path)
    attempts = []

    def mismatched(body):
        attempts.append(body)
        return {"id": "reply", **body, "root_id": "different-root"}

    rest.create_post = mismatched
    service.handle(event(post()))
    service.handle(event(post()))
    assert len(conversation.calls) == 1
    assert len(attempts) == 1
    assert attempts[0]["root_id"] == ROOT
    assert "mattermost_delivery_outcome=rejected_binding" in caplog.text
