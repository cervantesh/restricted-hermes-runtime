from __future__ import annotations

import base64
import hashlib
import json
import http.client
import os
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from restricted_runtime.contracts import ContractError, jcs_bytes
import restricted_runtime.mattermost_ingress as mattermost_ingress
from restricted_runtime.mattermost_ingress import (
    ConversationUdsClient,
    DefinitiveMattermostError,
    MattermostRestClient,
    Ingress,
    MattermostEvent,
    conversation_identity,
    request_identity,
)
from restricted_runtime.mattermost_policy import load_signed_mattermost_policy, load_token
from restricted_runtime.mattermost_outbox import DeliveryState, MattermostOutbox


ORIGIN = "https://mattermost.internal.example"
TEAM = "team0000000000000000000000"
CHANNEL = "chan0000000000000000000000"
USER = "user0000000000000000000000"
BOT = "bot00000000000000000000000"
ROOT = "root0000000000000000000000"
OUTBOX_KEY = b"m" * 32
UNICODE_15_1_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180D), (0x180E, 0x180E), (0x180F, 0x180F),
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2065, 0x2065),
    (0x2066, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0000), (0xE0001, 0xE0001), (0xE0002, 0xE001F), (0xE0020, 0xE007F),
    (0xE0080, 0xE00FF), (0xE0100, 0xE01EF), (0xE01F0, 0xE0FFF),
)


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
        "outbox_key_fingerprint": hashlib.sha256(OUTBOX_KEY).hexdigest(),
        "outbox_payload_retention_seconds": 3600,
        "outbox_payload_capacity": 1000,
        "outbox_tombstone_capacity": 1000,
        "outbox_scan_limit": 64, "outbox_scan_interval_seconds": 1,
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
        lambda value: value.update(outbox_scan_interval_seconds=0),
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

    def get_me(self, *, definitive=False):
        return self.me

    def get_channel(self, channel_id, *, definitive=False):
        return self.channels[channel_id]

    def get_post(self, post_id, *, definitive=False):
        return self.posts[post_id]

    def get_channel_member(self, channel_id, user_id, *, definitive=False):
        return {"channel_id": channel_id, "user_id": user_id}

    def create_post(self, body):
        self.created.append(body)
        return {"id": "reply000000000000000000000", **body}


class Conversation:
    def __init__(self):
        self.calls = []
        self.deadlines = []
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

    def create_conversation(self, *, conversation_id, deadline=None):
        self.deadlines.append(deadline)
        return {"conversation_id": conversation_id, "conversation_epoch": "epoch-one"}

    def submit_turn(self, *, conversation_id, conversation_epoch, client_request_id, message, deadline=None):
        self.deadlines.append(deadline)
        self.calls.append((conversation_id, client_request_id, message))
        return {"schema_version": "restricted-turn-result.v1", "turn_id": "turn", "conversation_epoch": conversation_epoch, "status": "COMMITTED", "message": "synthetic response"}


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
    key = tmp_path / "outbox.key"
    key.write_bytes(OUTBOX_KEY)
    os.chmod(key, 0o600)
    outbox = MattermostOutbox.initialize(tmp_path / "outbox", key, expected_fingerprint=policy.values["outbox_key_fingerprint"])
    service = Ingress(policy, rest, conversation, outbox)
    service.preflight()
    service.mark_authenticated()
    return service, rest, conversation


@pytest.mark.parametrize(
    ("uppercase", "lowercase", "ascii"),
    [
        ("\u0410", "\u0430", "a"), ("\u0415", "\u0435", "e"), ("\u0406", "\u0456", "i"),
        ("\u041c", "\u043c", "m"), ("\u041e", "\u043e", "o"), ("\u0420", "\u0440", "p"),
        ("\u0422", "\u0442", "t"), ("\u0425", "\u0445", "x"), ("\u0391", "\u03b1", "a"),
        ("\u0399", "\u03b9", "i"), ("\u039f", "\u03bf", "o"), ("\u03a1", "\u03c1", "p"),
        ("\u03a4", "\u03c4", "t"), ("\u03a7", "\u03c7", "x"),
    ],
)
def test_supported_uppercase_and_lowercase_confusables_reserve_the_clinical_namespace_in_an_allowed_private_channel(
    tmp_path, uppercase, lowercase, ascii,
):
    service, rest, conversation = ingress(tmp_path)
    for glyph in (uppercase, lowercase):
        candidate = post(message=f"@restricted-bot {'next-appointment'.replace(ascii, glyph, 1)} 123e4567-e89b-42d3-a456-426614174000")
        rest.posts[ROOT] = candidate
        service.handle(event(candidate, channel_type="P"))
        assert conversation.calls == []
        assert rest.created == []


@pytest.mark.parametrize(
    "modifier",
    ["\u034f", "\u17b4", "\u180b", "\ufe0e", "\ufe0f", "\U000e0100"],
)
@pytest.mark.parametrize(
    ("glyph", "ascii"),
    [
        ("\u0430", "a"), ("\u0435", "e"), ("\u0456", "i"), ("\u043c", "m"),
        ("\u043e", "o"), ("\u0440", "p"), ("\u0442", "t"), ("\u0445", "x"),
        ("\u03b1", "a"), ("\u03b9", "i"), ("\u03bf", "o"), ("\u03c1", "p"),
        ("\u03c4", "t"), ("\u03c7", "x"),
    ],
)
def test_default_ignorable_nonspacing_modifiers_around_supported_confusables_reserve_the_clinical_namespace(
    tmp_path, modifier, glyph, ascii,
):
    service, rest, conversation = ingress(tmp_path)
    command = "next-appointment".replace(ascii, glyph + modifier, 1)
    candidate = post(message=f"@restricted-bot {command} 123e4567-e89b-42d3-a456-426614174000")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls == []
    assert rest.created == []


@pytest.mark.parametrize("filler", ["\u115f", "\u1160", "\u3164", "\uffa0"])
def test_default_ignorable_hangul_fillers_around_supported_confusables_reserve_the_clinical_namespace(
    tmp_path, filler,
):
    service, rest, conversation = ingress(tmp_path)
    candidate = post(message=f"@restricted-bot n\u0435{filler}xt-appointment 123e4567-e89b-42d3-a456-426614174000")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls == []
    assert rest.created == []


@pytest.mark.parametrize("start, end", UNICODE_15_1_DEFAULT_IGNORABLE_RANGES)
def test_every_unicode_15_1_default_ignorable_range_boundary_is_removed_from_the_namespace_skeleton(start, end):
    assert mattermost_ingress._UNICODE_15_1_DEFAULT_IGNORABLE_RANGES == UNICODE_15_1_DEFAULT_IGNORABLE_RANGES
    for codepoint in (start, end):
        assert mattermost_ingress._namespace_ignorable(chr(codepoint))
        assert mattermost_ingress._namespace_skeleton(f"n\u0435{chr(codepoint)}xt-appointment") == "next-appointment"


def test_ordinary_private_channel_text_still_reaches_the_conversation_path(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    candidate = post(message="@restricted-bot ordinary request")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert len(conversation.calls) == 1
    assert len(rest.created) == 1


def test_ordinary_unicode_private_channel_text_still_reaches_the_conversation_path(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    candidate = post(message="@restricted-bot café 日本語")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert len(conversation.calls) == 1
    assert len(rest.created) == 1


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


@pytest.mark.parametrize(
    "response",
    [
        (b"{}", {"Content-Type": "text/plain"}),
        (b"[]", {"Content-Type": "application/json"}),
        (b"not-json", {"Content-Type": "application/json"}),
        (b"x" * 1_048_577, {"Content-Type": "application/json"}),
    ],
)
def test_recovery_resource_http_200_shape_rejection_is_definitive(monkeypatch, tmp_path, response):
    policy = signed_policy(tmp_path)

    class Response:
        status = 200

        def __init__(self, body, headers):
            self.body, self.headers, self.offset = body, headers, 0

        def getheader(self, name, default=None):
            return self.headers.get(name, default)

        def read(self, size=-1):
            if size < 0:
                size = len(self.body) - self.offset
            result = self.body[self.offset:self.offset + size]
            self.offset += len(result)
            return result

    class Connection:
        current = Response(*response)

        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            return self.current

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPSConnection", Connection)
    with pytest.raises(DefinitiveMattermostError, match="response"):
        MattermostRestClient(policy, "secret").get_me(definitive=True)


def test_events_before_websocket_auth_success_have_zero_side_effects(tmp_path):
    policy = signed_policy(tmp_path)
    rest, conversation = Rest(), Conversation()
    rest.posts[ROOT] = post()
    key = tmp_path / "outbox.key"
    key.write_bytes(OUTBOX_KEY)
    os.chmod(key, 0o600)
    service = Ingress(policy, rest, conversation, MattermostOutbox.initialize(tmp_path / "outbox", key, expected_fingerprint=policy.values["outbox_key_fingerprint"]))
    service.preflight()
    service.handle(event(post()))
    assert not conversation.calls and not rest.created


def test_fresh_root_and_channel_validation_and_thread_only_delivery(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    reply = post("reply00000000000000000000", root_id=ROOT, message="follow up")
    rest.posts[reply["id"]] = reply
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


def test_restart_after_reservation_recovers_one_waiting_turn_and_one_post(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    source = post()
    record, created = service.outbox.reserve(
        service._envelope(source, service._authorize_source(source)),
        payload_capacity=1000, tombstone_capacity=1000,
    )
    assert created and record.state is DeliveryState.WAITING_COMMIT
    service.outbox.close()
    reopened = MattermostOutbox.open(
        tmp_path / "outbox", tmp_path / "outbox.key",
        expected_fingerprint=service.policy.values["outbox_key_fingerprint"],
    )
    recovered = Ingress(service.policy, rest, conversation, reopened)
    recovered.preflight()
    assert len(conversation.calls) == 1 and len(rest.created) == 1
    durable = reopened.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.DELIVERED and durable.envelope is None
    reopened.close()


def test_restart_after_ready_attempts_one_post_and_after_inflight_never_retries(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    source = post()
    waiting, _ = service.outbox.reserve(
        service._envelope(source, service._authorize_source(source)),
        payload_capacity=1000, tombstone_capacity=1000,
    )
    ready = service.outbox.mark_ready(waiting, {**waiting.envelope, "conversation_epoch": "epoch-one", "response": "synthetic response"})
    service.outbox.close()
    reopened = MattermostOutbox.open(
        tmp_path / "outbox", tmp_path / "outbox.key",
        expected_fingerprint=service.policy.values["outbox_key_fingerprint"],
    )
    recovered = Ingress(service.policy, rest, conversation, reopened)
    recovered.preflight()
    assert len(rest.created) == 1
    delivered = reopened.get(ready.record_tag)
    assert delivered is not None and delivered.state is DeliveryState.DELIVERED
    # A separate ready record models the exact durable IN_FLIGHT boundary: a
    # replacement process must classify it ambiguous before any HTTP retry.
    source2 = post("second00000000000000000000", root_id="", message="@restricted-bot second")
    rest.posts[source2["id"]] = source2
    wait2, _ = reopened.reserve(recovered._envelope(source2, recovered._authorize_source(source2)), payload_capacity=1000, tombstone_capacity=1000)
    ready2 = reopened.mark_ready(wait2, {**wait2.envelope, "conversation_epoch": "epoch-two", "response": "synthetic response"})
    flight = reopened.claim_delivery(ready2)
    assert flight is not None and flight.state is DeliveryState.IN_FLIGHT
    reopened.close()
    final = MattermostOutbox.open(tmp_path / "outbox", tmp_path / "outbox.key", expected_fingerprint=service.policy.values["outbox_key_fingerprint"])
    restart = Ingress(service.policy, rest, conversation, final)
    restart.preflight()
    assert len(rest.created) == 1
    ambiguous = final.get(flight.record_tag)
    assert ambiguous is not None and ambiguous.state is DeliveryState.AMBIGUOUS and ambiguous.envelope is None
    final.close()


def test_recovery_readiness_uses_the_exact_preflight_binding_before_uds_or_post(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    source = post()
    record, _ = service.outbox.reserve(
        service._envelope(source, service._authorize_source(source)),
        payload_capacity=1000, tombstone_capacity=1000,
    )
    conversation.readiness["policy_digest"] = "b" * 64
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.WAITING_COMMIT
    assert conversation.calls == [] and rest.created == []
    conversation.readiness["policy_digest"] = "a" * 64
    service.executor.drain()
    assert len(conversation.calls) == 1 and len(rest.created) == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda rest: rest.me.update(username="renamed-bot"),
        lambda rest: rest.channels[CHANNEL].update(type="O"),
        lambda rest: rest.posts[ROOT].update(message="@restricted-bot edited"),
    ],
)
def test_recovery_current_bot_channel_and_root_mismatches_are_definitive_blocks(tmp_path, mutate):
    service, rest, conversation = ingress(tmp_path)
    source = post()
    record, _ = service.outbox.reserve(
        service._envelope(source, service._authorize_source(source)),
        payload_capacity=1000, tombstone_capacity=1000,
    )
    mutate(rest)
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.BLOCKED
    assert conversation.calls == [] and rest.created == []


def test_recovery_http_200_array_then_valid_resource_is_blocked_without_release(monkeypatch, tmp_path):
    policy = signed_policy(tmp_path)

    class Response:
        status = 200

        def __init__(self, body):
            self.body, self.offset = body, 0

        def getheader(self, name, default=None):
            return "application/json" if name == "Content-Type" else default

        def read(self, size=-1):
            if size < 0:
                size = len(self.body) - self.offset
            result = self.body[self.offset:self.offset + size]
            self.offset += len(result)
            return result

    class Connection:
        responses = [Response(b"[]"), Response(jcs_bytes({"id": BOT, "username": "restricted-bot"}))]
        requests = 0

        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, *_args, **_kwargs):
            type(self).requests += 1

        def getresponse(self):
            return type(self).responses.pop(0)

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPSConnection", Connection)
    key = tmp_path / "outbox.key"
    key.write_bytes(OUTBOX_KEY)
    os.chmod(key, 0o600)
    outbox = MattermostOutbox.initialize(
        tmp_path / "outbox", key, expected_fingerprint=policy.values["outbox_key_fingerprint"]
    )
    conversation = Conversation()
    service = Ingress(policy, MattermostRestClient(policy, "secret"), conversation, outbox)
    source = post()
    record, _ = outbox.reserve(
        service._envelope(source, ROOT), payload_capacity=1000, tombstone_capacity=1000,
    )
    try:
        service.executor.drain()
        blocked = outbox.get(record.record_tag)
        assert blocked is not None and blocked.state is DeliveryState.BLOCKED
        service.executor.drain()
        assert Connection.requests == 1
        assert conversation.calls == []
    finally:
        outbox.close()


def _expiring_waiting_record(service, source, *, expires_at=100):
    return service.outbox.reserve(
        {
            **service._envelope(source, service._authorize_source(source)),
            "payload_expires_at": expires_at,
            "policy_expires_at": max(10_000, expires_at),
        },
        payload_capacity=1000,
        tombstone_capacity=1000,
    )[0]


@pytest.mark.parametrize(
    ("field", "state"),
    [("payload_expires_at", DeliveryState.EXPIRED), ("policy_expires_at", DeliveryState.BLOCKED)],
)
def test_recovery_expiry_fence_is_exclusive_at_the_exact_signed_wall_clock(tmp_path, monkeypatch, field, state):
    service, rest, conversation = ingress(tmp_path)
    clock = {"now": 100}
    monkeypatch.setattr(mattermost_ingress.time, "time", lambda: clock["now"])
    source = post()
    envelope = {
        **service._envelope(source, service._authorize_source(source)),
        "payload_expires_at": 4_000_000_000,
        "policy_expires_at": 4_000_000_000,
        field: 100,
    }
    record, _ = service.outbox.reserve(envelope, payload_capacity=1000, tombstone_capacity=1000)
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is state
    assert conversation.deadlines == [] and conversation.calls == [] and rest.created == []


@pytest.mark.parametrize("expiry_now", [101, 100], ids=["after-expiry", "at-expiry"])
def test_recovery_expiry_fence_stops_before_conversation_after_slow_authorization(tmp_path, monkeypatch, expiry_now):
    service, rest, conversation = ingress(tmp_path)
    clock = {"now": 90}
    monkeypatch.setattr(mattermost_ingress.time, "time", lambda: clock["now"])
    record = _expiring_waiting_record(service, post())
    original_me = rest.get_me

    def auth_then_expire(**kwargs):
        value = original_me(**kwargs)
        clock["now"] = expiry_now
        return value

    rest.get_me = auth_then_expire
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.EXPIRED
    assert conversation.deadlines == [] and conversation.calls == [] and rest.created == []


@pytest.mark.parametrize("expiry_now", [101, 100], ids=["after-expiry", "at-expiry"])
def test_recovery_expiry_fence_stops_before_conversation_after_slow_readiness(tmp_path, monkeypatch, expiry_now):
    service, rest, conversation = ingress(tmp_path)
    clock = {"now": 90}
    monkeypatch.setattr(mattermost_ingress.time, "time", lambda: clock["now"])
    record = _expiring_waiting_record(service, post())
    original_ready = conversation.ready

    def readiness_then_expire():
        value = original_ready()
        clock["now"] = expiry_now
        return value

    conversation.ready = readiness_then_expire
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.EXPIRED
    assert conversation.deadlines == [] and conversation.calls == [] and rest.created == []


@pytest.mark.parametrize("expiry_now", [101, 100], ids=["after-expiry", "at-expiry"])
def test_recovery_expiry_fence_stops_before_turn_after_conversation_create(tmp_path, monkeypatch, expiry_now):
    service, rest, conversation = ingress(tmp_path)
    clock = {"now": 90}
    monkeypatch.setattr(mattermost_ingress.time, "time", lambda: clock["now"])
    record = _expiring_waiting_record(service, post())
    created = []
    original_create = conversation.create_conversation

    def create_then_expire(**kwargs):
        created.append(kwargs["conversation_id"])
        value = original_create(**kwargs)
        clock["now"] = expiry_now
        return value

    conversation.create_conversation = create_then_expire
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.EXPIRED
    assert len(created) == 1 and conversation.calls == [] and rest.created == []


@pytest.mark.parametrize("expiry_now", [101, 100], ids=["after-expiry", "at-expiry"])
def test_recovery_expiry_fence_stops_after_slow_turn_before_ready_transition(tmp_path, monkeypatch, expiry_now):
    service, rest, conversation = ingress(tmp_path)
    clock = {"now": 90}
    monkeypatch.setattr(mattermost_ingress.time, "time", lambda: clock["now"])
    record = _expiring_waiting_record(service, post())
    original_submit = conversation.submit_turn

    def turn_then_expire(**kwargs):
        value = original_submit(**kwargs)
        clock["now"] = expiry_now
        return value

    conversation.submit_turn = turn_then_expire
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.EXPIRED
    assert durable.generation == 2 and len(conversation.calls) == 1 and rest.created == []


@pytest.mark.parametrize("expiry_now", [101, 100], ids=["after-expiry", "at-expiry"])
def test_recovery_expiry_fence_stops_before_post_after_claim(tmp_path, monkeypatch, expiry_now):
    service, rest, _conversation = ingress(tmp_path)
    clock = {"now": 90}
    monkeypatch.setattr(mattermost_ingress.time, "time", lambda: clock["now"])
    source = post()
    waiting = _expiring_waiting_record(service, source)
    ready = service.outbox.mark_ready(
        waiting, {**waiting.envelope, "conversation_epoch": "epoch-one", "response": "synthetic response"}
    )
    original_claim = service.outbox.claim_delivery

    def claim_then_expire(record):
        value = original_claim(record)
        clock["now"] = expiry_now
        return value

    service.outbox.claim_delivery = claim_then_expire
    service.executor.drain()
    durable = service.outbox.get(ready.record_tag)
    assert durable is not None and durable.state is DeliveryState.EXPIRED
    assert rest.created == []


@pytest.mark.parametrize("expiry_now", [101, 100], ids=["after-expiry", "at-expiry"])
def test_recovery_expiry_fence_stops_before_claim_after_ready_readiness(tmp_path, monkeypatch, expiry_now):
    service, rest, conversation = ingress(tmp_path)
    clock = {"now": 90}
    monkeypatch.setattr(mattermost_ingress.time, "time", lambda: clock["now"])
    waiting = _expiring_waiting_record(service, post())
    ready = service.outbox.mark_ready(
        waiting, {**waiting.envelope, "conversation_epoch": "epoch-one", "response": "synthetic response"}
    )
    original_ready = conversation.ready
    claims = []

    def readiness_then_expire():
        value = original_ready()
        clock["now"] = expiry_now
        return value

    def counted_claim(record):
        claims.append(record.record_tag)
        return None

    conversation.ready = readiness_then_expire
    service.outbox.claim_delivery = counted_claim
    service.executor.drain()
    durable = service.outbox.get(ready.record_tag)
    assert durable is not None and durable.state is DeliveryState.EXPIRED
    assert claims == [] and rest.created == []


def test_durable_scan_cursor_does_not_starve_another_root_after_restart(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    service.policy.values["outbox_scan_limit"] = 1
    first_source = post("first-source000000000000000", message="@restricted-bot first")
    second_source = post("second-source00000000000000", message="@restricted-bot second")
    rest.posts[first_source["id"]] = first_source
    rest.posts[second_source["id"]] = second_source
    first = _expiring_waiting_record(service, first_source, expires_at=4_000_000_000)
    second = _expiring_waiting_record(service, second_source, expires_at=4_000_000_000)
    blocked, released = sorted((first, second), key=lambda item: item.root_tag)
    attempts = []
    original_create = conversation.create_conversation

    def transient_first_root(**kwargs):
        attempts.append(kwargs["conversation_id"])
        if kwargs["conversation_id"] == blocked.envelope["conversation_id"]:
            raise TimeoutError
        return original_create(**kwargs)

    conversation.create_conversation = transient_first_root
    service.executor.drain()
    assert attempts == [blocked.envelope["conversation_id"]]
    service.outbox.close()
    reopened = MattermostOutbox.open(
        tmp_path / "outbox", tmp_path / "outbox.key",
        expected_fingerprint=service.policy.values["outbox_key_fingerprint"],
    )
    recovered = Ingress(service.policy, rest, conversation, reopened)
    try:
        recovered.executor.drain()
        durable_blocked = reopened.get(blocked.record_tag)
        durable_released = reopened.get(released.record_tag)
        assert attempts == [blocked.envelope["conversation_id"], released.envelope["conversation_id"]]
        assert durable_blocked is not None and durable_blocked.state is DeliveryState.WAITING_COMMIT
        assert durable_released is not None and durable_released.state is DeliveryState.DELIVERED
        assert len(rest.created) == 1
    finally:
        reopened.close()


def test_process_lifetime_outbox_owner_blocks_a_second_writer_during_recovery_readiness(tmp_path):
    """A local SQLite writer cannot erase a selected record before the UDS turn."""
    service, rest, conversation = ingress(tmp_path)
    source = post()
    record, created = service.outbox.reserve(
        {
            **service._envelope(source, ROOT),
            "conversation_epoch": "epoch-one",
        },
        payload_capacity=1000,
        tombstone_capacity=1000,
    )
    assert created
    writer_outcomes = []
    original_ready = conversation.ready
    writer = r'''
import sqlite3, sys
connection = None
try:
    connection = sqlite3.connect(sys.argv[1], isolation_level=None, timeout=0)
    connection.execute("PRAGMA busy_timeout=0")
    cursor = connection.execute("DELETE FROM records WHERE record_tag=?", (sys.argv[2],))
    print("corrupted" if cursor.rowcount == 1 else "missing")
except sqlite3.Error:
    print("blocked")
finally:
    if connection is not None:
        connection.close()
    '''

    def readiness_with_concurrent_writer():
        if writer_outcomes:
            return original_ready()
        result = subprocess.run(
            [sys.executable, "-c", writer, str(service.outbox.path), record.record_tag],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        writer_outcomes.append(result.stdout.strip())
        return original_ready()

    conversation.ready = readiness_with_concurrent_writer
    try:
        service.executor.drain()
        durable = service.outbox.get(record.record_tag)
        assert writer_outcomes == ["blocked"]
        assert len(conversation.calls) == 1 and len(rest.created) == 1
        assert durable is not None and durable.state is DeliveryState.DELIVERED
    finally:
        service.outbox.close()


def test_recovery_passes_one_fresh_signed_deadline_to_creation_and_submission(tmp_path, monkeypatch):
    service, _rest, conversation = ingress(tmp_path)
    conversation.deadlines = []
    source = post()
    record, _ = service.outbox.reserve(
        service._envelope(source, service._authorize_source(source)),
        payload_capacity=1000, tombstone_capacity=1000,
    )
    monkeypatch.setattr(mattermost_ingress.time, "monotonic", lambda: 100.0)
    service.executor.drain()
    assert record.record_tag
    assert conversation.deadlines == [140.0, 140.0]


def test_periodic_recovery_retries_transient_waiting_work_without_a_new_event(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    source = post()
    record, _ = service.outbox.reserve(
        service._envelope(source, service._authorize_source(source)),
        payload_capacity=1000, tombstone_capacity=1000,
    )
    original_submit = conversation.submit_turn
    first = True
    delivered = threading.Event()

    def transient_once(**kwargs):
        nonlocal first
        if first:
            first = False
            raise TimeoutError
        return original_submit(**kwargs)

    def counted_post(body):
        value = Rest.create_post(rest, body)
        delivered.set()
        return value

    conversation.submit_turn = transient_once
    rest.create_post = counted_post
    service.executor.drain()
    waiting = service.outbox.get(record.record_tag)
    assert waiting is not None and waiting.state is DeliveryState.WAITING_COMMIT
    stop = service.start_periodic_recovery()
    try:
        assert delivered.wait(3), "periodic recovery did not retry the durable waiting record"
    finally:
        service.stop_periodic_recovery(stop)
    assert len(conversation.calls) == 1 and len(rest.created) == 1


def test_periodic_recovery_expires_waiting_payload_without_a_new_event(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    source = post()
    record, _ = service.outbox.reserve(
        {**service._envelope(source, service._authorize_source(source)), "payload_expires_at": 0},
        payload_capacity=1000, tombstone_capacity=1000,
    )
    transitioned = threading.Event()
    original_terminal = service.outbox.terminal

    def observed_terminal(*args, **kwargs):
        result = original_terminal(*args, **kwargs)
        transitioned.set()
        return result

    service.outbox.terminal = observed_terminal
    handle = service.start_periodic_recovery()
    try:
        assert transitioned.wait(3), "periodic recovery did not inspect expired durable work"
    finally:
        service.stop_periodic_recovery(handle)
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.EXPIRED
    assert conversation.calls == [] and rest.created == []


class _Clock:
    def __init__(self, now=0.0):
        self.now = now

    def monotonic(self):
        return self.now


class _UdsSocket:
    def __init__(self, clock: _Clock, response: bytes, *, connect_elapsed=0.0, send_elapsed=0.0, recv_elapsed=0.0):
        self.clock, self.response = clock, response
        self.connect_elapsed, self.send_elapsed, self.recv_elapsed = connect_elapsed, send_elapsed, recv_elapsed
        self.timeouts: list[float] = []
        self._sent = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, _path):
        self.clock.now += self.connect_elapsed

    def sendall(self, _wire):
        self._sent = True
        self.clock.now += self.send_elapsed

    def recv(self, _size):
        if self._sent:
            self._sent = False
            self.clock.now += self.recv_elapsed
            return self.response
        return b""


def _uds_client(*, uds_timeout_seconds=5, conversation_deadline_seconds=4):
    return ConversationUdsClient(
        SimpleNamespace(
            values={
                "uds_timeout_seconds": uds_timeout_seconds,
                "conversation_deadline_seconds": conversation_deadline_seconds,
            }
        )
    )


def _uds_response(value: dict) -> bytes:
    payload = jcs_bytes(value)
    return b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + payload


def test_uds_recomputes_the_shared_remaining_timeout_after_connect(monkeypatch):
    clock = _Clock()
    peer = _UdsSocket(
        clock, _uds_response({"ok": True}), connect_elapsed=0.2, send_elapsed=0.3, recv_elapsed=0.1
    )
    monkeypatch.setattr(mattermost_ingress.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(mattermost_ingress.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(mattermost_ingress.socket, "socket", lambda *_: peer)
    assert _uds_client()._request("POST", "/closed", {"x": "y"}, deadline=1.0) == {"ok": True}
    assert peer.timeouts[:4] == [1.0, pytest.approx(0.8), pytest.approx(0.5), pytest.approx(0.4)]


def test_uds_rejects_zero_or_negative_remaining_time_before_opening_a_socket(monkeypatch):
    clock = _Clock()
    opened = False

    def no_socket(*_):
        nonlocal opened
        opened = True
        raise AssertionError("socket must not open after the shared deadline")

    monkeypatch.setattr(mattermost_ingress.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(mattermost_ingress.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(mattermost_ingress.socket, "socket", no_socket)
    with pytest.raises(ContractError, match="conversation transport failed"):
        _uds_client()._request("POST", "/closed", {"x": "y"}, deadline=0.0)
    assert not opened


def test_uds_rejects_a_valid_response_when_decode_finishes_after_the_shared_deadline(monkeypatch):
    clock = _Clock()
    peer = _UdsSocket(clock, _uds_response({"ok": True}))
    original_decode = mattermost_ingress.load_closed_json

    def late_decode(raw):
        value = original_decode(raw)
        clock.now = 2.0
        return value

    monkeypatch.setattr(mattermost_ingress.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(mattermost_ingress.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(mattermost_ingress.socket, "socket", lambda *_: peer)
    monkeypatch.setattr(mattermost_ingress, "load_closed_json", late_decode)
    with pytest.raises(ContractError, match="conversation transport failed"):
        _uds_client()._request("POST", "/closed", {"x": "y"}, deadline=1.0)


def test_uds_rejects_when_a_slow_receive_crosses_the_absolute_deadline(monkeypatch):
    clock = _Clock()
    peer = _UdsSocket(clock, _uds_response({"ok": True}), recv_elapsed=1.1)
    monkeypatch.setattr(mattermost_ingress.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(mattermost_ingress.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(mattermost_ingress.socket, "socket", lambda *_: peer)
    with pytest.raises(ContractError, match="conversation transport failed"):
        _uds_client()._request("POST", "/closed", {"x": "y"}, deadline=1.0)


def test_submit_never_starts_turn_when_creation_exhausts_the_shared_deadline(monkeypatch):
    clock = _Clock()
    client = _uds_client(conversation_deadline_seconds=1)
    calls = []

    def exhausted_create(method, path, body=None, *, deadline=None):
        calls.append((method, path, deadline))
        clock.now = 2.0
        return {"conversation_id": "conversation", "conversation_epoch": "epoch"}

    monkeypatch.setattr(mattermost_ingress.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(client, "_request", exhausted_create)
    with pytest.raises(ContractError, match="conversation transport failed"):
        client.submit(conversation_id="conversation", client_request_id="request", message="message")
    assert calls == [("POST", "/v1/restricted/conversations/conversation", 1.0)]
