from __future__ import annotations

import base64
import hashlib
import json
import http.client
import os
import subprocess
import sys
import threading
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import unicodedata2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from restricted_runtime.contracts import ContractError, jcs_bytes
import restricted_runtime.mattermost_ingress as mattermost_ingress
from restricted_runtime.mattermost_ingress import (
    ConversationUdsClient,
    MattermostRestClient,
    TransientMattermostError,
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

UNICODE_15_1_DASH_PUNCTUATION = (
    0x002D, 0x058A, 0x05BE, 0x1400, 0x1806, 0x2010, 0x2011, 0x2012, 0x2013,
    0x2014, 0x2015, 0x2E17, 0x2E1A, 0x2E3A, 0x2E3B, 0x2E40, 0x2E5D, 0x301C,
    0x3030, 0x30A0, 0xFE31, 0xFE32, 0xFE58, 0xFE63, 0xFF0D, 0x10EAD,
)

LETTER_CONFUSABLE_COMMANDS = (
    ("\u026a", "next-appo\u026antment"), ("\u0269", "next-appo\u0269ntment"),
    ("\u0251", "next-\u0251ppointment"), ("\u04bd", "n\u04bdxt-appointment"),
    ("\u1d0f", "next-app\u1d0fintment"),
)

UNICODE_15_1_CLINICAL_SEPARATOR_CONFUSABLES = {
    "-": (0x2010, 0x2011, 0x2012, 0x2013, 0xFE58, 0x06D4, 0x2043, 0x02D7, 0x2212, 0x2796, 0x2CBA, 0x2A29, 0x2E1A, 0xFB29, 0x2238, 0x2A2A, 0xFF5E),
    "_": (0x07FA, 0xFE4D, 0xFE4E, 0xFE4F),
    " ": (0x2028, 0x2029, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2008, 0x2009, 0x200A, 0x205F, 0x00A0, 0x2007, 0x202F),
}
RESIDUAL_CLINICAL_SEPARATOR_SOURCES = (0x06D4, 0x02D7, 0x2796, 0x2CBA, 0x2A29, 0xFB29, 0x2238, 0x2A2A, 0xFF5E, 0x07FA)
RESIDUAL_CLINICAL_COMPATIBILITY_SEPARATOR_SOURCES = (0x00A8, 0x00AF, 0x00B4, 0x00B8, 0x02D8, 0x02D9, 0x02DA, 0x02DB, 0x02DC, 0x02DD, 0x037A, 0x0384, 0x0385, 0x1FBD, 0x1FBF, 0x1FC0, 0x1FC1, 0x1FCD, 0x1FCE, 0x1FCF, 0x1FDD, 0x1FDE, 0x1FDF, 0x1FED, 0x1FEE, 0x1FFD, 0x1FFE, 0x2017, 0x203E, 0x309B, 0x309C, 0xFC5E, 0xFC5F, 0xFC60, 0xFC61, 0xFC62, 0xFC63, 0xFE49, 0xFE4A, 0xFE4B, 0xFE4C, 0xFE70, 0xFE72, 0xFE74, 0xFE76, 0xFE78, 0xFE7A, 0xFE7C, 0xFE7E, 0xFFE3)
UNICODE_15_1_COMPATIBILITY_SEPARATOR_SOURCES = tuple(
    codepoint
    for codepoints in mattermost_ingress._UNICODE_15_1_CLINICAL_COMPATIBILITY_SEPARATORS.values()
    for codepoint in codepoints
)
COMBINING_MARK_O_CONFUSABLES = (0x0C02, 0x0C82, 0x0D02, 0x0D82)


def _unicode_15_1_mark_codepoints() -> tuple[int, ...]:
    assert unicodedata2.unidata_version == "15.1.0"
    return tuple(
        codepoint for codepoint in range(0x110000)
        if unicodedata2.category(chr(codepoint)).startswith("M")
    )
@pytest.fixture(autouse=True)
def portable_rest_deadline(monkeypatch):
    """HTTP shape tests run on Windows; POSIX alarm behavior is tested directly."""
    if os.name == "nt":
        monkeypatch.setattr(mattermost_ingress, "absolute_upstream_deadline", lambda _seconds: nullcontext())
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


def test_dotless_i_clinical_lookalike_is_reserved_in_private_channel(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    candidate = post(message="@restricted-bot next-appo\u0131ntment 123e4567-e89b-42d3-a456-426614174000")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls == [] and rest.created == []


@pytest.mark.parametrize(("character", "command"), LETTER_CONFUSABLE_COMMANDS)
def test_letter_confusable_clinical_lookalikes_are_reserved_in_private_channel(tmp_path, character, command):
    service, rest, conversation = ingress(tmp_path)
    candidate = post(message=f"@restricted-bot {command} 123e4567-e89b-42d3-a456-426614174000")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and rest.created == []


@pytest.mark.parametrize("character", [character for character, _command in LETTER_CONFUSABLE_COMMANDS])
def test_unrelated_letter_confusable_text_reaches_private_conversation_codepoint_exact(tmp_path, character):
    service, rest, conversation = ingress(tmp_path)
    message = f"@restricted-bot ordinary {character} text"
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls[0][2] == message and len(rest.created) == 1


@pytest.mark.parametrize(("_character", "command"), LETTER_CONFUSABLE_COMMANDS)
@pytest.mark.parametrize("ready", [False, True], ids=["waiting-commit", "ready"])
def test_legacy_letter_confusable_record_is_reclassified_before_delivery(tmp_path, ready, _character, command):
    service, rest, conversation = ingress(tmp_path)
    source = post(message=f"@restricted-bot {command} 123e4567-e89b-42d3-a456-426614174000")
    rest.posts[ROOT] = source
    record, _ = service.outbox.reserve(service._envelope(source, ROOT), payload_capacity=1000, tombstone_capacity=1000)
    if ready:
        record = service.outbox.mark_ready(record, {**record.envelope, "conversation_epoch": "epoch-one", "response": "legacy"})
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.BLOCKED
    assert conversation.calls == [] and rest.created == []


def test_frozen_unicode_15_1_letter_confusable_table_covers_each_secondary_skeleton_mapping():
    table = mattermost_ingress._UNICODE_15_1_NEXTAPPOINTMENT_CONFUSABLES
    assert sum(len(codepoints) for codepoints in table.values()) == 177
    for letter, codepoints in table.items():
        for codepoint in codepoints:
            candidate = "next-appointment".replace(letter, chr(codepoint), 1)
            assert mattermost_ingress._namespace_skeleton(candidate, secondary=True) == "next-appointment"


def test_hyphen_bullet_clinical_lookalike_is_reserved_in_private_channel(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    candidate = post(message="@restricted-bot next\u2043appointment 123e4567-e89b-42d3-a456-426614174000")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls == [] and rest.created == []


@pytest.mark.parametrize("dash", ["\u2015", "\u2e3a", "\u2e3b"])
def test_dash_punctuation_clinical_lookalikes_are_reserved_in_private_channel(tmp_path, dash):
    service, rest, conversation = ingress(tmp_path)
    candidate = post(message=f"@restricted-bot next{dash}appointment 123e4567-e89b-42d3-a456-426614174000")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls == [] and rest.created == []


def test_combined_horizontal_bar_and_dotless_i_clinical_lookalike_is_reserved_in_private_channel(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    candidate = post(message="@restricted-bot next\u2015appo\u0131ntment 123e4567-e89b-42d3-a456-426614174000")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and rest.created == []


@pytest.mark.parametrize("dash", [chr(codepoint) for codepoint in UNICODE_15_1_DASH_PUNCTUATION])
def test_unrelated_dash_punctuation_text_reaches_private_conversation_codepoint_exact(tmp_path, dash):
    service, rest, conversation = ingress(tmp_path)
    message = f"@restricted-bot agenda {dash} ordinary text"
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls[0][2] == message and len(rest.created) == 1


@pytest.mark.parametrize("dash", ["\u2015", "\u2e3a", "\u2e3b"])
@pytest.mark.parametrize("ready", [False, True], ids=["waiting-commit", "ready"])
def test_legacy_dash_punctuation_record_is_reclassified_before_delivery(tmp_path, ready, dash):
    service, rest, conversation = ingress(tmp_path)
    source = post(message=f"@restricted-bot next{dash}appointment 123e4567-e89b-42d3-a456-426614174000")
    rest.posts[ROOT] = source
    record, _ = service.outbox.reserve(service._envelope(source, ROOT), payload_capacity=1000, tombstone_capacity=1000)
    if ready:
        record = service.outbox.mark_ready(record, {**record.envelope, "conversation_epoch": "epoch-one", "response": "legacy"})
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state.name == "BLOCKED"
    assert conversation.calls == [] and rest.created == []


def test_secondary_classifier_exactly_covers_frozen_unicode_15_1_dash_punctuation():
    assert mattermost_ingress._UNICODE_15_1_DASH_PUNCTUATION == UNICODE_15_1_DASH_PUNCTUATION
    for codepoint in UNICODE_15_1_DASH_PUNCTUATION:
        assert mattermost_ingress._namespace_skeleton(f"next{chr(codepoint)}appointment", secondary=True) == "next-appointment"
    for character in ("\u2043", "\u2212"):
        assert mattermost_ingress._namespace_skeleton(f"next{character}appointment", secondary=True) == "next-appointment"


def test_frozen_unicode_15_1_separator_confusable_table_is_complete_and_hermetic():
    table = mattermost_ingress._UNICODE_15_1_CLINICAL_SEPARATOR_CONFUSABLES
    assert table == UNICODE_15_1_CLINICAL_SEPARATOR_CONFUSABLES
    assert sum(len(codepoints) for codepoints in table.values()) == 38
    for separator, codepoints in table.items():
        for codepoint in codepoints:
            assert mattermost_ingress._namespace_skeleton(
                f"next{chr(codepoint)}appointment", secondary=True
            ) == f"next{separator}appointment"
    assert 0xA4FE not in {codepoint for codepoints in table.values() for codepoint in codepoints}
    assert mattermost_ingress._clinical_command(
        "@restricted-bot next\ua4feappointment 123e4567-e89b-42d3-a456-426614174000", "restricted-bot"
    )[0] == "ordinary"


def test_frozen_unicode_15_1_compatibility_separator_table_is_complete_and_separate():
    assert unicodedata2.unidata_version == "15.1.0"
    table = mattermost_ingress._UNICODE_15_1_CLINICAL_COMPATIBILITY_SEPARATORS
    expected = {"-": [], "_": [], " ": []}

    for codepoint in range(0x110000):
        source = chr(codepoint)
        decomposed = unicodedata2.normalize("NFKD", source)
        if decomposed == source:
            continue
        derived = "".join(
            character for character in decomposed
            if not unicodedata2.category(character).startswith("M")
        )
        derived = derived.casefold().translate(mattermost_ingress._CONFUSABLES).translate(mattermost_ingress._DASHES)
        if derived in expected:
            expected[derived].append(codepoint)
    expected = {separator: tuple(codepoints) for separator, codepoints in expected.items()}
    assert {separator: frozenset(codepoints) for separator, codepoints in table.items()} == {
        separator: frozenset(codepoints) for separator, codepoints in expected.items()
    }
    assert tuple(map(len, table.values())) == (8, 6, 65)
    assert sum(map(len, table.values())) == 79
    assert mattermost_ingress._UNICODE_15_1_CLINICAL_SEPARATOR_CONFUSABLES == UNICODE_15_1_CLINICAL_SEPARATOR_CONFUSABLES
    for separator, codepoints in table.items():
        for codepoint in codepoints:
            assert mattermost_ingress._namespace_skeleton(
                f"next{chr(codepoint)}appointment", remove_marks=True,
                compatibility_separators=True,
            ) == f"next{separator}appointment"


@pytest.mark.parametrize("codepoint", RESIDUAL_CLINICAL_COMPATIBILITY_SEPARATOR_SOURCES)
def test_compatibility_separator_residuals_reserve_private_namespace_without_effects(tmp_path, codepoint):
    service, rest, conversation = ingress(tmp_path)
    message = f"@restricted-bot next{chr(codepoint)}appointment 123e4567-e89b-42d3-a456-426614174000"
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert mattermost_ingress._clinical_command(message, "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("codepoint", RESIDUAL_CLINICAL_COMPATIBILITY_SEPARATOR_SOURCES)
def test_compatibility_separator_residuals_outside_namespace_reach_private_conversation_exactly(tmp_path, codepoint):
    service, rest, conversation = ingress(tmp_path)
    message = f"@restricted-bot ordinary {chr(codepoint)} text"
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls[0][2] == message and len(rest.created) == 1


@pytest.mark.parametrize("codepoint", RESIDUAL_CLINICAL_COMPATIBILITY_SEPARATOR_SOURCES)
@pytest.mark.parametrize("ready", [False, True], ids=["waiting-commit", "ready"])
def test_legacy_compatibility_separator_records_are_reclassified_before_delivery(tmp_path, ready, codepoint):
    service, rest, conversation = ingress(tmp_path)
    source = post(message=f"@restricted-bot next{chr(codepoint)}appointment 123e4567-e89b-42d3-a456-426614174000")
    rest.posts[ROOT] = source
    record, _ = service.outbox.reserve(service._envelope(source, ROOT), payload_capacity=1000, tombstone_capacity=1000)
    if ready:
        record = service.outbox.mark_ready(record, {**record.envelope, "conversation_epoch": "epoch-one", "response": "legacy"})
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.BLOCKED
    assert conversation.calls == [] and rest.created == []


@pytest.mark.parametrize("separator_source, letter_command", [
    (0x02DB, "next-appo\u02dbntment"), (0x037A, "next-appo\u037antment"),
])
def test_compatibility_letter_collision_preserves_both_namespace_interpretations(tmp_path, separator_source, letter_command):
    separator_message = f"@restricted-bot next{chr(separator_source)}appointment 123e4567-e89b-42d3-a456-426614174000"
    assert mattermost_ingress._clinical_command(separator_message, "restricted-bot") == ("malformed", None)
    assert mattermost_ingress._clinical_command(
        f"@restricted-bot {letter_command} 123e4567-e89b-42d3-a456-426614174000", "restricted-bot"
    ) == ("malformed", None)


@pytest.mark.parametrize("separator_source", (0x2017, 0x00A8, 0x02DB))
@pytest.mark.parametrize("letter_source", (0x0131, 0x026A, 0x02DB))
def test_compatibility_and_secondary_letter_sources_compose_without_effects(
    tmp_path, separator_source, letter_source,
):
    service, rest, conversation = ingress(tmp_path)
    message = (
        f"@restricted-bot next{chr(separator_source)}appo{chr(letter_source)}ntment "
        "123e4567-e89b-42d3-a456-426614174000"
    )
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert mattermost_ingress._clinical_command(message, "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("separator_source", UNICODE_15_1_COMPATIBILITY_SEPARATOR_SOURCES)
@pytest.mark.parametrize("letter_source", COMBINING_MARK_O_CONFUSABLES)
def test_round12_compatibility_separator_and_combining_o_reserve_private_namespace_without_effects(
    tmp_path, separator_source, letter_source,
):
    service, rest, conversation = ingress(tmp_path)
    message = (
        f"@restricted-bot next{chr(separator_source)}app{chr(letter_source)}intment "
        "123e4567-e89b-42d3-a456-426614174000"
    )
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert mattermost_ingress._clinical_command(message, "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("separator_source", (0x2017, 0x0385, 0xFE49, 0xFFE3))
@pytest.mark.parametrize("ready", [False, True], ids=["waiting-commit", "ready"])
def test_round12_legacy_combining_o_records_are_reclassified_before_delivery(
    tmp_path, separator_source, ready,
):
    service, rest, conversation = ingress(tmp_path)
    source = post(message=(
        f"@restricted-bot next{chr(separator_source)}app\u0c02intment "
        "123e4567-e89b-42d3-a456-426614174000"
    ))
    rest.posts[ROOT] = source
    record, _ = service.outbox.reserve(
        service._envelope(source, ROOT), payload_capacity=1000, tombstone_capacity=1000,
    )
    if ready:
        record = service.outbox.mark_ready(
            record, {**record.envelope, "conversation_epoch": "epoch-one", "response": "legacy"},
        )
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.BLOCKED
    assert conversation.calls == [] and rest.created == []


def test_round12_combining_o_outside_namespace_reaches_private_conversation_exactly(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    message = "@restricted-bot ordinary \u2017 app\u0c02intment text"
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls[0][2] == message and len(rest.created) == 1


def test_round13_mark_source_confusables_and_every_unicode_15_1_mark_reserve_namespace():
    mark_sources = {
        letter: marked
        for letter, codepoints in mattermost_ingress._UNICODE_15_1_NEXTAPPOINTMENT_CONFUSABLES.items()
        if (marked := tuple(
            codepoint for codepoint in codepoints if unicodedata2.category(chr(codepoint)).startswith("M")
        ))
    }
    assert mark_sources == {"o": COMBINING_MARK_O_CONFUSABLES}
    marks = _unicode_15_1_mark_codepoints()
    assert tuple(
        codepoint for codepoint in range(0x110000)
        if mattermost_ingress._namespace_mark(chr(codepoint))
    ) == marks
    for source in COMBINING_MARK_O_CONFUSABLES:
        for mark in marks:
            for separator in ("-", "\u2017"):
                assert mattermost_ingress._clinical_namespace(
                    f"ne{chr(mark)}xt{separator}app{chr(source)}intment",
                    remove_marks=True, secondary=True, compatibility_separators=True,
                )
                assert mattermost_ingress._clinical_namespace(
                    f"next{separator}{chr(mark)}app{chr(source)}intment",
                    remove_marks=True, secondary=True, compatibility_separators=True,
                )


def test_round13_mark_o_sources_compose_with_every_existing_nonmark_letter_confusable():
    mappings = {
        **mattermost_ingress._CONFUSABLES,
        **mattermost_ingress._SECONDARY_CLINICAL_NONMARK_SOURCE_CONFUSABLES,
        **mattermost_ingress._SECONDARY_CLINICAL_CONFUSABLES,
    }
    companions = tuple(
        (source, letter, index)
        for source, letter in mappings.items()
        if letter in "nextappointment" and letter != "o"
        for index, character in enumerate("next-appointment")
        if character == letter
    )
    assert companions
    for mark_o_source in COMBINING_MARK_O_CONFUSABLES:
        for source, letter, index in companions:
            for separator in ("-", "\u2017"):
                candidate = list("next-appointment")
                candidate[4] = separator
                candidate[8] = chr(mark_o_source)
                candidate[index] = chr(source)
                assert mattermost_ingress._clinical_namespace(
                    "".join(candidate), remove_marks=True, secondary=True,
                    compatibility_separators=True,
                    preserve_compatibility_letter_collisions=source in {0x02DB, 0x037A},
                ), (hex(mark_o_source), hex(source), letter, index, separator)


@pytest.mark.parametrize("namespace", (
    "next-\u0430pp\u0c02intment",
    "next-app\u0c02i\u0578tment",
))
def test_round13_mark_o_nonmark_companions_reserve_private_namespace_without_effects(tmp_path, namespace):
    service, rest, conversation = ingress(tmp_path)
    message = f"@restricted-bot {namespace} 123e4567-e89b-42d3-a456-426614174000"
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert mattermost_ingress._clinical_command(message, "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("separator", ("-", "\u2017"))
@pytest.mark.parametrize("source", COMBINING_MARK_O_CONFUSABLES)
@pytest.mark.parametrize("mark_position", ("letter", "separator"))
def test_round13_mark_source_confusables_reserve_private_namespace_without_effects(
    tmp_path, separator, source, mark_position,
):
    service, rest, conversation = ingress(tmp_path)
    namespace = (
        f"ne\u0301xt{separator}app{chr(source)}intment"
        if mark_position == "letter" else f"next{separator}\u0301app{chr(source)}intment"
    )
    message = f"@restricted-bot {namespace} 123e4567-e89b-42d3-a456-426614174000"
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert mattermost_ingress._clinical_command(message, "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("ready", [False, True], ids=["waiting-commit", "ready"])
def test_round13_legacy_mark_source_confusable_record_is_reclassified_before_delivery(tmp_path, ready):
    service, rest, conversation = ingress(tmp_path)
    source = post(message=(
        "@restricted-bot next\u2017\u0301app\u0c02intment "
        "123e4567-e89b-42d3-a456-426614174000"
    ))
    rest.posts[ROOT] = source
    record, _ = service.outbox.reserve(
        service._envelope(source, ROOT), payload_capacity=1000, tombstone_capacity=1000,
    )
    if ready:
        record = service.outbox.mark_ready(
            record, {**record.envelope, "conversation_epoch": "epoch-one", "response": "legacy"},
        )
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.BLOCKED
    assert conversation.calls == [] and rest.created == []


@pytest.mark.parametrize("message", (
    "@restricted-bot ordinary \u2017 app\u0c02\u0301intment text",
    "@restricted-bot ordinary \u0430 app\u0c02intment text",
))
def test_round13_mark_source_confusable_outside_namespace_reaches_private_conversation_exactly(tmp_path, message):
    service, rest, conversation = ingress(tmp_path)
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls[0][2] == message and len(rest.created) == 1


@pytest.mark.parametrize("codepoint", RESIDUAL_CLINICAL_SEPARATOR_SOURCES)
def test_residual_separator_sources_reserve_private_namespace_without_effects(tmp_path, codepoint):
    service, rest, conversation = ingress(tmp_path)
    message = f"@restricted-bot next{chr(codepoint)}appointment 123e4567-e89b-42d3-a456-426614174000"
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert mattermost_ingress._clinical_command(message, "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("codepoint", RESIDUAL_CLINICAL_SEPARATOR_SOURCES)
def test_residual_separator_characters_outside_namespace_reach_private_conversation_exactly(tmp_path, codepoint):
    service, rest, conversation = ingress(tmp_path)
    message = f"@restricted-bot ordinary {chr(codepoint)} text"
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls[0][2] == message and len(rest.created) == 1


@pytest.mark.parametrize("codepoint", RESIDUAL_CLINICAL_SEPARATOR_SOURCES)
@pytest.mark.parametrize("ready", [False, True], ids=["waiting-commit", "ready"])
def test_legacy_residual_separator_records_are_reclassified_before_delivery(tmp_path, ready, codepoint):
    service, rest, conversation = ingress(tmp_path)
    source = post(message=f"@restricted-bot next{chr(codepoint)}appointment 123e4567-e89b-42d3-a456-426614174000")
    rest.posts[ROOT] = source
    record, _ = service.outbox.reserve(service._envelope(source, ROOT), payload_capacity=1000, tombstone_capacity=1000)
    if ready:
        record = service.outbox.mark_ready(record, {**record.envelope, "conversation_epoch": "epoch-one", "response": "legacy"})
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.BLOCKED
    assert conversation.calls == [] and rest.created == []


@pytest.mark.parametrize("message", [
    "@restricted-bot next\u02d7appo\u026antment 123e4567-e89b-42d3-a456-426614174000",
    "@restricted-bot next\u02d7appo\ufe0fintment 123e4567-e89b-42d3-a456-426614174000",
])
def test_residual_separator_composed_with_existing_secondary_forms_is_reserved(tmp_path, message):
    service, rest, conversation = ingress(tmp_path)
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert mattermost_ingress._clinical_command(message, "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and rest.created == [] and service.outbox.candidates(10) == []


def test_unrelated_hyphen_bullet_text_reaches_private_conversation_codepoint_exact(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    message = "@restricted-bot agenda \u2043 ordinary text"
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls[0][2] == message and len(rest.created) == 1


@pytest.mark.parametrize("ready", [False, True], ids=["waiting-commit", "ready"])
def test_legacy_hyphen_bullet_record_is_reclassified_before_delivery(tmp_path, ready):
    service, rest, conversation = ingress(tmp_path)
    source = post(message="@restricted-bot next\u2043appointment 123e4567-e89b-42d3-a456-426614174000")
    rest.posts[ROOT] = source
    record, _ = service.outbox.reserve(service._envelope(source, ROOT), payload_capacity=1000, tombstone_capacity=1000)
    if ready:
        record = service.outbox.mark_ready(record, {**record.envelope, "conversation_epoch": "epoch-one", "response": "legacy"})
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state.name == "BLOCKED"
    assert conversation.calls == [] and rest.created == []


def test_unrelated_dotless_i_text_reaches_private_conversation_codepoint_exact(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    message = "@restricted-bot patient notes: \u0131 is ordinary text"
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls[0][2] == message and len(rest.created) == 1


@pytest.mark.parametrize("ready", [False, True], ids=["waiting-commit", "ready"])
def test_legacy_dotless_i_private_record_is_reclassified_before_delivery(tmp_path, ready):
    service, rest, conversation = ingress(tmp_path)
    source = post(message="@restricted-bot next-appo\u0131ntment 123e4567-e89b-42d3-a456-426614174000")
    rest.posts[ROOT] = source
    record, _ = service.outbox.reserve(
        service._envelope(source, ROOT), payload_capacity=1000, tombstone_capacity=1000,
    )
    if ready:
        record = service.outbox.mark_ready(record, {**record.envelope, "conversation_epoch": "epoch-one", "response": "legacy"})
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state.name == "BLOCKED"
    assert conversation.calls == [] and rest.created == []


def test_rest_timeout_before_delivery_claim_is_retryable(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    source = post()
    record, _ = service.outbox.reserve(
        service._envelope(source, ROOT), payload_capacity=1000, tombstone_capacity=1000,
    )
    ready = service.outbox.mark_ready(record, {**record.envelope, "conversation_epoch": "epoch-one", "response": "ready"})
    rest.get_me = lambda **_kwargs: (_ for _ in ()).throw(TimeoutError)
    service.executor.drain()
    durable = service.outbox.get(ready.record_tag)
    assert durable is not None and durable.state is DeliveryState.READY
    assert conversation.calls == [] and rest.created == []


def test_rest_timeout_after_delivery_claim_is_ambiguous_without_resend(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    source = post()
    record, _ = service.outbox.reserve(
        service._envelope(source, ROOT), payload_capacity=1000, tombstone_capacity=1000,
    )
    ready = service.outbox.mark_ready(record, {**record.envelope, "conversation_epoch": "epoch-one", "response": "ready"})
    rest.create_post = lambda _body: (_ for _ in ()).throw(TimeoutError)
    service.executor.drain()
    durable = service.outbox.get(ready.record_tag)
    assert durable is not None and durable.state is DeliveryState.AMBIGUOUS
    assert conversation.calls == [] and rest.created == []


def test_ordinary_decomposed_unicode_reaches_the_conversation_byte_for_codepoint_unchanged(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    message = "@restricted-bot cafe\u0301 日本語"
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert len(conversation.calls) == 1
    assert conversation.calls[0][2] == message


def test_ordinary_unrelated_underscore_text_reaches_the_conversation_unchanged(tmp_path):
    service, rest, conversation = ingress(tmp_path)
    message = "@restricted-bot status_report for today"
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert len(conversation.calls) == 1
    assert conversation.calls[0][2] == message


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


@pytest.mark.parametrize("phase", ["resolver", "upload", "headers"], ids=["before-upload", "before-headers", "before-body"])
def test_rest_absolute_deadline_stops_later_phases_and_closes_connection(monkeypatch, tmp_path, phase):
    policy = signed_policy(tmp_path)
    policy.values["rest_timeout_seconds"] = 2
    clock = {"now": 0.0}

    class Response:
        status = 200
        reads = 0

        def getheader(self, name, default=None):
            return "application/json" if name == "Content-Type" else default

        def read(self, _size):
            type(self).reads += 1
            return b"{}"

    class Connection:
        requests = responses = closes = 0

        def __init__(self, *_args, **_kwargs):
            if phase == "resolver":
                clock["now"] += 3

        def request(self, *_args, **_kwargs):
            type(self).requests += 1
            if phase == "upload":
                clock["now"] += 3

        def getresponse(self):
            type(self).responses += 1
            if phase == "headers":
                clock["now"] += 3
            return Response()

        def close(self):
            type(self).closes += 1

    monkeypatch.setattr(mattermost_ingress.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(http.client, "HTTPSConnection", Connection)
    with pytest.raises(TransientMattermostError, match="transport"):
        MattermostRestClient(policy, "secret").get_me()
    expected = {
        "resolver": (0, 0, 0), "upload": (1, 0, 0), "headers": (1, 1, 0),
    }[phase]
    assert (Connection.requests, Connection.responses, Response.reads) == expected
    assert Connection.closes == 1


@pytest.mark.parametrize(
    "response",
    [
        (b"{}", {"Content-Type": "text/plain"}),
        (b"[]", {"Content-Type": "application/json"}),
        (b"not-json", {"Content-Type": "application/json"}),
        (b"x" * 1_048_577, {"Content-Type": "application/json"}),
    ],
)
def test_recovery_resource_http_200_shape_rejection_is_retryable(monkeypatch, tmp_path, response):
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
    with pytest.raises(TransientMattermostError, match="response"):
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


@pytest.mark.parametrize(
    "malformed",
    [
        (b"not-json", {"Content-Type": "application/json"}),
        (b'{"id":', {"Content-Type": "application/json"}),
        (b"x" * 1_048_577, {"Content-Type": "application/json"}),
        (b"{}", {"Content-Type": "text/plain"}),
        (b"[]", {"Content-Type": "application/json"}),
        (b"{}", {"Content-Type": "application/json"}),
    ],
    ids=["malformed", "truncated", "oversized", "wrong-content-type", "wrong-shape", "incomplete"],
)
@pytest.mark.parametrize("state", [DeliveryState.WAITING_COMMIT, DeliveryState.READY])
def test_recovery_http_200_unusable_resource_retries_then_delivers_once(monkeypatch, tmp_path, malformed, state):
    policy = signed_policy(tmp_path)

    class Response:
        def __init__(self, body, *, status=200, headers=None):
            self.status, self.body, self.offset = status, body, 0
            self.headers = headers or {"Content-Type": "application/json"}

        def getheader(self, name, default=None):
            return self.headers.get(name, default)

        def read(self, size=-1):
            if size < 0:
                size = len(self.body) - self.offset
            result = self.body[self.offset:self.offset + size]
            self.offset += len(result)
            return result

    class Connection:
        malformed_response = None
        bad_once = True
        requests = []
        last_request = None

        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, method, path, body=None, **_kwargs):
            type(self).requests.append((method, path))
            type(self).last_request = (method, path, body)

        def getresponse(self):
            if type(self).bad_once:
                type(self).bad_once = False
                return type(self).malformed_response
            method, path, body = type(self).last_request
            if path == "/api/v4/users/me":
                value = {"id": BOT, "username": "restricted-bot"}
            elif path == "/api/v4/posts/" + ROOT:
                value = post()
            elif path == "/api/v4/channels/" + CHANNEL:
                value = {"id": CHANNEL, "team_id": TEAM, "type": "P"}
            elif path.startswith("/api/v4/channels/" + CHANNEL + "/members/"):
                value = {"channel_id": CHANNEL, "user_id": path.rsplit("/", 1)[1]}
            elif (method, path) == ("POST", "/api/v4/posts"):
                value = {"id": "reply000000000000000000000", **json.loads(body)}
            else:
                raise AssertionError((method, path))
            return Response(jcs_bytes(value))

        def close(self):
            pass

    Connection.malformed_response = Response(malformed[0], headers=malformed[1])
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
    if state is DeliveryState.READY:
        record = outbox.mark_ready(record, {
            **record.envelope, "conversation_epoch": "epoch-one", "response": "synthetic response",
        })
    try:
        service.executor.drain()
        retryable = outbox.get(record.record_tag)
        assert retryable is not None and retryable.state is state
        assert retryable.generation == record.generation and retryable.envelope == record.envelope
        assert Connection.requests == [("GET", "/api/v4/users/me")]
        assert conversation.calls == []
        service.executor.drain()
        delivered = outbox.get(record.record_tag)
        assert delivered is not None and delivered.state is DeliveryState.DELIVERED
        assert len(conversation.calls) == (1 if state is DeliveryState.WAITING_COMMIT else 0)
        request_count = len(Connection.requests)
        service.executor.drain()
        assert len(Connection.requests) == request_count
        assert len(conversation.calls) == (1 if state is DeliveryState.WAITING_COMMIT else 0)
    finally:
        outbox.close()


@pytest.mark.parametrize("status", [403, 404])
def test_recovery_http_authorization_rejection_blocks_without_inference(monkeypatch, tmp_path, status):
    policy = signed_policy(tmp_path)

    class Response:
        def __init__(self):
            self.status = status

        def getheader(self, _name, default=None):
            return default

        def read(self, _size=-1):
            return b""

    class Connection:
        requests = []

        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, method, path, **_kwargs):
            type(self).requests.append((method, path))

        def getresponse(self):
            return Response()

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
        assert Connection.requests == [("GET", "/api/v4/users/me")]
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


@pytest.mark.parametrize("status", ["FAILED", "REJECTED", "INDETERMINATE", "RECEIVED", "REQUEST_COMMITTED", "INFERENCE_PENDING", "RESPONSE_RECEIVED"])
def test_submit_turn_accepts_exact_known_status_documents(monkeypatch, status):
    client = _uds_client()
    status_document = {
        "schema_version": "restricted-turn-status.v1", "turn_id": "turn-id",
        "conversation_epoch": "epoch", "status": status,
    }
    monkeypatch.setattr(client, "_request", lambda *_args, **_kwargs: status_document)
    assert client.submit_turn(
        conversation_id="conversation", conversation_epoch="epoch", client_request_id="request", message="message"
    ) == status_document


def test_legacy_submit_uses_the_same_exact_status_validator(monkeypatch):
    client = _uds_client()
    responses = iter((
        {"conversation_id": "conversation", "conversation_epoch": "epoch"},
        {"schema_version": "restricted-turn-status.v1", "turn_id": "turn-id", "conversation_epoch": "epoch", "status": "FAILED"},
    ))
    monkeypatch.setattr(client, "_request", lambda *_args, **_kwargs: next(responses))
    assert client.submit(conversation_id="conversation", client_request_id="request", message="message")["status"] == "FAILED"


def test_submit_turn_preserves_the_exact_committed_result_contract(monkeypatch):
    client = _uds_client()
    committed = {
        "schema_version": "restricted-turn-result.v1", "turn_id": "turn-id",
        "conversation_epoch": "epoch", "status": "COMMITTED", "message": "committed response",
    }
    monkeypatch.setattr(client, "_request", lambda *_args, **_kwargs: committed)
    assert client.submit_turn(
        conversation_id="conversation", conversation_epoch="epoch", client_request_id="request", message="message"
    ) == committed


@pytest.mark.parametrize("result", [
    {"schema_version": "restricted-turn-result.v1", "turn_id": "turn", "conversation_epoch": "epoch", "status": "COMMITTED"},
    {"schema_version": "restricted-turn-result.v1", "turn_id": "turn", "conversation_epoch": "epoch", "status": "FAILED", "message": "wrong"},
    {"schema_version": "restricted-turn-status.v1", "turn_id": "turn", "conversation_epoch": "epoch", "status": "FAILED", "message": "wrong"},
    {"schema_version": "restricted-turn-status.v1", "turn_id": "turn", "conversation_epoch": "epoch", "status": "COMMITTED"},
    {"schema_version": "restricted-turn-status.v1", "turn_id": "turn", "conversation_epoch": "other", "status": "FAILED"},
    {"schema_version": "restricted-turn-status.v1", "turn_id": "", "conversation_epoch": "epoch", "status": "FAILED"},
    {"schema_version": "restricted-turn-status.v1", "turn_id": "turn", "conversation_epoch": "e" * 129, "status": "FAILED"},
    {"schema_version": "unknown", "turn_id": "turn", "conversation_epoch": "epoch", "status": "FAILED"},
])
def test_submit_turn_rejects_cross_product_and_binding_mismatches(monkeypatch, result):
    client = _uds_client()
    monkeypatch.setattr(client, "_request", lambda *_args, **_kwargs: result)
    with pytest.raises(ContractError, match="conversation turn response rejected"):
        client.submit_turn(conversation_id="conversation", conversation_epoch="epoch", client_request_id="request", message="message")


@pytest.mark.parametrize("status", ["FAILED", "REJECTED", "INDETERMINATE"])
def test_terminal_conversation_status_fails_outbox_once_without_recovery_resubmit(tmp_path, status):
    service, rest, conversation = ingress(tmp_path)
    source = post()
    record, _ = service.outbox.reserve(
        service._envelope(source, service._authorize_source(source)), payload_capacity=1000, tombstone_capacity=1000,
    )
    calls = 0

    def terminal_status(**kwargs):
        nonlocal calls
        calls += 1
        return {
            "schema_version": "restricted-turn-status.v1", "turn_id": "turn-id",
            "conversation_epoch": kwargs["conversation_epoch"], "status": status,
        }

    conversation.submit_turn = terminal_status
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.FAILED and calls == 1 and rest.created == []
    service.executor.drain()
    assert calls == 1


@pytest.mark.parametrize("status", ["RECEIVED", "REQUEST_COMMITTED", "INFERENCE_PENDING", "RESPONSE_RECEIVED"])
def test_active_conversation_status_keeps_outbox_waiting_for_idempotent_recovery(tmp_path, status):
    service, rest, conversation = ingress(tmp_path)
    source = post()
    record, _ = service.outbox.reserve(
        service._envelope(source, service._authorize_source(source)), payload_capacity=1000, tombstone_capacity=1000,
    )
    calls = 0

    def active_status(**kwargs):
        nonlocal calls
        calls += 1
        return {
            "schema_version": "restricted-turn-status.v1", "turn_id": "turn-id",
            "conversation_epoch": kwargs["conversation_epoch"], "status": status,
        }

    conversation.submit_turn = active_status
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.WAITING_COMMIT and calls == 1 and rest.created == []
    service.executor.drain()
    assert calls == 2


@pytest.mark.parametrize("status", ["FAILED", "INDETERMINATE"])
def test_real_conversation_service_terminal_result_matches_the_status_wire(status):
    from restricted_runtime.conversation import ConversationService
    from restricted_runtime.contracts import ProviderResult, TurnRequest
    from restricted_runtime.crypto import LocalHmacKey
    from test_conversation_execution import Keys, Store, policy

    class TerminalGateway:
        def infer_once(self, envelope, principal):
            return ProviderResult(status)

    runtime = ConversationService(
        Store(), TerminalGateway(), LocalHmacKey("k", "v", b"x" * 32), Keys(), policy(), "tenant"
    )
    request = TurnRequest.parse({
        "schema_version": "restricted-turn.v1", "client_request_id": "00000000-0000-0000-0000-000000000001",
        "conversation_epoch": "epoch", "message": "hello",
    })
    result = runtime.submit(request, principal="svc@example.com", conversation_id="conversation")
    assert result == {
        "schema_version": "restricted-turn-status.v1", "turn_id": result["turn_id"],
        "conversation_epoch": "epoch", "status": status,
    }
