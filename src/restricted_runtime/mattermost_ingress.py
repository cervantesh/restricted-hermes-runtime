"""Standalone restricted Mattermost edge; no normal Hermes runtime is imported."""
from __future__ import annotations

import http.client
import hashlib
import json
import logging
import re
import socket
import ssl
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

from .contracts import ClinicalAuthorizationDenied, ContractError, TurnState, jcs_bytes, load_closed_json
from .mattermost_outbox import CLINICAL_OUTBOX_SCHEMA, DeliveryState, MattermostOutbox, OutboxRecord
from .mattermost_policy import MAX_EVENT_BYTES, MattermostPolicy
from .upstream_deadline import absolute_upstream_deadline

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
    def get_channel_members(self, channel_id: str, *, definitive: bool = False) -> list[dict[str, Any]]: ...
    def create_post(self, body: dict[str, Any]) -> dict[str, Any]: ...


class ConversationApi(Protocol):
    def ready(self) -> dict[str, Any]: ...
    def submit(self, *, conversation_id: str, client_request_id: str, message: str) -> dict[str, Any]: ...
    def create_conversation(self, *, conversation_id: str, deadline: float | None = None) -> dict[str, Any]: ...
    def submit_turn(self, *, conversation_id: str, conversation_epoch: str, client_request_id: str, message: str, deadline: float | None = None) -> dict[str, Any]: ...


class ClinicalApi(Protocol):
    def query(self, request: dict[str, Any]) -> dict[str, Any]: ...
    def reauthorize_delivery(self, request: dict[str, Any]) -> dict[str, Any]: ...


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


def _complete_post_response(value: Any) -> bool:
    return (
        isinstance(value, dict) and _POST_REQUIRED_FIELDS <= set(value)
        and all(isinstance(value.get(name), str) for name in ("id", "root_id", "channel_id", "user_id", "message", "type"))
        and isinstance(value.get("edit_at"), int) and not isinstance(value.get("edit_at"), bool)
        and isinstance(value.get("delete_at"), int) and not isinstance(value.get("delete_at"), bool)
    )


def _incomplete_resource_error(definitive: bool, message: str) -> ContractError:
    return TransientMattermostError(message) if definitive else ContractError(message)


_PATIENT_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_DASHES = str.maketrans({"\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-", "\u2212": "-"})
_CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u0456": "i", "\u043c": "m", "\u043e": "o", "\u0440": "p",
    "\u0442": "t", "\u0445": "x", "\u03b1": "a", "\u03b9": "i", "\u03bf": "o", "\u03c1": "p", "\u03c4": "t", "\u03c7": "x",
})
# Unicode 15.1.0 UnicodeData.txt, General_Category=Pd:
# https://www.unicode.org/Public/15.1.0/ucd/UnicodeData.txt
_UNICODE_15_1_DASH_PUNCTUATION = (
    0x002D, 0x058A, 0x05BE, 0x1400, 0x1806, 0x2010, 0x2011, 0x2012, 0x2013,
    0x2014, 0x2015, 0x2E17, 0x2E1A, 0x2E3A, 0x2E3B, 0x2E40, 0x2E5D, 0x301C,
    0x3030, 0x30A0, 0xFE31, 0xFE32, 0xFE58, 0xFE63, 0xFF0D, 0x10EAD,
)
_SECONDARY_CLINICAL_CONFUSABLES = str.maketrans({
    **{chr(codepoint): "-" for codepoint in _UNICODE_15_1_DASH_PUNCTUATION},
    "\u0131": "i", "\u2043": "-", "\u2212": "-",
})
# Unicode 15.1.0 confusables.txt: single-source mappings whose skeleton
# resolves to one clinical namespace separator.  This detection-only mapping
# runs before NFKC/casefold so source identity is not lost.
# https://www.unicode.org/Public/security/15.1.0/confusables.txt
_UNICODE_15_1_CLINICAL_SEPARATOR_CONFUSABLES = {
    "-": (
        0x2010, 0x2011, 0x2012, 0x2013, 0xFE58, 0x06D4, 0x2043, 0x02D7,
        0x2212, 0x2796, 0x2CBA, 0x2A29, 0x2E1A, 0xFB29, 0x2238, 0x2A2A,
        0xFF5E,
    ),
    "_": (0x07FA, 0xFE4D, 0xFE4E, 0xFE4F),
    " ": (
        0x2028, 0x2029, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
        0x2005, 0x2006, 0x2008, 0x2009, 0x200A, 0x205F, 0x00A0, 0x2007,
        0x202F,
    ),
}
_SECONDARY_CLINICAL_SOURCE_SEPARATORS = str.maketrans({
    codepoint: separator
    for separator, codepoints in _UNICODE_15_1_CLINICAL_SEPARATOR_CONFUSABLES.items()
    for codepoint in codepoints
})
# Unicode 15.1.0 UnicodeData.txt: compatibility-decomposition sources that
# resolve to exactly one reserved separator in the namespace detector.  This
# intentionally remains separate from the confusables.txt corpus above.
# https://www.unicode.org/Public/15.1.0/ucd/UnicodeData.txt
_UNICODE_15_1_CLINICAL_COMPATIBILITY_SEPARATORS = {
    "-": (0x2011, 0x207B, 0x208B, 0xFE31, 0xFE32, 0xFE58, 0xFE63, 0xFF0D),
    "_": (0xFE33, 0xFE34, 0xFE4D, 0xFE4E, 0xFE4F, 0xFF3F),
    " ": (
        0x00A0, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
        0x2007, 0x2008, 0x2009, 0x200A, 0x202F, 0x205F, 0x3000, 0x00A8,
        0x00AF, 0x00B4, 0x00B8, 0x02D8, 0x02D9, 0x02DA, 0x02DB, 0x02DC,
        0x02DD, 0x037A, 0x0384, 0x0385, 0x1FBD, 0x1FBF, 0x1FC0, 0x1FC1,
        0x1FCD, 0x1FCE, 0x1FCF, 0x1FDD, 0x1FDE, 0x1FDF, 0x1FED, 0x1FEE,
        0x1FFD, 0x1FFE, 0x2017, 0x203E, 0x309B, 0x309C, 0xFC5E, 0xFC5F,
        0xFC60, 0xFC61, 0xFC62, 0xFC63, 0xFE49, 0xFE4A, 0xFE4B, 0xFE4C,
        0xFE70, 0xFE72, 0xFE74, 0xFE76, 0xFE78, 0xFE7A, 0xFE7C, 0xFE7E,
        0xFFE3,
    ),
}
_UNICODE_15_1_CLINICAL_COMPATIBILITY_SEPARATOR_SOURCES = frozenset(
    codepoint
    for codepoints in _UNICODE_15_1_CLINICAL_COMPATIBILITY_SEPARATORS.values()
    for codepoint in codepoints
)
_CLINICAL_COMPATIBILITY_SEPARATOR_SKELETONS = str.maketrans({
    codepoint: separator
    for separator, codepoints in _UNICODE_15_1_CLINICAL_COMPATIBILITY_SEPARATORS.items()
    for codepoint in codepoints
})
_CLINICAL_COMPATIBILITY_SECONDARY_COLLISION = "\uE000"
_CLINICAL_COMPATIBILITY_SECONDARY_SEPARATOR_SKELETONS = str.maketrans({
    codepoint: (
        _CLINICAL_COMPATIBILITY_SECONDARY_COLLISION
        if codepoint in {0x02DB, 0x037A} else separator
    )
    for separator, codepoints in _UNICODE_15_1_CLINICAL_COMPATIBILITY_SEPARATORS.items()
    for codepoint in codepoints
})
# Unicode 15.1.0 confusables.txt: single-source, single-ASCII-letter mappings
# for letters in "nextappointment" that remain after NFKC/casefold and the
# primary namespace maps. This is detection-only, not a general parser.
# https://www.unicode.org/Public/security/15.1.0/confusables.txt
_UNICODE_15_1_NEXTAPPOINTMENT_CONFUSABLES = {
    "a": (0x237A, 0x0251, 0x13AA, 0x15C5, 0xA4EE, 0x16F40, 0x102A0),
    "e": (0x212E, 0xAB32, 0x04BD, 0x22FF, 0x0395, 0x1D6AC, 0x1D6E6, 0x1D720, 0x1D75A, 0x1D794, 0x2D39, 0x13AC, 0xA4F0, 0x118A6, 0x118AE, 0x10286),
    "i": (0x02DB, 0x2373, 0x0131, 0x1D6A4, 0x026A, 0x0269, 0x037A, 0xA647, 0x04CF, 0xAB75, 0x13A5, 0x118C3),
    "m": (0x039C, 0x1D6B3, 0x1D6ED, 0x1D727, 0x1D761, 0x1D79B, 0x03FA, 0x2C98, 0x13B7, 0x15F0, 0x16D6, 0xA4DF, 0x102B0, 0x10311),
    "n": (0x0578, 0x057C, 0x039D, 0x1D6B4, 0x1D6EE, 0x1D728, 0x1D762, 0x1D79C, 0x2C9A, 0xA4E0, 0x10513),
    "o": (0x0C02, 0x0C82, 0x0D02, 0x0D82, 0x0966, 0x0A66, 0x0AE6, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66, 0x0E50, 0x0ED0, 0x1040, 0x0665, 0x06F5, 0x1D0F, 0x1D11, 0xAB3D, 0x03C3, 0x1D6D4, 0x1D70E, 0x1D748, 0x1D782, 0x1D7BC, 0x2C9F, 0x10FF, 0x0585, 0x05E1, 0x0647, 0x1EE24, 0x1EE64, 0x1EE84, 0xFEEB, 0xFEEC, 0xFEEA, 0xFEE9, 0x06BE, 0xFBAC, 0xFBAD, 0xFBAB, 0xFBAA, 0x06C1, 0xFBA8, 0xFBA9, 0xFBA7, 0xFBA6, 0x06D5, 0x0D20, 0x101D, 0x104EA, 0x118C8, 0x118D7, 0x1042C, 0x0030, 0x07C0, 0x09E6, 0x0B66, 0x3007, 0x114D0, 0x118E0, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1FBF0, 0x2C9E, 0x0555, 0x2D54, 0x12D0, 0x0B20, 0x104C2, 0xA4F3, 0x118B5, 0x10292, 0x102AB, 0x10404, 0x10516),
    "p": (0x2374, 0x2CA3, 0x2CA2, 0x13E2, 0x146D, 0xA4D1, 0x10295),
    "t": (0x22A4, 0x27D9, 0x1F768, 0x2CA6, 0x13A2, 0xA4D4, 0x16F0A, 0x118BC, 0x10297, 0x102B1, 0x10315),
    "x": (0x166E, 0x00D7, 0x292B, 0x292C, 0x2A2F, 0x1541, 0x157D, 0x166D, 0x2573, 0x10322, 0x118EC, 0xA7B3, 0x2CAC, 0x2D5D, 0x16B7, 0xA4EB, 0x10290, 0x102B4, 0x10317, 0x10527),
}
_SECONDARY_CLINICAL_SOURCE_CONFUSABLES = str.maketrans({
    ord(chr(codepoint)): letter
    for letter, codepoints in _UNICODE_15_1_NEXTAPPOINTMENT_CONFUSABLES.items()
    for codepoint in codepoints
})
# Unicode 15.1.0 DerivedCoreProperties.txt, Default_Ignorable_Code_Point:
# https://www.unicode.org/Public/15.1.0/ucd/DerivedCoreProperties.txt
_UNICODE_15_1_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180D), (0x180E, 0x180E), (0x180F, 0x180F),
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2065, 0x2065),
    (0x2066, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0000), (0xE0001, 0xE0001), (0xE0002, 0xE001F), (0xE0020, 0xE007F),
    (0xE0080, 0xE00FF), (0xE0100, 0xE01EF), (0xE01F0, 0xE0FFF),
)


def _namespace_ignorable(character: str) -> bool:
    if unicodedata.category(character) == "Cf":
        return True
    codepoint = ord(character)
    return any(start <= codepoint <= end for start, end in _UNICODE_15_1_DEFAULT_IGNORABLE_RANGES)


def _namespace_skeleton(
    value: str, *, remove_marks: bool = False, secondary: bool = False,
    compatibility_separators: bool = False, preserve_compatibility_letter_collisions: bool = False,
) -> str:
    if compatibility_separators:
        # Each replacement is the source-local UnicodeData compatibility
        # decomposition after NFKC and mark removal.  Do not strip marks from
        # unrelated characters in the same message.
        value = value.translate(
            _CLINICAL_COMPATIBILITY_SECONDARY_SEPARATOR_SKELETONS
            if secondary and preserve_compatibility_letter_collisions
            else _CLINICAL_COMPATIBILITY_SEPARATOR_SKELETONS
        )
    if secondary:
        value = value.translate(_SECONDARY_CLINICAL_SOURCE_SEPARATORS)
    if remove_marks:
        value = unicodedata.normalize("NFD", value)
        value = "".join(character for character in value if not unicodedata.category(character).startswith("M"))
    if secondary:
        value = value.translate(_SECONDARY_CLINICAL_SOURCE_CONFUSABLES)
    normalized = unicodedata.normalize("NFKC", value).casefold().translate(_CONFUSABLES).translate(_DASHES)
    if secondary:
        normalized = normalized.translate(_SECONDARY_CLINICAL_CONFUSABLES)
    return "".join(character for character in normalized if not _namespace_ignorable(character))


def _clinical_namespace(
    value: str, *, remove_marks: bool = False, secondary: bool = False,
    compatibility_separators: bool = False, preserve_compatibility_letter_collisions: bool = False,
) -> bool:
    skeleton = _namespace_skeleton(
        value, remove_marks=remove_marks, secondary=secondary,
        compatibility_separators=compatibility_separators,
        preserve_compatibility_letter_collisions=preserve_compatibility_letter_collisions,
    )
    pattern = (
        rf"next[-_\s{_CLINICAL_COMPATIBILITY_SECONDARY_COLLISION}]+appo"
        rf"[i{_CLINICAL_COMPATIBILITY_SECONDARY_COLLISION}]ntment"
        if preserve_compatibility_letter_collisions
        else r"next[-_\s]+appointment"
    )
    return re.search(pattern, skeleton) is not None


def _clinical_command(message: str, bot_username: str) -> tuple[str, str | None]:
    """Return (ordinary|malformed|valid, patient id), reserving confusable forms."""
    mention = re.compile(rf"(?<![A-Za-z0-9._-])@{re.escape(bot_username)}(?![A-Za-z0-9._-])")
    matches = list(mention.finditer(message))
    if len(matches) != 1:
        return ("malformed", None) if any((
            _clinical_namespace(message), _clinical_namespace(message, remove_marks=True),
            _clinical_namespace(message, secondary=True), _clinical_namespace(message, remove_marks=True, secondary=True),
            _clinical_namespace(message, remove_marks=True, compatibility_separators=True),
            _clinical_namespace(message, secondary=True, compatibility_separators=True),
            _clinical_namespace(message, secondary=True, compatibility_separators=True,
                                preserve_compatibility_letter_collisions=True),
            _clinical_namespace(message, remove_marks=True, secondary=True, compatibility_separators=True),
            _clinical_namespace(message, remove_marks=True, secondary=True, compatibility_separators=True,
                                preserve_compatibility_letter_collisions=True),
        )) else ("ordinary", None)
    match = matches[0]
    body = (message[:match.start()] + message[match.end():]).strip()
    if not any((
        _clinical_namespace(body), _clinical_namespace(body, remove_marks=True),
        _clinical_namespace(body, secondary=True), _clinical_namespace(body, remove_marks=True, secondary=True),
        _clinical_namespace(body, remove_marks=True, compatibility_separators=True),
        _clinical_namespace(body, secondary=True, compatibility_separators=True),
        _clinical_namespace(body, secondary=True, compatibility_separators=True,
                            preserve_compatibility_letter_collisions=True),
        _clinical_namespace(body, remove_marks=True, secondary=True, compatibility_separators=True),
        _clinical_namespace(body, remove_marks=True, secondary=True, compatibility_separators=True,
                            preserve_compatibility_letter_collisions=True),
    )):
        return "ordinary", None
    if any(unicodedata.category(character).startswith("M") for character in body):
        return "malformed", None
    exact = re.fullmatch(r"next-appointment ([0-9a-f-]{36})", body)
    if exact is None or not _PATIENT_UUID.fullmatch(exact.group(1)):
        return "malformed", None
    try:
        if str(uuid.UUID(exact.group(1))) != exact.group(1):
            return "malformed", None
    except ValueError:
        return "malformed", None
    return "valid", exact.group(1)


_CLINICAL_WIRE_FIELDS = {
    "mattermostActorId", "patientId", "requestId", "integrationId",
    "clinicalPolicyId", "policyEpoch", "policyDigest",
}
_CLINICAL_APPOINTMENT_STATUSES = {
    "scheduled", "confirmed", "checked_in", "in_progress", "in_service", "post_procedure",
    "ready_for_checkout", "awaiting_payment", "payment_collected", "checked_out",
}


def _valid_clinical_wire_request(body: dict[str, Any], *, delivery: bool = False) -> bool:
    fields = _CLINICAL_WIRE_FIELDS | ({"responseDigest"} if delivery else set())
    return (
        set(body) == fields
        and isinstance(body.get("mattermostActorId"), str)
        and re.fullmatch(r"[a-z0-9]{26}", body["mattermostActorId"]) is not None
        and isinstance(body.get("patientId"), str) and _PATIENT_UUID.fullmatch(body["patientId"]) is not None
        and isinstance(body.get("requestId"), str) and re.fullmatch(r"[A-Za-z0-9_-]{8,64}", body["requestId"]) is not None
        and isinstance(body.get("integrationId"), str) and re.fullmatch(r"[A-Za-z0-9_-]{8,64}", body["integrationId"]) is not None
        and body.get("clinicalPolicyId") == "clinical-read-v1"
        and isinstance(body.get("policyEpoch"), str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", body["policyEpoch"]) is not None
        and isinstance(body.get("policyDigest"), str) and re.fullmatch(r"[0-9a-f]{64}", body["policyDigest"]) is not None
        and (not delivery or (
            isinstance(body.get("responseDigest"), str)
            and re.fullmatch(r"[0-9a-f]{64}", body["responseDigest"]) is not None
        ))
    )


def _valid_clinical_appointment(appointment: Any) -> bool:
    if (
        not isinstance(appointment, dict) or set(appointment) != {"id", "date", "time", "duration", "status"}
        or not isinstance(appointment.get("id"), str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", appointment["id"]) is None
        or not isinstance(appointment.get("date"), str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", appointment["date"]) is None
        or not isinstance(appointment.get("time"), str) or re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", appointment["time"]) is None
        or not isinstance(appointment.get("duration"), int) or isinstance(appointment["duration"], bool)
        or not 1 <= appointment["duration"] <= 1440 or appointment.get("status") not in _CLINICAL_APPOINTMENT_STATUSES
    ):
        return False
    try:
        datetime.strptime(appointment["date"], "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _clinical_response_digest(result: dict[str, Any]) -> str:
    """Hash the frozen HRH projection using its explicit insertion order."""
    appointment = result.get("appointment")
    closed: dict[str, Any] = {
        "clinicTimezone": result.get("clinicTimezone"),
        "appointment": None,
    }
    if isinstance(appointment, dict):
        closed["appointment"] = {
            "id": appointment.get("id"),
            "date": appointment.get("date"),
            "time": appointment.get("time"),
            "duration": appointment.get("duration"),
            "status": appointment.get("status"),
        }
    raw = json.dumps(closed, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class Ingress:
    """Reserve authenticated events; the sole executor owns UDS and REST effects."""
    def __init__(self, policy: MattermostPolicy, rest: MattermostApi, conversation: ConversationApi, outbox: MattermostOutbox, *, clinical: ClinicalApi | None = None):
        policy.validate()
        self.policy, self.rest, self.conversation, self.outbox, self.clinical = policy, rest, conversation, outbox, clinical
        if ("clinical_bindings" in policy.values) != (clinical is not None):
            raise ContractError("Mattermost clinical client/policy binding rejected")
        self._authenticated = False
        self.executor = SerializedDeliveryExecutor(self)

    def preflight(self) -> None:
        self._bot_identity()
        clinical_channels = {item["channel_id"] for item in self.policy.values.get("clinical_bindings", [])}
        if any(channel_id not in clinical_channels for channel_id in self.policy.values["allowed_channel_ids"]):
            self._readiness_binding()
        for channel_id in self.policy.values["allowed_channel_ids"]:
            if channel_id in clinical_channels:
                self._direct_channel(channel_id)
                binding = next(item for item in self.policy.values["clinical_bindings"] if item["channel_id"] == channel_id)
                self._exact_direct_roster(channel_id, binding["actor_id"])
            else:
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
        if not isinstance(me, dict) or not all(isinstance(me.get(name), str) for name in ("id", "username")):
            raise _incomplete_resource_error(definitive, "Mattermost bot identity response incomplete")
        if me["id"] != self.policy.values["bot_user_id"] or me["username"] != self.policy.values["bot_username"]:
            error = DefinitiveMattermostError if definitive else ContractError
            raise error("Mattermost bot identity rejected")

    def mark_authenticated(self) -> None:
        self._authenticated = True

    def _private_channel(self, channel_id: str, *, definitive: bool = False) -> dict[str, Any]:
        channel = self.rest.get_channel(channel_id, definitive=definitive)
        if not isinstance(channel, dict) or not all(isinstance(channel.get(name), str) for name in ("id", "team_id", "type")):
            raise _incomplete_resource_error(definitive, "Mattermost private channel response incomplete")
        if (
            channel["id"] != channel_id or channel["team_id"] != self.policy.values["team_id"]
            or channel["type"] != "P" or channel_id not in self.policy.values["allowed_channel_ids"]
        ):
            error = DefinitiveMattermostError if definitive else ContractError
            raise error("Mattermost private channel binding rejected")
        return channel

    def _member(self, channel_id: str, user_id: str, *, definitive: bool = False) -> dict[str, Any]:
        member = self.rest.get_channel_member(channel_id, user_id, definitive=definitive)
        if not isinstance(member, dict) or not all(isinstance(member.get(name), str) for name in ("channel_id", "user_id")):
            raise _incomplete_resource_error(definitive, "Mattermost channel membership response incomplete")
        if member["channel_id"] != channel_id or member["user_id"] != user_id:
            error = DefinitiveMattermostError if definitive else ContractError
            raise error("Mattermost channel membership rejected")
        return member

    def _direct_channel(self, channel_id: str, *, definitive: bool = False) -> dict[str, Any]:
        channel = self.rest.get_channel(channel_id, definitive=definitive)
        if not isinstance(channel, dict) or not all(isinstance(channel.get(name), str) for name in ("id", "type")):
            raise _incomplete_resource_error(definitive, "Mattermost direct channel response incomplete")
        if channel["id"] != channel_id or channel["type"] != "D":
            error = DefinitiveMattermostError if definitive else ContractError
            raise error("Mattermost direct channel binding rejected")
        return channel

    def _exact_direct_roster(self, channel_id: str, actor_id: str, *, definitive: bool = False) -> None:
        members = self.rest.get_channel_members(channel_id, definitive=definitive)
        expected = {actor_id, self.policy.values["bot_user_id"]}
        if not isinstance(members, list) or not all(
            isinstance(item, dict) and all(isinstance(item.get(name), str) for name in ("channel_id", "user_id"))
            for item in members
        ):
            raise _incomplete_resource_error(definitive, "Mattermost direct channel roster response incomplete")
        if len(members) != 2 or {item["user_id"] for item in members if item["channel_id"] == channel_id} != expected:
            error = DefinitiveMattermostError if definitive else ContractError
            raise error("Mattermost direct channel roster rejected")

    def _clinical_binding(self, channel_id: str, actor_id: str) -> bool:
        return {"channel_id": channel_id, "actor_id": actor_id} in self.policy.values.get("clinical_bindings", [])

    def _authorize_clinical_source(self, post: dict[str, Any], *, definitive: bool = False) -> None:
        self.policy.validate()
        if (
            post.get("root_id") != "" or not _ordinary(post, policy=self.policy, require_mention=True)
            or not self._clinical_binding(post.get("channel_id", ""), post.get("user_id", ""))
        ):
            error = DefinitiveMattermostError if definitive else ContractError
            raise error("Mattermost clinical source binding rejected")
        self._direct_channel(post["channel_id"], definitive=definitive)
        self._exact_direct_roster(post["channel_id"], post["user_id"], definitive=definitive)

    def _validated_root(self, post: dict[str, Any], *, definitive: bool = False) -> tuple[str, dict[str, Any]]:
        root_id = post["root_id"] or post["id"]
        root = self.rest.get_post(root_id, definitive=definitive)
        if isinstance(root, dict) and "file_ids" not in root:
            root = {**root, "file_ids": []}
        if not _complete_post_response(root) or not isinstance(root.get("file_ids"), list):
            raise _incomplete_resource_error(definitive, "Mattermost root response incomplete")
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

    def _clinical_envelope(self, post: dict[str, Any], patient_id: str) -> dict[str, Any]:
        expires = int(datetime.fromisoformat(self.policy.values["expires_at"].replace("Z", "+00:00")).timestamp())
        now = int(time.time())
        return {
            "schema_version": CLINICAL_OUTBOX_SCHEMA,
            "tenant_id": self.policy.values["tenant_id"], "origin": self.policy.origin,
            "channel_id": post["channel_id"], "root_id": post["id"], "source_id": post["id"],
            "actor_id": post["user_id"], "patient_id": patient_id, "operation": "next-appointment",
            "request_id": request_identity(self.policy.values["tenant_id"], self.policy.origin, post["channel_id"], post["id"]),
            "source_message": post["message"],
            "integration_id": self.policy.values["clinical_integration_id"],
            "clinical_policy_id": self.policy.values["clinical_policy_id"],
            "policy_epoch": self.policy.values["policy_epoch"], "policy_digest": self.policy.digest,
            "key_fingerprint": self.policy.values["outbox_key_fingerprint"],
            "policy_expires_at": expires,
            "payload_expires_at": min(expires, now + self.policy.values["outbox_payload_retention_seconds"]),
            "clinic_timezone": None, "appointment": None, "response": None,
            "response_digest": None,
            "pending_post_id": str(uuid.uuid5(_NAMESPACE, "clinical-delivery\x00" + post["id"])),
            "returned_post_id": None,
        }

    def _revalidate_clinical_envelope(self, envelope: dict[str, Any]) -> None:
        if (
            envelope["policy_epoch"] != self.policy.values["policy_epoch"]
            or envelope["policy_digest"] != self.policy.digest
            or envelope["key_fingerprint"] != self.policy.values["outbox_key_fingerprint"]
            or envelope["clinical_policy_id"] != self.policy.values["clinical_policy_id"]
            or envelope["integration_id"] != self.policy.values["clinical_integration_id"]
            or envelope["operation"] != "next-appointment"
            or not isinstance(envelope["patient_id"], str) or _PATIENT_UUID.fullmatch(envelope["patient_id"]) is None
            or envelope["request_id"] != request_identity(
                self.policy.values["tenant_id"], self.policy.origin, envelope["channel_id"], envelope["source_id"]
            )
            or not self._clinical_binding(envelope["channel_id"], envelope["actor_id"])
        ):
            raise DefinitiveMattermostError("Mattermost clinical policy binding changed")
        self._bot_identity(definitive=True)
        source = self.rest.get_post(envelope["source_id"], definitive=True)
        if isinstance(source, dict) and "file_ids" not in source:
            source = {**source, "file_ids": []}
        if not _complete_post_response(source) or not isinstance(source.get("file_ids"), list):
            raise TransientMattermostError("Mattermost clinical source response incomplete")
        if (
            source.get("id") != envelope["source_id"]
            or source.get("root_id") != "" or envelope["root_id"] != envelope["source_id"]
            or source.get("channel_id") != envelope["channel_id"] or source.get("user_id") != envelope["actor_id"]
            or source.get("message") != envelope["source_message"]
        ):
            raise DefinitiveMattermostError("Mattermost clinical source replay binding rejected")
        command_state, patient_id = _clinical_command(source["message"], self.policy.values["bot_username"])
        if command_state != "valid" or patient_id != envelope["patient_id"]:
            raise DefinitiveMattermostError("Mattermost clinical patient replay binding rejected")
        self._authorize_clinical_source(source, definitive=True)

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
        if not _complete_post_response(source) or not isinstance(source.get("file_ids"), list):
            raise TransientMattermostError("Mattermost source response incomplete")
        if source.get("id") != envelope["source_id"] or source.get("channel_id") != envelope["channel_id"] or source.get("user_id") != envelope["actor_id"]:
            raise DefinitiveMattermostError("Mattermost source replay binding rejected")
        if _clinical_command(source["message"], self.policy.values["bot_username"])[0] != "ordinary":
            raise DefinitiveMattermostError("Mattermost source replay clinical namespace rejected")
        root_id = self._authorize_source(source, definitive=True)
        if root_id != envelope["root_id"] or source.get("message") != envelope["message"]:
            raise DefinitiveMattermostError("Mattermost source/root replay binding rejected")

    def handle(self, event: MattermostEvent) -> None:
        try:
            self.policy.validate()
            if not self._authenticated:
                return
            post = event.post
            command_state, patient_id = _clinical_command(post.get("message", ""), self.policy.values["bot_username"])
            if event.channel_type == "D":
                if command_state != "valid" or patient_id is None or post.get("root_id") != "":
                    return
                self._authorize_clinical_source(post)
                record, _ = self.outbox.reserve(
                    self._clinical_envelope(post, patient_id),
                    payload_capacity=self.policy.values["outbox_payload_capacity"],
                    tombstone_capacity=self.policy.values["outbox_tombstone_capacity"],
                )
                self.executor.signal(record.record_tag)
                return
            if command_state != "ordinary" or event.channel_type != "P":
                return
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
        if envelope.get("schema_version") == CLINICAL_OUTBOX_SCHEMA:
            self._process_clinical(record)
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

    def _process_clinical(self, record: OutboxRecord) -> None:
        envelope = record.envelope
        if envelope is None:
            return
        if self.ingress.clinical is None:
            self._block_or_expire(record, "clinical_capability_disabled")
            return
        if not self._expiry_fence(record):
            return
        try:
            self.ingress._revalidate_clinical_envelope(envelope)
        except DefinitiveMattermostError:
            self._block_or_expire(record, "current_authorization_rejected")
            return
        except (ContractError, OSError, TimeoutError, ValueError):
            return
        if record.state is DeliveryState.WAITING_COMMIT:
            request = {
                "mattermostActorId": envelope["actor_id"], "patientId": envelope["patient_id"],
                "requestId": envelope["request_id"], "integrationId": envelope["integration_id"],
                "clinicalPolicyId": envelope["clinical_policy_id"], "policyEpoch": envelope["policy_epoch"],
                "policyDigest": envelope["policy_digest"],
            }
            try:
                result = self.ingress.clinical.query(request)
            except ClinicalAuthorizationDenied:
                logging.getLogger("restricted_mattermost").warning(
                    "mattermost_clinical_outcome=authorization_denied"
                )
                self._block_or_expire(record, "clinical_query_authorization_denied")
                return
            except (ContractError, OSError, TimeoutError, ValueError):
                return
            expected = {"clinicTimezone", "appointment", "responseDigest"}
            appointment = result.get("appointment") if isinstance(result, dict) else None
            if not isinstance(result, dict) or set(result) != expected:
                self._block_or_expire(record, "clinical_query_not_authorized")
                return
            if result.get("clinicTimezone") != self.ingress.policy.values["clinical_timezone"]:
                self._block_or_expire(record, "clinical_query_timezone")
                return
            response_digest = result.get("responseDigest")
            if (
                not isinstance(response_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", response_digest) is None
                or response_digest != _clinical_response_digest(result)
            ):
                self._block_or_expire(record, "clinical_query_digest")
                return
            if appointment is None:
                response = "No upcoming appointment found."
                record = self.ingress.outbox.mark_ready(record, {
                    **envelope, "clinic_timezone": result.get("clinicTimezone"), "appointment": None,
                    "response": response, "response_digest": response_digest,
                })
                envelope = record.envelope
            else:
                if not _valid_clinical_appointment(appointment):
                    self._block_or_expire(record, "clinical_query_shape")
                    return
                response = f"Next appointment: {appointment['date']} at {appointment['time']} {result['clinicTimezone']} ({appointment['status']}, {appointment['duration']} minutes)."
                record = self.ingress.outbox.mark_ready(record, {
                    **envelope, "clinic_timezone": result["clinicTimezone"], "appointment": appointment,
                    "response": response, "response_digest": response_digest,
                })
                envelope = record.envelope
        if record.state is not DeliveryState.READY or envelope is None or not self._expiry_fence(record):
            return
        try:
            self.ingress._revalidate_clinical_envelope(envelope)
            authorization = self.ingress.clinical.reauthorize_delivery({
                "mattermostActorId": envelope["actor_id"], "patientId": envelope["patient_id"],
                "requestId": envelope["request_id"], "integrationId": envelope["integration_id"],
                "clinicalPolicyId": envelope["clinical_policy_id"], "policyEpoch": envelope["policy_epoch"],
                "policyDigest": envelope["policy_digest"],
                "responseDigest": envelope["response_digest"],
            })
        except ClinicalAuthorizationDenied:
            logging.getLogger("restricted_mattermost").warning(
                "mattermost_clinical_outcome=authorization_denied"
            )
            self._block_or_expire(record, "delivery_authorization_denied")
            return
        except DefinitiveMattermostError:
            self._block_or_expire(record, "delivery_authorization_rejected")
            return
        except (ContractError, OSError, TimeoutError, ValueError):
            return
        if (
            not isinstance(authorization, dict)
            or set(authorization) != {"authorized"} or authorization.get("authorized") is not True
        ):
            self._block_or_expire(record, "delivery_authorization_not_authorized")
            return
        try:
            self.ingress._revalidate_clinical_envelope(envelope)
        except DefinitiveMattermostError:
            self._block_or_expire(record, "post_authorization_source_rejected")
            return
        except (ContractError, OSError, TimeoutError, ValueError):
            return
        if not self._expiry_fence(record):
            return
        claimed = self.ingress.outbox.claim_delivery(record)
        if claimed is None or claimed.envelope is None or not self._expiry_fence(claimed):
            return
        outbound = {
            "channel_id": claimed.envelope["channel_id"], "root_id": claimed.envelope["root_id"],
            "message": claimed.envelope["response"], "pending_post_id": claimed.envelope["pending_post_id"],
        }
        try:
            delivered = self.ingress.rest.create_post(outbound)
            if (
                not isinstance(delivered, dict) or not isinstance(delivered.get("id"), str) or not delivered["id"]
                or delivered.get("channel_id") != outbound["channel_id"] or delivered.get("root_id") != outbound["root_id"]
                or delivered.get("pending_post_id") != outbound["pending_post_id"]
            ):
                raise ContractError("Mattermost clinical delivery binding rejected")
        except (ContractError, OSError, TimeoutError, ValueError):
            self.ingress.outbox.terminal(claimed, DeliveryState.AMBIGUOUS, reason="clinical_post_attempt_unconfirmed")
            return
        self.ingress.outbox.delivered(claimed, returned_post_id=delivered["id"])


class MattermostRestClient:
    """One-origin REST transport with no proxy discovery or redirect handling."""
    def __init__(self, policy: MattermostPolicy, token: str, *, ca_path: Path | None = None):
        self.policy, self._token = policy, token
        split = urlsplit(policy.origin)
        self._host, self._port = split.hostname or "", split.port or 443
        self._context = ssl.create_default_context(cafile=str(ca_path) if ca_path else None)

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None, *, list_response: bool = False) -> Any:
        member_page = path.endswith("/members?page=0&per_page=3")
        if not path.startswith("/api/v4/") or "//" in path or "#" in path or ("?" in path and not member_page):
            raise ContractError("Mattermost REST path rejected")
        payload = None if body is None else jcs_bytes(body)
        deadline = time.monotonic() + self.policy.values["rest_timeout_seconds"]

        def remaining() -> float:
            value = deadline - time.monotonic()
            if value <= 0:
                raise TimeoutError
            return value

        connection = None
        try:
            with absolute_upstream_deadline(self.policy.values["rest_timeout_seconds"]):
                connection = http.client.HTTPSConnection(
                    self._host, self._port, timeout=remaining(), context=self._context
                )
                remaining()
                headers = {"Authorization": "Bearer " + self._token, "Accept": "application/json", "Connection": "close"}
                if payload is not None:
                    headers.update({"Content-Type": "application/json", "Content-Length": str(len(payload))})
                connection.request(method, path, body=payload, headers=headers)
                if getattr(connection, "sock", None) is not None:
                    connection.sock.settimeout(remaining())
                remaining()
                response = connection.getresponse()
                if response.status not in {200, 201} or response.getheader("Location") is not None:
                    if response.status in {403, 404}:
                        raise DefinitiveMattermostError("Mattermost REST current resource rejected")
                    raise TransientMattermostError("Mattermost REST response unavailable")
                try:
                    if getattr(connection, "sock", None) is not None:
                        connection.sock.settimeout(remaining())
                    remaining()
                    raw = response.read(_MAX_HTTP_BYTES + 1)
                    if len(raw) > _MAX_HTTP_BYTES:
                        raise ContractError("Mattermost REST response oversized")
                    if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                        raise ContractError("Mattermost REST response content type rejected")
                    value = load_closed_json(raw)
                    if not isinstance(value, list if list_response else dict):
                        raise ContractError("Mattermost REST response JSON rejected")
                    remaining()
                except ContractError as exc:
                    raise TransientMattermostError("Mattermost REST response rejected") from exc
                return value
        except ContractError:
            raise
        except (OSError, http.client.HTTPException, TimeoutError) as exc:
            raise TransientMattermostError("Mattermost REST transport failed") from exc
        finally:
            if connection is not None:
                connection.close()

    def get_me(self, *, definitive: bool = False): return self._request("GET", "/api/v4/users/me")
    def get_channel(self, channel_id, *, definitive: bool = False): return self._request("GET", "/api/v4/channels/" + quote(channel_id, safe=""))
    def get_channel_member(self, channel_id, user_id, *, definitive: bool = False): return self._request("GET", "/api/v4/channels/" + quote(channel_id, safe="") + "/members/" + quote(user_id, safe=""))
    def get_channel_members(self, channel_id, *, definitive: bool = False): return self._request("GET", "/api/v4/channels/" + quote(channel_id, safe="") + "/members?page=0&per_page=3", list_response=True)
    def get_post(self, post_id, *, definitive: bool = False): return self._request("GET", "/api/v4/posts/" + quote(post_id, safe=""))
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

    @staticmethod
    def _valid_identifier(value: Any) -> bool:
        return isinstance(value, str) and 1 <= len(value) <= 128

    def _turn_response(self, result: Any, *, conversation_epoch: str) -> dict[str, Any]:
        if not isinstance(result, dict):
            raise ContractError("conversation turn response rejected")
        schema = result.get("schema_version")
        if schema == "restricted-turn-result.v1":
            if (
                set(result) != {"schema_version", "turn_id", "conversation_epoch", "status", "message"}
                or result.get("status") != TurnState.COMMITTED
                or not isinstance(result.get("message"), str) or not result["message"]
            ):
                raise ContractError("conversation turn response rejected")
        elif schema == "restricted-turn-status.v1":
            if (
                set(result) != {"schema_version", "turn_id", "conversation_epoch", "status"}
                or result.get("status") not in {state.value for state in TurnState if state is not TurnState.COMMITTED}
            ):
                raise ContractError("conversation turn response rejected")
        else:
            raise ContractError("conversation turn response rejected")
        if (
            not self._valid_identifier(result.get("turn_id"))
            or not self._valid_identifier(result.get("conversation_epoch"))
            or result["conversation_epoch"] != conversation_epoch
        ):
            raise ContractError("conversation turn response rejected")
        return result

    def submit_turn(self, *, conversation_id: str, conversation_epoch: str, client_request_id: str, message: str, deadline: float | None = None) -> dict[str, Any]:
        deadline = deadline if deadline is not None else time.monotonic() + self.policy.values["conversation_deadline_seconds"]
        result = self._request(
            "POST", "/v1/restricted/conversations/" + conversation_id + "/turns",
            {"schema_version": "restricted-turn.v1", "client_request_id": client_request_id,
             "conversation_epoch": conversation_epoch, "message": message}, deadline=deadline,
        )
        result = self._turn_response(result, conversation_epoch=conversation_epoch)
        if deadline - time.monotonic() <= 0:
            raise ContractError("conversation transport failed")
        return result

    def submit(self, *, conversation_id: str, client_request_id: str, message: str):
        deadline = time.monotonic() + self.policy.values["conversation_deadline_seconds"]
        created = self.create_conversation(conversation_id=conversation_id, deadline=deadline)
        if created.get("conversation_id") != conversation_id or not self._valid_identifier(created.get("conversation_epoch")):
            raise ContractError("conversation creation response rejected")
        if deadline - time.monotonic() <= 0:
            raise ContractError("conversation transport failed")
        result = self._request(
            "POST", "/v1/restricted/conversations/" + conversation_id + "/turns",
            {"schema_version": "restricted-turn.v1", "client_request_id": client_request_id,
             "conversation_epoch": created["conversation_epoch"], "message": message}, deadline=deadline,
        )
        result = self._turn_response(result, conversation_epoch=created["conversation_epoch"])
        if deadline - time.monotonic() <= 0:
            raise ContractError("conversation transport failed")
        return result


class ClinicalQueryUdsClient:
    """Closed client for one separately authorized HRH-backed clinical service."""

    def __init__(self, policy: MattermostPolicy):
        path = policy.values.get("clinical_query_socket_path")
        if path != "/run/restricted-clinical/query.sock":
            raise ContractError("clinical query socket path rejected")
        self.policy, self.path = policy, path

    def _request(self, endpoint: str, body: dict[str, Any]) -> dict[str, Any]:
        if endpoint not in {"/v1/clinical/query", "/v1/clinical/reauthorize-delivery"}:
            raise ContractError("clinical query endpoint rejected")
        delivery = endpoint == "/v1/clinical/reauthorize-delivery"
        if not isinstance(body, dict) or not _valid_clinical_wire_request(body, delivery=delivery):
            raise ContractError("clinical query request schema rejected")
        payload = jcs_bytes(body)
        deadline = time.monotonic() + self.policy.values["uds_timeout_seconds"]
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(max(0.001, deadline - time.monotonic()))
                client.connect(self.path)
                wire = b"POST " + endpoint.encode("ascii") + b" HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: " + str(len(payload)).encode("ascii") + b"\r\n\r\n" + payload
                client.settimeout(max(0.001, deadline - time.monotonic()))
                client.sendall(wire)
                chunks, total = [], 0
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    client.settimeout(remaining)
                    chunk = client.recv(min(65536, _MAX_HTTP_BYTES + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > _MAX_HTTP_BYTES:
                        raise ContractError("clinical query response oversized")
            head, raw = b"".join(chunks).split(b"\r\n\r\n", 1)
            if head.startswith(b"HTTP/1.1 403 Forbidden\r\n"):
                raise ClinicalAuthorizationDenied("clinical authorization denied")
            if not head.startswith(b"HTTP/1.1 200 OK\r\n"):
                raise ContractError("clinical query response rejected")
            value = load_closed_json(raw)
            if not isinstance(value, dict) or time.monotonic() >= deadline:
                raise ContractError("clinical query response rejected")
            return value
        except ContractError:
            raise
        except (OSError, TimeoutError, ValueError) as exc:
            raise ContractError("clinical query transport failed") from exc

    def query(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._request("/v1/clinical/query", request)

    def reauthorize_delivery(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._request("/v1/clinical/reauthorize-delivery", request)
