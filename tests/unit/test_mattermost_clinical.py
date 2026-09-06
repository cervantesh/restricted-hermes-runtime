from __future__ import annotations

import uuid
import hashlib

import pytest

from restricted_runtime.contracts import ClinicalAuthorizationDenied, ContractError
from restricted_runtime.mattermost_ingress import ClinicalQueryUdsClient, Ingress, _clinical_response_digest

from test_mattermost_ingress import (
    BOT,
    CHANNEL,
    ROOT,
    USER,
    Conversation,
    Rest,
    event,
    policy_values,
    post,
    signed_policy,
    LETTER_CONFUSABLE_COMMANDS,
    COMBINING_MARK_O_CONFUSABLES,
    RESIDUAL_CLINICAL_SEPARATOR_SOURCES,
    RESIDUAL_CLINICAL_COMPATIBILITY_SEPARATOR_SOURCES,
    UNICODE_15_1_COMPATIBILITY_SEPARATOR_SOURCES,
)
from restricted_runtime.mattermost_outbox import DeliveryState, MattermostOutbox
import os
import re
from types import SimpleNamespace

import restricted_runtime.mattermost_ingress as mattermost_ingress


PATIENT = "123e4567-e89b-42d3-a456-426614174000"


def test_response_digest_matches_frozen_hrh_canonical_bytes():
    raw = b'{"clinicTimezone":"America/New_York","appointment":{"id":"a","date":"2026-09-08","time":"14:30","duration":30,"status":"scheduled"}}'
    assert _clinical_response_digest({
        "appointment": {"status": "scheduled", "duration": 30, "time": "14:30", "date": "2026-09-08", "id": "a"},
        "clinicTimezone": "America/New_York",
    }) == hashlib.sha256(raw).hexdigest()


class Clinical:
    def __init__(self):
        self.queries = []
        self.reauthorizations = []
        self.delivery_status = "AUTHORIZED"

    def query(self, request):
        self.queries.append(request)
        result = {
            "clinicTimezone": "America/New_York",
            "appointment": {
                "id": "appt0000000000000000000000",
                "date": "2026-09-08",
                "time": "14:30",
                "duration": 30,
                "status": "scheduled",
            },
        }
        return {**result, "responseDigest": _clinical_response_digest(result)}

    def reauthorize_delivery(self, request):
        self.reauthorizations.append(request)
        return {
            "authorized": self.delivery_status == "AUTHORIZED",
        }


class DirectRest(Rest):
    def __init__(self):
        super().__init__()
        self.channels[CHANNEL] = {"id": CHANNEL, "team_id": "", "type": "D"}
        self.roster = [USER, BOT]

    def get_channel_members(self, channel_id, *, definitive=False):
        return [{"channel_id": channel_id, "user_id": value} for value in self.roster]


def clinical_ingress(tmp_path):
    values = policy_values()
    values.update(
        clinical_bindings=[{"channel_id": CHANNEL, "actor_id": USER}],
        clinical_integration_id="hrh-mattermost-01",
        clinical_policy_id="clinical-read-v1",
        clinical_query_socket_path="/run/restricted-clinical/query.sock",
        clinical_timezone="America/New_York",
    )
    policy = signed_policy(tmp_path, values)
    rest, conversation, clinical = DirectRest(), Conversation(), Clinical()
    conversation.ready = lambda: (_ for _ in ()).throw(AssertionError("clinical path touched conversation"))
    root = post(message=f"@restricted-bot next-appointment {PATIENT}")
    rest.posts[ROOT] = root
    key = tmp_path / "outbox.key"
    key.write_bytes(b"m" * 32)
    os.chmod(key, 0o600)
    outbox = MattermostOutbox.initialize(
        tmp_path / "outbox", key, expected_fingerprint=policy.values["outbox_key_fingerprint"]
    )
    service = Ingress(policy, rest, conversation, outbox, clinical=clinical)
    service.preflight()
    service.mark_authenticated()
    return service, rest, conversation, clinical


def test_exact_root_command_is_deterministic_and_never_reaches_conversation(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    assert conversation.calls == []
    assert len(clinical.queries) == len(clinical.reauthorizations) == 1
    request = clinical.queries[0]
    assert set(request) == {"mattermostActorId", "patientId", "requestId", "integrationId", "clinicalPolicyId", "policyEpoch", "policyDigest"}
    assert request["mattermostActorId"] == USER
    assert request["patientId"] == PATIENT
    assert request["integrationId"] == "hrh-mattermost-01"
    assert clinical.reauthorizations[0]["responseDigest"] == _clinical_response_digest({
        "clinicTimezone": "America/New_York",
        "appointment": {"id": "appt0000000000000000000000", "date": "2026-09-08", "time": "14:30", "duration": 30, "status": "scheduled"},
    })
    uuid.UUID(request["requestId"])
    assert rest.created == [{
        "channel_id": CHANNEL,
        "root_id": ROOT,
        "message": "Next appointment: 2026-09-08 at 14:30 America/New_York (scheduled, 30 minutes).",
        "pending_post_id": rest.created[0]["pending_post_id"],
    }]


@pytest.mark.parametrize("message", [
    f"@restricted-bot NEXT-APPOINTMENT {PATIENT}",
    f"@restricted-bot next‑appointment {PATIENT}",
    f"@restricted-bot next-appointment {PATIENT} extra",
    "@restricted-bot next-appointment not-a-uuid",
    f"@restricted-bot next-appointment {PATIENT.upper()}",
    f"next-appointment {PATIENT}",
    f"@restricted-bot @restricted-bot next-appointment {PATIENT}",
    f"@restricted-bot next-app\u043eintment {PATIENT}",
    f"@restricted-bot next\u200b-appointment {PATIENT}",
])
def test_clinical_namespace_is_reserved_and_malformed_forms_never_fall_to_model(tmp_path, message):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert conversation.calls == []
    assert clinical.queries == []
    assert rest.created == []


def test_dotless_i_clinical_lookalike_is_reserved_in_direct_channel(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=f"@restricted-bot next-appo\u0131ntment {PATIENT}")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []
    assert service.outbox.candidates(10) == []


@pytest.mark.parametrize("codepoint", RESIDUAL_CLINICAL_SEPARATOR_SOURCES)
def test_residual_separator_sources_reserve_direct_clinical_namespace_without_effects(tmp_path, codepoint):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=f"@restricted-bot next{chr(codepoint)}appointment {PATIENT}")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and clinical.queries == [] and clinical.reauthorizations == []
    assert rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("codepoint", RESIDUAL_CLINICAL_COMPATIBILITY_SEPARATOR_SOURCES)
def test_compatibility_separator_residuals_reserve_direct_clinical_namespace_without_effects(tmp_path, codepoint):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=f"@restricted-bot next{chr(codepoint)}appointment {PATIENT}")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and clinical.queries == [] and clinical.reauthorizations == []
    assert rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("separator_source", (0x2017, 0x00A8, 0x02DB))
@pytest.mark.parametrize("letter_source", (0x0131, 0x026A, 0x02DB))
def test_compatibility_and_secondary_letter_sources_reserve_direct_clinical_namespace(
    tmp_path, separator_source, letter_source,
):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=(
        f"@restricted-bot next{chr(separator_source)}appo{chr(letter_source)}ntment {PATIENT}"
    ))
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and clinical.queries == [] and clinical.reauthorizations == []
    assert rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("separator_source", UNICODE_15_1_COMPATIBILITY_SEPARATOR_SOURCES)
@pytest.mark.parametrize("letter_source", COMBINING_MARK_O_CONFUSABLES)
def test_round12_compatibility_separator_and_combining_o_reserve_direct_clinical_namespace(
    tmp_path, separator_source, letter_source,
):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=(
        f"@restricted-bot next{chr(separator_source)}app{chr(letter_source)}intment {PATIENT}"
    ))
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and clinical.queries == [] and clinical.reauthorizations == []
    assert rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("separator", ("-", "\u2017"))
@pytest.mark.parametrize("source", COMBINING_MARK_O_CONFUSABLES)
@pytest.mark.parametrize("mark_position", ("letter", "separator"))
def test_round13_mark_source_confusables_reserve_direct_clinical_namespace(
    tmp_path, separator, source, mark_position,
):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    namespace = (
        f"ne\u0301xt{separator}app{chr(source)}intment"
        if mark_position == "letter" else f"next{separator}\u0301app{chr(source)}intment"
    )
    candidate = post(message=f"@restricted-bot {namespace} {PATIENT}")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and clinical.queries == [] and clinical.reauthorizations == []
    assert rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("namespace", (
    "next-\u0430pp\u0c02intment",
    "next-app\u0c02i\u0578tment",
))
def test_round13_mark_o_nonmark_companions_reserve_direct_clinical_namespace(tmp_path, namespace):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=f"@restricted-bot {namespace} {PATIENT}")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and clinical.queries == [] and clinical.reauthorizations == []
    assert rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("namespace", (
    "NEXT-APP\u0c02INTMENT",
    "next\u2017ap\u200bp\u0c02i\u0578tment",
    "ne\u0c02xt-app\u0c02intment",
))
def test_round13_late_context_mark_o_sources_reserve_direct_clinical_namespace(tmp_path, namespace):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=f"@restricted-bot {namespace} {PATIENT}")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and clinical.queries == [] and clinical.reauthorizations == []
    assert rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("namespace", (
    "next-app\u0c02\u0c82intment",
    "next-a\u0c02pp\u0c82intment",
    "next-app\u0c02\u0c82\u0d02intment",
    "next\u02dbappo\u037antment",
))
def test_round14_ambiguous_sources_reserve_direct_clinical_namespace(tmp_path, namespace):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=f"@restricted-bot {namespace} {PATIENT}")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and clinical.queries == [] and clinical.reauthorizations == []
    assert rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize("codepoint", RESIDUAL_CLINICAL_COMPATIBILITY_SEPARATOR_SOURCES)
@pytest.mark.parametrize("ready", [False, True], ids=["waiting-commit", "ready"])
def test_legacy_compatibility_separator_records_are_reclassified_in_direct_channel(tmp_path, ready, codepoint):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    source = post(message=f"@restricted-bot next{chr(codepoint)}appointment {PATIENT}")
    rest.posts[ROOT] = source
    record, _ = service.outbox.reserve(service._envelope(source, ROOT), payload_capacity=1000, tombstone_capacity=1000)
    if ready:
        record = service.outbox.mark_ready(record, {**record.envelope, "conversation_epoch": "epoch-one", "response": "legacy"})
    service.executor.drain()
    durable = service.outbox.get(record.record_tag)
    assert durable is not None and durable.state is DeliveryState.BLOCKED
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []


@pytest.mark.parametrize("message", [
    f"@restricted-bot next\u02d7appo\u026antment {PATIENT}",
    f"@restricted-bot next\u02d7appo\ufe0fintment {PATIENT}",
])
def test_residual_separator_composed_with_existing_secondary_forms_is_reserved_in_direct_channel(tmp_path, message):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=message)
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert conversation.calls == [] and clinical.queries == [] and clinical.reauthorizations == []
    assert rest.created == [] and service.outbox.candidates(10) == []


@pytest.mark.parametrize(("_character", "command"), LETTER_CONFUSABLE_COMMANDS)
def test_letter_confusable_clinical_lookalikes_are_reserved_in_direct_channel(tmp_path, _character, command):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=f"@restricted-bot {command} {PATIENT}")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []
    assert service.outbox.candidates(10) == []


def test_hyphen_bullet_clinical_lookalike_is_reserved_in_direct_channel(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=f"@restricted-bot next\u2043appointment {PATIENT}")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []
    assert service.outbox.candidates(10) == []


@pytest.mark.parametrize("dash", ["\u2015", "\u2e3a", "\u2e3b"])
def test_dash_punctuation_clinical_lookalikes_are_reserved_in_direct_channel(tmp_path, dash):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=f"@restricted-bot next{dash}appointment {PATIENT}")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []
    assert service.outbox.candidates(10) == []


def test_combined_horizontal_bar_and_dotless_i_clinical_lookalike_is_reserved_in_direct_channel(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=f"@restricted-bot next\u2015appo\u0131ntment {PATIENT}")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="D"))
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []
    assert service.outbox.candidates(10) == []


def test_dotless_i_is_secondary_namespace_only_and_exact_ascii_grammar_stays_valid():
    dotless = f"@restricted-bot next-appo\u0131ntment {PATIENT}"
    assert mattermost_ingress._clinical_command(dotless, "restricted-bot") == ("malformed", None)
    assert mattermost_ingress._clinical_command(
        f"@restricted-bot next-appointment {PATIENT}", "restricted-bot"
    ) == ("valid", PATIENT)


def test_exact_ascii_clinical_command_is_the_only_valid_grammar():
    assert mattermost_ingress._clinical_command(
        f"@restricted-bot next-appointment {PATIENT}", "restricted-bot"
    ) == ("valid", PATIENT)


@pytest.mark.parametrize("mark", ["\u0301", "\u0903", "\u20dd"], ids=["Mn", "Mc", "Me"])
@pytest.mark.parametrize("channel_type", ["P", "D"])
def test_mark_variants_of_clinical_namespace_never_reach_any_delivery_path(tmp_path, mark, channel_type):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=f"@restricted-bot ne{mark}xt-appointment {PATIENT}")
    rest.posts[ROOT] = candidate
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    service.handle(event(candidate, channel_type=channel_type))
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []
    assert service.outbox.candidates(10) == []


@pytest.mark.parametrize(
    "command",
    [f"next-a\u1fe4pointment {PATIENT}", f"next-appo\u0130ntment {PATIENT}"],
    ids=["rho-with-psili", "latin-capital-i-with-dot"],
)
@pytest.mark.parametrize("channel_type", ["P", "D"])
def test_precomposed_mark_confusable_variants_never_reach_any_delivery_path(tmp_path, command, channel_type):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=f"@restricted-bot {command}")
    rest.posts[ROOT] = candidate
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    service.handle(event(candidate, channel_type=channel_type))
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []
    assert service.outbox.candidates(10) == []


def test_underscore_separated_clinical_namespace_in_an_allowed_private_event_has_zero_effects(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    candidate = post(message=f"@restricted-bot next_appointment {PATIENT}")
    rest.posts[ROOT] = candidate
    assert mattermost_ingress._clinical_command(candidate["message"], "restricted-bot") == ("malformed", None)
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []
    assert service.outbox.candidates(10) == []


def test_clinical_command_is_root_only_and_never_falls_to_model(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    reply = post("reply00000000000000000000000", root_id=ROOT, message=f"next-appointment {PATIENT}")
    rest.posts[reply["id"]] = reply
    service.handle(event(reply, channel_type="D"))
    assert conversation.calls == []
    assert clinical.queries == []
    assert rest.created == []


@pytest.mark.parametrize("failure", ["third-member", "wrong-binding"])
def test_direct_roster_and_channel_actor_pair_are_authoritative(tmp_path, failure):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    if failure == "third-member":
        rest.roster.append("other000000000000000000000")
    else:
        service.policy.values["clinical_bindings"] = [
            {"channel_id": CHANNEL, "actor_id": "other000000000000000000000"}
        ]
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []


@pytest.mark.parametrize("status", ["DENIED", "UNAVAILABLE", "INDETERMINATE"])
def test_delivery_reauthorization_failures_never_post_phi(tmp_path, status):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    clinical.delivery_status = status
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    assert conversation.calls == []
    assert len(clinical.queries) == len(clinical.reauthorizations) == 1
    assert rest.created == []


def test_authoritative_query_denial_is_terminal_and_never_revives(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    original = clinical.query
    clinical.query = lambda _request: (_ for _ in ()).throw(ClinicalAuthorizationDenied("denied"))
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    clinical.query = original
    service.executor.drain()
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []
    assert service.outbox.candidates(10) == []


def test_clinical_policy_extension_is_all_or_nothing_and_pair_bound(tmp_path):
    values = policy_values()
    values["clinical_policy_id"] = "clinical-read-v1"
    with pytest.raises(ContractError):
        signed_policy(tmp_path / "partial", values)
    values = policy_values()
    values.update(
        clinical_bindings=[
            {"channel_id": CHANNEL, "actor_id": USER},
            {"channel_id": CHANNEL, "actor_id": USER},
        ],
        clinical_integration_id="hrh-mattermost-01",
        clinical_policy_id="clinical-read-v1",
        clinical_query_socket_path="/run/restricted-clinical/query.sock",
        clinical_timezone="America/New_York",
    )
    with pytest.raises(ContractError):
        signed_policy(tmp_path / "duplicate", values)

    values["clinical_bindings"] = [{"channel_id": CHANNEL, "actor_id": USER}]
    values["uds_timeout_seconds"] = 9
    with pytest.raises(ContractError, match="deadline"):
        signed_policy(tmp_path / "short-deadline", values)


def test_no_upcoming_appointment_is_a_closed_deterministic_result(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    result = {"clinicTimezone": "America/New_York", "appointment": None}
    clinical.query = lambda request: {**result, "responseDigest": _clinical_response_digest(result)}
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    assert conversation.calls == []
    assert rest.created[0]["message"] == "No upcoming appointment found."


def test_unknown_clinical_response_fields_fail_closed(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    clinical.query = lambda request: {
        "clinicTimezone": "America/New_York", "appointment": None,
        "responseDigest": _clinical_response_digest({"clinicTimezone": "America/New_York", "appointment": None}),
        "notes": "must not cross"
    }
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    assert conversation.calls == [] and rest.created == []


def test_ingress_rejects_adapter_config_timezone_that_does_not_match_the_signed_policy(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    adapter_config_timezone = "Europe/Madrid"
    result = {"clinicTimezone": adapter_config_timezone, "appointment": None}
    clinical.query = lambda _request: {**result, "responseDigest": _clinical_response_digest(result)}
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    assert conversation.calls == []
    assert rest.created == []
    assert clinical.reauthorizations == []


def test_impossible_calendar_date_from_clinical_service_fails_closed(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    original = clinical.query

    def impossible(request):
        result = original(request)
        result["appointment"]["date"] = "2026-02-31"
        return result

    clinical.query = impossible
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    assert conversation.calls == [] and rest.created == []


def test_malformed_clinical_namespace_in_private_channel_never_falls_to_model(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    rest.channels[CHANNEL] = {"id": CHANNEL, "team_id": "team0000000000000000000000", "type": "P"}
    candidate = post(message=f"@restricted-bot next-appointment {PATIENT} explain")
    rest.posts[ROOT] = candidate
    service.handle(event(candidate, channel_type="P"))
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []


def test_runtime_surface_keeps_clinical_transport_narrow_and_documented():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    source = (root / "src/restricted_runtime/mattermost_ingress.py").read_text(encoding="utf-8")
    image = (root / "Dockerfile.mattermost-ingress").read_text(encoding="utf-8")
    design = (root / "docs/design/clinical-staff-next-appointment.md").read_text(encoding="utf-8")
    assert "/run/restricted-clinical/query.sock" in source
    assert set(re.findall(r'"/v1/clinical/[^"]+"', source)) == {
        '"/v1/clinical/query"', '"/v1/clinical/reauthorize-delivery"'
    }
    assert "restricted-clinical-query" in image
    assert "not a PHI, HIPAA, BAA" in design


def test_clinical_uds_client_rejects_unknown_request_fields_before_transport(tmp_path):
    service, _rest, _conversation, _clinical = clinical_ingress(tmp_path)
    client = ClinicalQueryUdsClient(service.policy)
    request = {
        "mattermostActorId": USER, "patientId": PATIENT,
        "requestId": "request_123", "integrationId": "hrh-mattermost-01",
        "clinicalPolicyId": "clinical-read-v1", "policyEpoch": "mattermost-e1",
        "policyDigest": service.policy.digest, "notes": "must not cross",
    }
    with pytest.raises(ContractError, match="schema"):
        client.query(request)


def test_clinical_uds_client_preserves_authoritative_denial(monkeypatch):
    from test_mattermost_ingress import _Clock, _UdsSocket

    clock = _Clock()
    peer = _UdsSocket(
        clock,
        b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    )
    policy = SimpleNamespace(values={
        "clinical_query_socket_path": "/run/restricted-clinical/query.sock",
        "uds_timeout_seconds": 10,
    })
    monkeypatch.setattr(mattermost_ingress.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(mattermost_ingress.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(mattermost_ingress.socket, "socket", lambda *_: peer)
    with pytest.raises(ClinicalAuthorizationDenied):
        ClinicalQueryUdsClient(policy).query({
            "mattermostActorId": USER, "patientId": PATIENT, "requestId": "request_123",
            "integrationId": "hrh-mattermost-01", "clinicalPolicyId": "clinical-read-v1",
            "policyEpoch": "mattermost-e1", "policyDigest": "a" * 64,
        })


def test_roster_is_revalidated_after_hrh_delivery_authorization(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    original = clinical.reauthorize_delivery

    def revoke_audience(request):
        result = original(request)
        rest.roster.append("other000000000000000000000")
        return result

    clinical.reauthorize_delivery = revoke_audience
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    assert conversation.calls == [] and rest.created == []


def test_source_identity_swap_before_query_discloses_nothing(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    original = rest.get_post

    def swapped(post_id, *, definitive=False):
        value = dict(original(post_id, definitive=definitive))
        if definitive:
            value["id"] = "other000000000000000000000"
        return value

    rest.get_post = swapped
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []


def test_integration_identity_is_frozen_in_encrypted_envelope(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    original_signal = service.executor.signal
    service.executor.signal = lambda _tag: None
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    service.executor.signal = original_signal
    service.policy.values["clinical_integration_id"] = "other-integration"
    service.executor.drain()
    assert conversation.calls == [] and clinical.queries == [] and rest.created == []


def test_mismatched_response_digest_never_posts(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    original = clinical.query

    def swapped(request):
        result = original(request)
        result["appointment"]["time"] = "16:45"
        return result

    clinical.query = swapped
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    assert conversation.calls == [] and rest.created == []
    assert clinical.reauthorizations == []


def test_swapped_self_consistent_dto_is_rejected_by_hrh_digest_binding(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    original = clinical.query
    authorized_digest = _clinical_response_digest({
        "clinicTimezone": "America/New_York",
        "appointment": {"id": "appt0000000000000000000000", "date": "2026-09-08", "time": "14:30", "duration": 30, "status": "scheduled"},
    })

    def swapped(request):
        result = original(request)
        result["appointment"]["time"] = "16:45"
        result["responseDigest"] = _clinical_response_digest(result)
        return result

    def reauthorize(request):
        clinical.reauthorizations.append(request)
        return {"authorized": request["responseDigest"] == authorized_digest}

    clinical.query = swapped
    clinical.reauthorize_delivery = reauthorize
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    assert conversation.calls == [] and rest.created == []
    assert len(clinical.reauthorizations) == 1


def test_clinical_uds_waits_the_remaining_ten_second_budget_across_six_second_receive(monkeypatch):
    from test_mattermost_ingress import _Clock, _UdsSocket, _uds_response

    clock = _Clock()
    result = {"clinicTimezone": "America/New_York", "appointment": None}
    result["responseDigest"] = _clinical_response_digest(result)
    peer = _UdsSocket(clock, _uds_response(result), recv_elapsed=6.0)
    policy = SimpleNamespace(values={
        "clinical_query_socket_path": "/run/restricted-clinical/query.sock",
        "uds_timeout_seconds": 10,
    })
    monkeypatch.setattr(mattermost_ingress.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(mattermost_ingress.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(mattermost_ingress.socket, "socket", lambda *_: peer)
    assert ClinicalQueryUdsClient(policy).query({
        "mattermostActorId": USER, "patientId": PATIENT, "requestId": "request_123",
        "integrationId": "hrh-mattermost-01", "clinicalPolicyId": "clinical-read-v1",
        "policyEpoch": "mattermost-e1", "policyDigest": "a" * 64,
    }) == result
    assert peer.timeouts[0] == pytest.approx(10.0)
