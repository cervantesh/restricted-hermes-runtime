from __future__ import annotations

import uuid

import pytest

from restricted_runtime.contracts import ContractError
from restricted_runtime.mattermost_ingress import ClinicalQueryUdsClient, Ingress

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
)
from restricted_runtime.mattermost_outbox import MattermostOutbox
import os
import re


PATIENT = "123e4567-e89b-42d3-a456-426614174000"


class Clinical:
    def __init__(self):
        self.queries = []
        self.reauthorizations = []
        self.delivery_status = "AUTHORIZED"

    def query(self, request):
        self.queries.append(request)
        return {
            "clinicTimezone": "America/New_York",
            "appointment": {
                "id": "appt0000000000000000000000",
                "date": "2026-09-08",
                "time": "14:30",
                "duration": 30,
                "status": "scheduled",
            },
        }

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


def test_no_upcoming_appointment_is_a_closed_deterministic_result(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    clinical.query = lambda request: {"clinicTimezone": "America/New_York", "appointment": None}
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    assert conversation.calls == []
    assert rest.created[0]["message"] == "No upcoming appointment found."


def test_unknown_clinical_response_fields_fail_closed(tmp_path):
    service, rest, conversation, clinical = clinical_ingress(tmp_path)
    clinical.query = lambda request: {
        "clinicTimezone": "America/New_York", "appointment": None, "notes": "must not cross"
    }
    service.handle(event(rest.posts[ROOT], channel_type="D"))
    assert conversation.calls == [] and rest.created == []


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
