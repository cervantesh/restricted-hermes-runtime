from __future__ import annotations

import os
from pathlib import Path

import pytest

from restricted_runtime.contracts import ContractError
from restricted_runtime.mattermost_outbox import DeliveryState, MattermostOutbox, key_fingerprint


def _key(path: Path) -> bytes:
    value = bytes(range(32))
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return value


def _envelope(*, source="source-one", root="root-one", epoch=None, response=None):
    return {
        "schema_version": "restricted-mattermost-outbox.v1", "tenant_id": "tenant", "origin": "https://mm.example",
        "channel_id": "channel", "root_id": root, "source_id": source, "actor_id": "actor", "message": "MESSAGE_CANARY",
        "conversation_id": "conversation", "conversation_epoch": epoch, "client_request_id": "request", "policy_epoch": "policy",
        "policy_digest": "a" * 64, "key_fingerprint": key_fingerprint(bytes(range(32))), "policy_expires_at": 4_000_000_000,
        "payload_expires_at": 4_000_000_000, "response": response, "pending_post_id": "pending", "returned_post_id": None,
    }


def _store(tmp_path: Path) -> MattermostOutbox:
    key_path = tmp_path / "key"
    key = _key(key_path)
    return MattermostOutbox.initialize(tmp_path / "state", key_path, expected_fingerprint=key_fingerprint(key))


def test_reservation_is_encrypted_unique_and_duplicate_precedes_capacity(tmp_path):
    store = _store(tmp_path)
    try:
        first, created = store.reserve(_envelope(), payload_capacity=1, tombstone_capacity=1)
        duplicate, repeated = store.reserve(_envelope(), payload_capacity=1, tombstone_capacity=1)
        assert created and not repeated and duplicate.record_tag == first.record_tag
        raw = (tmp_path / "state" / "mattermost-outbox.sqlite3").read_bytes()
        assert b"MESSAGE_CANARY" not in raw and b"source-one" not in raw
        with pytest.raises(ContractError):
            store.reserve(_envelope(source="source-two", root="root-two"), payload_capacity=1, tombstone_capacity=1)
    finally:
        store.close()


def test_aad_tag_tampering_and_wrong_key_fail_before_record_use(tmp_path):
    store = _store(tmp_path)
    try:
        record, _ = store.reserve(_envelope(), payload_capacity=2, tombstone_capacity=2)
        store._connection.execute("UPDATE records SET source_tag='0' || substr(source_tag, 2) WHERE record_tag=?", (record.record_tag,))
        with pytest.raises(ContractError):
            store.get(record.record_tag)
    finally:
        store.close()
    wrong = tmp_path / "wrong"
    wrong.write_bytes(b"x" * 32)
    os.chmod(wrong, 0o600)
    with pytest.raises(ContractError):
        MattermostOutbox.open(tmp_path / "state", wrong, expected_fingerprint=key_fingerprint(b"x" * 32))


def test_cas_inflight_recovery_is_ambiguous_and_terminal_payload_is_erased(tmp_path):
    store = _store(tmp_path)
    try:
        waiting, _ = store.reserve(_envelope(), payload_capacity=2, tombstone_capacity=2)
        ready = store.mark_ready(waiting, _envelope(epoch="epoch", response="RESPONSE_CANARY"))
        flight = store.claim_delivery(ready)
        assert flight is not None and flight.state is DeliveryState.IN_FLIGHT
        assert store.stale_inflight_to_ambiguous() == 1
        recovered = store.get(flight.record_tag)
        assert recovered is not None and recovered.state is DeliveryState.AMBIGUOUS and recovered.envelope is None
    finally:
        store.close()
