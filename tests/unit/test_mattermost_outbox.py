from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from restricted_runtime.contracts import ContractError
import restricted_runtime.mattermost_outbox as mattermost_outbox
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


def test_nonce_registry_rejects_repeated_entropy_for_the_lifetime_of_a_database_key(tmp_path, monkeypatch):
    store = _store(tmp_path)
    try:
        monkeypatch.setattr(mattermost_outbox.secrets, "token_bytes", lambda size: b"n" * size)
        first, created = store.reserve(_envelope(), payload_capacity=3, tombstone_capacity=3)
        assert created
        store.terminal(first, DeliveryState.BLOCKED, reason="test_terminal")
        with pytest.raises(ContractError, match="nonce reuse"):
            store.reserve(_envelope(source="second-source", root="second-root"), payload_capacity=3, tombstone_capacity=3)
        assert store._connection.execute("SELECT COUNT(*) FROM nonce_tombstones").fetchone()[0] == 2
        assert store._connection.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 1
        store.close()
        reopened = MattermostOutbox.open(
            tmp_path / "state", tmp_path / "key", expected_fingerprint=key_fingerprint(bytes(range(32)))
        )
        try:
            with pytest.raises(ContractError, match="nonce reuse"):
                reopened.reserve(_envelope(source="third-source", root="third-root"), payload_capacity=3, tombstone_capacity=3)
        finally:
            reopened.close()
    finally:
        try:
            store.close()
        except sqlite3.ProgrammingError:
            pass


def test_nonce_registry_history_deletion_is_fatal_after_terminal_payload_erasure(tmp_path):
    store = _store(tmp_path)
    try:
        record, _ = store.reserve(_envelope(), payload_capacity=3, tombstone_capacity=3)
        store.terminal(record, DeliveryState.BLOCKED, reason="test_terminal")
        nonce = store._connection.execute("SELECT nonce FROM nonce_tombstones").fetchone()[0]
        store.close()
        connection = sqlite3.connect(tmp_path / "state" / "mattermost-outbox.sqlite3")
        try:
            connection.execute("DELETE FROM nonce_tombstones WHERE nonce=?", (nonce,))
            connection.commit()
        finally:
            connection.close()
        with pytest.raises(ContractError, match="nonce registry"):
            MattermostOutbox.open(
                tmp_path / "state", tmp_path / "key", expected_fingerprint=key_fingerprint(bytes(range(32)))
            )
    finally:
        try:
            store.close()
        except sqlite3.ProgrammingError:
            pass


def test_nonce_registry_prefix_rollback_is_fatal_while_newer_terminal_row_remains(tmp_path):
    store = _store(tmp_path)
    try:
        store.reserve(_envelope(), payload_capacity=3, tombstone_capacity=3)
        later, _ = store.reserve(
            _envelope(source="second-source", root="second-root"), payload_capacity=3, tombstone_capacity=3
        )
        store.terminal(later, DeliveryState.BLOCKED, reason="test_terminal")
        first_root = store._connection.execute(
            "SELECT chain_tag FROM nonce_tombstones WHERE sequence=1"
        ).fetchone()[0]
        store.close()
        connection = sqlite3.connect(tmp_path / "state" / "mattermost-outbox.sqlite3")
        try:
            connection.execute("DELETE FROM nonce_tombstones WHERE sequence > 1")
            connection.execute("UPDATE nonce_registry SET sequence=1, root_tag=? WHERE singleton=1", (first_root,))
            connection.commit()
        finally:
            connection.close()
        with pytest.raises(ContractError, match="nonce registry"):
            MattermostOutbox.open(
                tmp_path / "state", tmp_path / "key", expected_fingerprint=key_fingerprint(bytes(range(32)))
            )
    finally:
        try:
            store.close()
        except sqlite3.ProgrammingError:
            pass


def test_restoring_an_older_authentic_ready_row_after_delivery_is_fatal(tmp_path):
    store = _store(tmp_path)
    try:
        waiting, _ = store.reserve(_envelope(), payload_capacity=3, tombstone_capacity=3)
        ready = store.mark_ready(waiting, {**_envelope(), "response": "answer"})
        ready_snapshot = store._connection.execute(
            "SELECT state,generation,updated_at,nonce_sequence,nonce,ciphertext,reason,returned_post_tag,auth_tag FROM records WHERE record_tag=?",
            (ready.record_tag,),
        ).fetchone()
        claimed = store.claim_delivery(ready)
        assert claimed is not None
        assert store.delivered(claimed, returned_post_id="returned") is not None
        store._connection.execute(
            "UPDATE records SET state=?,generation=?,updated_at=?,nonce_sequence=?,nonce=?,ciphertext=?,reason=?,returned_post_tag=?,auth_tag=? WHERE record_tag=?",
            tuple(ready_snapshot) + (ready.record_tag,),
        )
        with pytest.raises(ContractError, match="record history"):
            store.get(ready.record_tag)
        store.close()
        with pytest.raises(ContractError, match="record history"):
            MattermostOutbox.open(
                tmp_path / "state", tmp_path / "key", expected_fingerprint=key_fingerprint(bytes(range(32)))
            )
    finally:
        try:
            store.close()
        except sqlite3.ProgrammingError:
            pass


def test_deleting_an_older_terminal_row_is_fatal_while_newer_terminal_history_remains(tmp_path):
    store = _store(tmp_path)
    try:
        first, _ = store.reserve(_envelope(), payload_capacity=3, tombstone_capacity=3)
        assert store.terminal(first, DeliveryState.BLOCKED, reason="test_terminal") is not None
        later, _ = store.reserve(
            _envelope(source="second-source", root="second-root"), payload_capacity=3, tombstone_capacity=3
        )
        assert store.terminal(later, DeliveryState.BLOCKED, reason="test_terminal") is not None
        store._connection.execute("DELETE FROM records WHERE record_tag=?", (first.record_tag,))
        with pytest.raises(ContractError, match="record history"):
            store.reserve(_envelope(), payload_capacity=3, tombstone_capacity=3)
        store.close()
        with pytest.raises(ContractError, match="record history"):
            MattermostOutbox.open(
                tmp_path / "state", tmp_path / "key", expected_fingerprint=key_fingerprint(bytes(range(32)))
            )
    finally:
        try:
            store.close()
        except sqlite3.ProgrammingError:
            pass


def test_runtime_open_probes_state_directory_writability_before_using_the_database(tmp_path, monkeypatch):
    store = _store(tmp_path)
    key_path = tmp_path / "key"
    store.close()
    original_open = mattermost_outbox.os.open

    def reject_write_probe(path, flags, *args, **kwargs):
        if Path(path).name.startswith(".mattermost-outbox-write-probe-"):
            raise PermissionError("read-only state")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(mattermost_outbox.os, "open", reject_write_probe)
    with pytest.raises(ContractError, match="writable"):
        MattermostOutbox.open(
            tmp_path / "state", key_path, expected_fingerprint=key_fingerprint(bytes(range(32)))
        )
    assert not list((tmp_path / "state").glob(".mattermost-outbox-write-probe-*"))


def test_second_process_cannot_open_the_outbox_while_the_owner_connection_lives(tmp_path):
    store = _store(tmp_path)
    try:
        program = r'''
from pathlib import Path
from restricted_runtime.contracts import ContractError
from restricted_runtime.mattermost_outbox import MattermostOutbox, key_fingerprint
try:
    candidate = MattermostOutbox.open(Path(r"""%s"""), Path(r"""%s"""), expected_fingerprint=key_fingerprint(bytes(range(32))))
    candidate.close()
    print("opened")
except ContractError:
    print("blocked")
''' % (tmp_path / "state", tmp_path / "key")
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        assert result.stdout.strip() == "blocked"
    finally:
        store.close()


def test_startup_acquires_exclusive_writer_before_its_first_integrity_read(tmp_path, monkeypatch):
    store = _store(tmp_path)
    key_path = tmp_path / "key"
    record, _ = store.reserve(_envelope(), payload_capacity=3, tombstone_capacity=3)
    store.close()
    original_connect = mattermost_outbox.sqlite3.connect
    writer_outcomes = []
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

    class ProbeConnection:
        def __init__(self, inner):
            object.__setattr__(self, "inner", inner)
            object.__setattr__(self, "probed", False)

        def __getattr__(self, name):
            return getattr(self.inner, name)

        def __setattr__(self, name, value):
            if name in {"inner", "probed"}:
                object.__setattr__(self, name, value)
            else:
                setattr(self.inner, name, value)

        def execute(self, statement, *args, **kwargs):
            if statement == "PRAGMA integrity_check" and not self.probed:
                self.probed = True
                result = subprocess.run(
                    [sys.executable, "-c", writer, str(tmp_path / "state" / "mattermost-outbox.sqlite3"), record.record_tag],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10,
                )
                writer_outcomes.append(result.stdout.strip())
            return self.inner.execute(statement, *args, **kwargs)

    monkeypatch.setattr(mattermost_outbox.sqlite3, "connect", lambda *args, **kwargs: ProbeConnection(original_connect(*args, **kwargs)))
    reopened = MattermostOutbox.open(
        tmp_path / "state", key_path, expected_fingerprint=key_fingerprint(bytes(range(32)))
    )
    try:
        assert writer_outcomes == ["blocked"]
        assert reopened.get(record.record_tag) is not None
        assert not reopened._connection.in_transaction
    finally:
        reopened.close()


def test_aad_tag_tampering_and_wrong_key_fail_before_record_use(tmp_path):
    store = _store(tmp_path)
    try:
        record, _ = store.reserve(_envelope(), payload_capacity=2, tombstone_capacity=2)
        store._connection.execute(
            "UPDATE records SET source_tag=CASE WHEN substr(source_tag,1,1)='0' THEN '1' || substr(source_tag,2) ELSE '0' || substr(source_tag,2) END WHERE record_tag=?",
            (record.record_tag,),
        )
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


@pytest.mark.parametrize("terminal", [DeliveryState.AMBIGUOUS, DeliveryState.BLOCKED, DeliveryState.FAILED, DeliveryState.EXPIRED])
def test_terminal_root_fence_rejects_later_reply_before_capacity_or_payload_use(tmp_path, terminal):
    store = _store(tmp_path)
    try:
        first, _ = store.reserve(_envelope(), payload_capacity=3, tombstone_capacity=3)
        store.terminal(first, terminal, reason="test_terminal")
        # A distinct source in the same root must be rejected without growing
        # the database, even though the downstream conversation epoch could
        # have reset in the meantime.
        before = store._connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        with pytest.raises(ContractError, match="root is fenced"):
            store.reserve(_envelope(source="later-source"), payload_capacity=3, tombstone_capacity=3)
        assert store._connection.execute("SELECT COUNT(*) FROM records").fetchone()[0] == before
        independent, created = store.reserve(_envelope(source="independent", root="other-root"), payload_capacity=3, tombstone_capacity=3)
        assert created and independent.state is DeliveryState.WAITING_COMMIT
    finally:
        store.close()


def test_compare_and_set_never_dispatches_from_a_stale_ready_generation(tmp_path):
    store = _store(tmp_path)
    try:
        waiting, _ = store.reserve(_envelope(), payload_capacity=3, tombstone_capacity=3)
        ready = store.mark_ready(waiting, _envelope(epoch="epoch", response="RESPONSE_CANARY"))
        first = store.claim_delivery(ready)
        assert first is not None and first.state is DeliveryState.IN_FLIGHT
        assert store.claim_delivery(ready) is None
        current = store.get(ready.record_tag)
        assert current is not None and current.state is DeliveryState.IN_FLIGHT
    finally:
        store.close()


def test_total_tombstone_capacity_reserves_room_for_every_active_record(tmp_path):
    store = _store(tmp_path)
    try:
        one, created = store.reserve(_envelope(), payload_capacity=10, tombstone_capacity=1)
        assert created
        # A second active record would make it impossible to preserve the
        # required permanent tombstone fence after both reach terminal states.
        with pytest.raises(ContractError, match="capacity"):
            store.reserve(_envelope(source="second", root="second-root"), payload_capacity=10, tombstone_capacity=1)
        store.terminal(one, DeliveryState.BLOCKED, reason="bound_response")
        with pytest.raises(ContractError, match="capacity"):
            store.reserve(_envelope(source="third", root="third-root"), payload_capacity=10, tombstone_capacity=1)
    finally:
        store.close()


@pytest.mark.parametrize(
    ("column", "value"),
    [("state", DeliveryState.READY.value), ("root_tag", "0" * 64)],
)
def test_terminal_metadata_mutation_is_fatal_before_a_tombstone_can_be_used(tmp_path, column, value):
    store = _store(tmp_path)
    key_path = tmp_path / "key"
    try:
        record, _ = store.reserve(_envelope(), payload_capacity=2, tombstone_capacity=2)
        terminal = store.terminal(record, DeliveryState.BLOCKED, reason="test_terminal")
        assert terminal is not None and terminal.envelope is None
        store.close()
        connection = sqlite3.connect(tmp_path / "state" / "mattermost-outbox.sqlite3")
        try:
            connection.execute(f"UPDATE records SET {column}=? WHERE record_tag=?", (value, record.record_tag))
            connection.commit()
        finally:
            connection.close()
        with pytest.raises(ContractError, match="authentication"):
            MattermostOutbox.open(tmp_path / "state", key_path, expected_fingerprint=key_fingerprint(bytes(range(32))))
    finally:
        try:
            store.close()
        except sqlite3.ProgrammingError:
            pass


def test_startup_authenticates_inflight_ciphertext_before_any_recovery_effect(tmp_path):
    store = _store(tmp_path)
    key_path = tmp_path / "key"
    try:
        waiting, _ = store.reserve(_envelope(), payload_capacity=2, tombstone_capacity=2)
        ready = store.mark_ready(waiting, _envelope(epoch="epoch", response="RESPONSE_CANARY"))
        assert store.claim_delivery(ready) is not None
        store._connection.execute("UPDATE records SET ciphertext=x'00' WHERE record_tag=?", (waiting.record_tag,))
        store.close()
        with pytest.raises(ContractError, match="authentication"):
            MattermostOutbox.open(tmp_path / "state", key_path, expected_fingerprint=key_fingerprint(bytes(range(32))))
    finally:
        try:
            store.close()
        except sqlite3.ProgrammingError:
            pass


def test_tampered_duplicate_fails_with_the_original_contract_error_not_a_rollback_escape(tmp_path):
    store = _store(tmp_path)
    try:
        record, _ = store.reserve(_envelope(), payload_capacity=2, tombstone_capacity=2)
        store._connection.execute("UPDATE records SET ciphertext=x'00' WHERE record_tag=?", (record.record_tag,))
        with pytest.raises(ContractError, match="authentication"):
            store.reserve(_envelope(), payload_capacity=2, tombstone_capacity=2)
    finally:
        store.close()


def test_delivered_tombstone_authenticates_an_irreversible_returned_post_receipt(tmp_path):
    store = _store(tmp_path)
    try:
        waiting, _ = store.reserve(_envelope(), payload_capacity=2, tombstone_capacity=2)
        ready = store.mark_ready(waiting, _envelope(epoch="epoch", response="RESPONSE_CANARY"))
        flight = store.claim_delivery(ready)
        assert flight is not None
        delivered = store.delivered(flight, returned_post_id="returned-post-one")
        assert delivered is not None and delivered.state is DeliveryState.DELIVERED
        tag = store._connection.execute(
            "SELECT returned_post_tag FROM records WHERE record_tag=?", (flight.record_tag,)
        ).fetchone()[0]
        assert isinstance(tag, str) and len(tag) == 64 and "returned-post-one" not in tag
        assert tag == store._tag("returned-post", flight.record_tag, "returned-post-one")
        assert tag != store._tag("returned-post", flight.record_tag, "returned-post-two")
    finally:
        store.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode hardening")
def test_initialize_hardens_an_explicit_preexisting_empty_mount_before_sqlite_creation(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o777)
    os.chmod(state, 0o777)
    key_path = tmp_path / "key"
    key = _key(key_path)
    store = MattermostOutbox.initialize(state, key_path, expected_fingerprint=key_fingerprint(key))
    try:
        assert (state.stat().st_mode & 0o777) == 0o700
    finally:
        store.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink initialization rejection")
@pytest.mark.parametrize("planted", ["symlink", "database"])
def test_initialize_rejects_planted_state_before_sqlite_can_follow_or_overwrite_it(tmp_path, planted):
    state = tmp_path / "state"
    if planted == "symlink":
        target = tmp_path / "target"
        target.mkdir()
        state.symlink_to(target, target_is_directory=True)
    else:
        state.mkdir()
        (state / "mattermost-outbox.sqlite3").write_bytes(b"not-a-database")
    key_path = tmp_path / "key"
    key = _key(key_path)
    with pytest.raises(ContractError, match="initialization state"):
        MattermostOutbox.initialize(state, key_path, expected_fingerprint=key_fingerprint(key))
    if planted == "symlink":
        assert not (target / "mattermost-outbox.sqlite3").exists()
