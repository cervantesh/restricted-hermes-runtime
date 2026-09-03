"""Encrypted, single-replica delivery outbox for the restricted Mattermost edge.

This module deliberately owns only local SQLite state.  It never imports the
conversation runtime or PostgreSQL client; the edge talks to the existing UDS
contract through its caller.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .contracts import ContractError, jcs_bytes, load_closed_json


OUTBOX_SCHEMA = "restricted-mattermost-outbox.v1"
OUTBOX_DB_NAME = "mattermost-outbox.sqlite3"
_META_SCHEMA = "restricted-mattermost-outbox-meta.v1"
_TERMINAL = {"DELIVERED", "AMBIGUOUS", "BLOCKED", "FAILED", "EXPIRED"}
_ACTIVE = {"WAITING_COMMIT", "READY", "IN_FLIGHT"}
_ENVELOPE_FIELDS = {
    "schema_version", "tenant_id", "origin", "channel_id", "root_id", "source_id", "actor_id",
    "message", "conversation_id", "conversation_epoch", "client_request_id", "policy_epoch",
    "policy_digest", "key_fingerprint", "policy_expires_at", "payload_expires_at", "response",
    "pending_post_id", "returned_post_id",
}


class DeliveryState(StrEnum):
    WAITING_COMMIT = "WAITING_COMMIT"
    READY = "READY"
    IN_FLIGHT = "IN_FLIGHT"
    DELIVERED = "DELIVERED"
    AMBIGUOUS = "AMBIGUOUS"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True)
class OutboxRecord:
    record_tag: str
    source_tag: str
    root_tag: str
    state: DeliveryState
    generation: int
    created_at: int
    updated_at: int
    payload_expires_at: int
    policy_expires_at: int
    envelope: dict[str, Any] | None
    reason: str | None


def _now() -> int:
    return int(time.time())


def _key_file(path: Path) -> bytes:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or (os.name != "nt" and before.st_mode & 0o077):
            raise ContractError("Mattermost outbox key artifact rejected")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        try:
            opened = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise ContractError("Mattermost outbox key artifact changed during open")
            raw = os.read(descriptor, 33)
        finally:
            os.close(descriptor)
        if len(raw) != 32:
            raise ContractError("Mattermost outbox key must be exactly 32 bytes")
        return raw
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError("Mattermost outbox key artifact unavailable") from exc


def key_fingerprint(key: bytes) -> str:
    if len(key) != 32:
        raise ContractError("Mattermost outbox key must be exactly 32 bytes")
    return hashlib.sha256(key).hexdigest()


def _derive(master: bytes, instance_id: bytes, purpose: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=instance_id, info=b"restricted-mattermost-outbox\0" + purpose).derive(master)


def _state_dir(path: Path, *, create: bool) -> None:
    try:
        if create:
            path.mkdir(mode=0o700, parents=True, exist_ok=False)
        details = path.stat()
        if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(path.lstat().st_mode):
            raise ContractError("Mattermost outbox state directory rejected")
        owner = getattr(os, "geteuid", lambda: details.st_uid)()
        if details.st_uid != owner or (os.name != "nt" and stat.S_IMODE(details.st_mode) != 0o700):
            raise ContractError("Mattermost outbox state directory ownership rejected")
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError("Mattermost outbox state directory unavailable") from exc


class MattermostOutbox:
    """One encrypted SQLite database with durable source and root fences."""

    def __init__(self, database: Path, master_key: bytes, *, expected_fingerprint: str):
        self.path = database
        self._master = master_key
        self.fingerprint = key_fingerprint(master_key)
        if not hmac.compare_digest(self.fingerprint, expected_fingerprint):
            raise ContractError("Mattermost outbox policy key binding rejected")
        self._lock = threading.RLock()
        self._connection = self._connect()
        self._instance_id = self._meta()
        self._enc_key = _derive(master_key, self._instance_id, b"aes-256-gcm")
        self._tag_key = _derive(master_key, self._instance_id, b"lookup-hmac-sha256")

    @classmethod
    def initialize(cls, state_dir: Path, key_path: Path, *, expected_fingerprint: str) -> "MattermostOutbox":
        """Explicit operator-only initialization; runtime open never creates state."""
        # A named Docker volume is mounted as an empty directory before the
        # explicit initializer runs.  Accept that one empty mountpoint, but
        # never an existing database, entry, symlink, or non-directory.  The
        # normal runtime path is ``open`` and cannot take this branch.
        if state_dir.exists():
            try:
                details = state_dir.lstat()
                if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode) or any(state_dir.iterdir()):
                    raise ContractError("Mattermost outbox initialization state is not empty")
            except ContractError:
                raise
            except OSError as exc:
                raise ContractError("Mattermost outbox initialization state unavailable") from exc
        else:
            _state_dir(state_dir, create=True)
        database = state_dir / OUTBOX_DB_NAME
        key = _key_file(key_path)
        if not hmac.compare_digest(key_fingerprint(key), expected_fingerprint):
            raise ContractError("Mattermost outbox policy key binding rejected")
        connection = sqlite3.connect(database, isolation_level=None)
        try:
            cls._configure(connection)
            cls._create_schema(connection, secrets.token_bytes(16), key_fingerprint(key))
        finally:
            connection.close()
        return cls(database, key, expected_fingerprint=expected_fingerprint)

    @classmethod
    def open(cls, state_dir: Path, key_path: Path, *, expected_fingerprint: str) -> "MattermostOutbox":
        _state_dir(state_dir, create=False)
        database = state_dir / OUTBOX_DB_NAME
        if not database.is_file() or database.is_symlink():
            raise ContractError("Mattermost outbox database is not initialized")
        return cls(database, _key_file(key_path), expected_fingerprint=expected_fingerprint)

    @staticmethod
    def _configure(connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=5000")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ContractError("Mattermost outbox integrity check failed")

    @staticmethod
    def _create_schema(connection: sqlite3.Connection, instance_id: bytes, fingerprint: str) -> None:
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute("CREATE TABLE meta (schema_version TEXT NOT NULL, instance_id BLOB NOT NULL, key_fingerprint TEXT NOT NULL)")
            connection.execute("INSERT INTO meta VALUES (?, ?, ?)", (_META_SCHEMA, instance_id, fingerprint))
            connection.execute(
                "CREATE TABLE records (record_tag TEXT PRIMARY KEY, source_tag TEXT UNIQUE NOT NULL, root_tag TEXT NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, payload_expires_at INTEGER NOT NULL, policy_expires_at INTEGER NOT NULL, policy_digest TEXT NOT NULL, nonce BLOB, ciphertext BLOB, reason TEXT)"
            )
            connection.execute("CREATE INDEX records_root_order ON records(root_tag, created_at, record_tag)")
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
            self._configure(connection)
            return connection
        except (sqlite3.Error, OSError) as exc:
            raise ContractError("Mattermost outbox database unavailable") from exc

    def _meta(self) -> bytes:
        try:
            rows = self._connection.execute("SELECT schema_version, instance_id, key_fingerprint FROM meta").fetchall()
            if len(rows) != 1 or rows[0][0] != _META_SCHEMA or not isinstance(rows[0][1], bytes) or len(rows[0][1]) != 16:
                raise ContractError("Mattermost outbox metadata rejected")
            if not hmac.compare_digest(rows[0][2], self.fingerprint):
                raise ContractError("Mattermost outbox database key binding rejected")
            return rows[0][1]
        except ContractError:
            raise
        except (sqlite3.Error, TypeError) as exc:
            raise ContractError("Mattermost outbox metadata unavailable") from exc

    def close(self) -> None:
        self._connection.close()

    def _tag(self, domain: str, *parts: str) -> str:
        payload = domain.encode("ascii") + b"\0" + b"\0".join(part.encode("utf-8") for part in parts)
        return hmac.new(self._tag_key, payload, hashlib.sha256).hexdigest()

    def source_tag(self, envelope: dict[str, Any]) -> str:
        return self._tag("source", envelope["tenant_id"], envelope["origin"], envelope["channel_id"], envelope["source_id"])

    def root_tag(self, envelope: dict[str, Any]) -> str:
        return self._tag("root", envelope["tenant_id"], envelope["origin"], envelope["channel_id"], envelope["root_id"])

    def record_tag(self, envelope: dict[str, Any]) -> str:
        return self._tag("record", envelope["tenant_id"], envelope["origin"], envelope["channel_id"], envelope["source_id"])

    def _aad(self, *, record_tag: str, source_tag: str, root_tag: str, policy_digest: str) -> bytes:
        return jcs_bytes({"schema_version": OUTBOX_SCHEMA, "record_tag": record_tag, "source_tag": source_tag, "root_tag": root_tag, "policy_digest": policy_digest})

    def _seal(self, envelope: dict[str, Any], *, record_tag: str, source_tag: str, root_tag: str) -> tuple[bytes, bytes]:
        if set(envelope) != _ENVELOPE_FIELDS or envelope.get("schema_version") != OUTBOX_SCHEMA:
            raise ContractError("Mattermost outbox envelope schema rejected")
        nonce = secrets.token_bytes(12)
        payload = AESGCM(self._enc_key).encrypt(nonce, jcs_bytes(envelope), self._aad(record_tag=record_tag, source_tag=source_tag, root_tag=root_tag, policy_digest=envelope["policy_digest"]))
        return nonce, payload

    def _open_envelope(self, row: sqlite3.Row) -> dict[str, Any]:
        if row["nonce"] is None or row["ciphertext"] is None:
            raise ContractError("Mattermost outbox payload was erased")
        try:
            raw = AESGCM(self._enc_key).decrypt(row["nonce"], row["ciphertext"], self._aad(record_tag=row["record_tag"], source_tag=row["source_tag"], root_tag=row["root_tag"], policy_digest=row["policy_digest"]))
            envelope = load_closed_json(raw)
        except Exception as exc:
            raise ContractError("Mattermost outbox payload authentication failed") from exc
        if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_FIELDS or envelope.get("schema_version") != OUTBOX_SCHEMA:
            raise ContractError("Mattermost outbox envelope schema rejected")
        if (
            not hmac.compare_digest(self.source_tag(envelope), row["source_tag"])
            or not hmac.compare_digest(self.root_tag(envelope), row["root_tag"])
            or not hmac.compare_digest(self.record_tag(envelope), row["record_tag"])
            or envelope["policy_digest"] != row["policy_digest"]
        ):
            raise ContractError("Mattermost outbox lookup binding rejected")
        return envelope

    @staticmethod
    def _record(row: sqlite3.Row, envelope: dict[str, Any] | None) -> OutboxRecord:
        return OutboxRecord(row["record_tag"], row["source_tag"], row["root_tag"], DeliveryState(row["state"]), row["generation"], row["created_at"], row["updated_at"], row["payload_expires_at"], row["policy_expires_at"], envelope, row["reason"])

    def _fetch(self, record_tag: str, *, decrypt: bool = True) -> OutboxRecord | None:
        self._connection.row_factory = sqlite3.Row
        row = self._connection.execute("SELECT * FROM records WHERE record_tag=?", (record_tag,)).fetchone()
        if row is None:
            return None
        envelope = self._open_envelope(row) if decrypt and row["nonce"] is not None else None
        return self._record(row, envelope)

    def reserve(self, envelope: dict[str, Any], *, payload_capacity: int, tombstone_capacity: int) -> tuple[OutboxRecord, bool]:
        """Commit the encrypted reservation before any UDS request."""
        record_tag, source_tag, root_tag = self.record_tag(envelope), self.source_tag(envelope), self.root_tag(envelope)
        nonce, ciphertext = self._seal(envelope, record_tag=record_tag, source_tag=source_tag, root_tag=root_tag)
        now = _now()
        with self._lock:
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute("SELECT * FROM records WHERE source_tag=?", (source_tag,)).fetchone()
                if row is not None:
                    self._connection.execute("COMMIT")
                    return self._record(row, self._open_envelope(row) if row["nonce"] is not None else None), False
                fence = self._connection.execute("SELECT 1 FROM records WHERE root_tag=? AND state<>? LIMIT 1", (root_tag, DeliveryState.DELIVERED.value)).fetchone()
                if fence is not None:
                    raise ContractError("Mattermost outbox root is fenced")
                active = self._connection.execute("SELECT COUNT(*) FROM records WHERE nonce IS NOT NULL").fetchone()[0]
                tombstones = self._connection.execute("SELECT COUNT(*) FROM records WHERE nonce IS NULL").fetchone()[0]
                # Every active record must be able to become a permanent
                # tombstone without exceeding the signed total fence bound.
                # Limiting only existing erased rows would admit more active
                # work than the database can safely retain after completion.
                if active >= payload_capacity or active + tombstones >= tombstone_capacity:
                    raise ContractError("Mattermost outbox capacity reached")
                self._connection.execute(
                    "INSERT INTO records(record_tag,source_tag,root_tag,state,generation,created_at,updated_at,payload_expires_at,policy_expires_at,policy_digest,nonce,ciphertext,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
                    (record_tag, source_tag, root_tag, DeliveryState.WAITING_COMMIT.value, 0, now, now, envelope["payload_expires_at"], envelope["policy_expires_at"], envelope["policy_digest"], nonce, ciphertext),
                )
                row = self._connection.execute("SELECT * FROM records WHERE record_tag=?", (record_tag,)).fetchone()
                self._connection.execute("COMMIT")
                return self._record(row, envelope), True
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def update_waiting(self, record: OutboxRecord, envelope: dict[str, Any]) -> OutboxRecord:
        return self._transition(record, DeliveryState.WAITING_COMMIT, DeliveryState.WAITING_COMMIT, envelope=envelope)

    def mark_ready(self, record: OutboxRecord, envelope: dict[str, Any]) -> OutboxRecord:
        return self._transition(record, DeliveryState.WAITING_COMMIT, DeliveryState.READY, envelope=envelope)

    def claim_delivery(self, record: OutboxRecord) -> OutboxRecord | None:
        return self._transition(record, DeliveryState.READY, DeliveryState.IN_FLIGHT, envelope=record.envelope, missing_ok=True)

    def terminal(self, record: OutboxRecord, state: DeliveryState, *, reason: str) -> OutboxRecord | None:
        if state.value not in _TERMINAL:
            raise ContractError("Mattermost outbox terminal state rejected")
        return self._transition(record, record.state, state, envelope=None, reason=reason, missing_ok=True)

    def _transition(self, record: OutboxRecord, expected: DeliveryState, target: DeliveryState, *, envelope: dict[str, Any] | None, reason: str | None = None, missing_ok: bool = False) -> OutboxRecord | None:
        if record.state != expected:
            raise ContractError("Mattermost outbox transition state rejected")
        nonce = ciphertext = None
        if envelope is not None:
            nonce, ciphertext = self._seal(envelope, record_tag=record.record_tag, source_tag=record.source_tag, root_tag=record.root_tag)
        now = _now()
        with self._lock:
            cursor = self._connection.execute(
                "UPDATE records SET state=?, generation=generation+1, updated_at=?, nonce=?, ciphertext=?, reason=? WHERE record_tag=? AND state=? AND generation=?",
                (target.value, now, nonce, ciphertext, reason, record.record_tag, expected.value, record.generation),
            )
            if cursor.rowcount != 1:
                if missing_ok:
                    return None
                raise ContractError("Mattermost outbox compare-and-set rejected")
            refreshed = self.get(record.record_tag)
            if refreshed is None:
                raise ContractError("Mattermost outbox record disappeared")
            return refreshed

    def get(self, record_tag: str) -> OutboxRecord | None:
        with self._lock:
            self._connection.row_factory = sqlite3.Row
            row = self._connection.execute("SELECT * FROM records WHERE record_tag=?", (record_tag,)).fetchone()
            if row is None:
                return None
            return self._record(row, self._open_envelope(row) if row["nonce"] is not None else None)

    def stale_inflight_to_ambiguous(self) -> int:
        with self._lock:
            now = _now()
            cursor = self._connection.execute(
                "UPDATE records SET state=?, generation=generation+1, updated_at=?, nonce=NULL, ciphertext=NULL, reason=? WHERE state=?",
                (DeliveryState.AMBIGUOUS.value, now, "restart_in_flight", DeliveryState.IN_FLIGHT.value),
            )
            return cursor.rowcount

    def candidates(self, limit: int) -> list[OutboxRecord]:
        with self._lock:
            self._connection.row_factory = sqlite3.Row
            rows = self._connection.execute(
                "SELECT * FROM records WHERE state IN (?,?,?) ORDER BY root_tag, created_at, record_tag LIMIT ?",
                tuple(item.value for item in (DeliveryState.WAITING_COMMIT, DeliveryState.READY, DeliveryState.IN_FLIGHT)) + (limit,),
            ).fetchall()
            return [self._record(row, self._open_envelope(row) if row["nonce"] is not None else None) for row in rows]
