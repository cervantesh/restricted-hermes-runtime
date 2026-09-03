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
CLINICAL_OUTBOX_SCHEMA = "restricted-mattermost-clinical-outbox.v1"
OUTBOX_DB_NAME = "mattermost-outbox.sqlite3"
_META_SCHEMA = "restricted-mattermost-outbox-meta.v7"
_TERMINAL = {"DELIVERED", "AMBIGUOUS", "BLOCKED", "FAILED", "EXPIRED"}
_ACTIVE = {"WAITING_COMMIT", "READY", "IN_FLIGHT"}
_ENVELOPE_FIELDS = {
    "schema_version", "tenant_id", "origin", "channel_id", "root_id", "source_id", "actor_id",
    "message", "conversation_id", "conversation_epoch", "client_request_id", "policy_epoch",
    "policy_digest", "key_fingerprint", "policy_expires_at", "payload_expires_at", "response",
    "pending_post_id", "returned_post_id",
}
_CLINICAL_ENVELOPE_FIELDS = {
    "schema_version", "tenant_id", "origin", "channel_id", "root_id", "source_id", "actor_id",
    "patient_id", "operation", "request_id", "source_message", "integration_id", "clinical_policy_id", "policy_epoch", "policy_digest",
    "key_fingerprint", "policy_expires_at", "payload_expires_at", "clinic_timezone", "appointment",
    "response", "response_digest", "pending_post_id", "returned_post_id",
}
_ROW_FIELDS = (
    "record_tag", "source_tag", "root_tag", "state", "generation", "created_at", "updated_at",
    "payload_expires_at", "policy_expires_at", "policy_digest", "nonce_sequence", "nonce", "ciphertext", "reason",
    "returned_post_tag",
)


def _valid_envelope(envelope: dict[str, Any]) -> bool:
    schema = envelope.get("schema_version")
    return (
        schema == OUTBOX_SCHEMA and set(envelope) == _ENVELOPE_FIELDS
    ) or (
        schema == CLINICAL_OUTBOX_SCHEMA and set(envelope) == _CLINICAL_ENVELOPE_FIELDS
    )


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
    returned_post_tag: str | None = None


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


def _initialization_directory(path: Path) -> int | None:
    """Harden one explicit empty mount before SQLite is allowed to create a file."""
    try:
        try:
            before = path.lstat()
        except FileNotFoundError:
            path.mkdir(mode=0o700, parents=True, exist_ok=False)
            before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise ContractError("Mattermost outbox initialization state is not empty")
        if os.name == "nt":
            if any(path.iterdir()):
                raise ContractError("Mattermost outbox initialization state is not empty")
            return None
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or not stat.S_ISDIR(opened.st_mode):
            os.close(descriptor)
            raise ContractError("Mattermost outbox initialization state changed during open")
        if any(os.listdir(descriptor)):
            os.close(descriptor)
            raise ContractError("Mattermost outbox initialization state is not empty")
        current_uid = getattr(os, "geteuid", lambda: opened.st_uid)()
        if opened.st_uid != current_uid and current_uid != 0:
            os.close(descriptor)
            raise ContractError("Mattermost outbox initialization ownership rejected")
        os.fchmod(descriptor, 0o700)
        return descriptor
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError("Mattermost outbox initialization state unavailable") from exc


class MattermostOutbox:
    """One encrypted SQLite database with durable source and root fences."""

    def __init__(
        self,
        database: Path,
        master_key: bytes,
        *,
        expected_fingerprint: str,
        bootstrap_nonce_registry: bool = False,
    ):
        self.path = database
        self._master = master_key
        self.fingerprint = key_fingerprint(master_key)
        if not hmac.compare_digest(self.fingerprint, expected_fingerprint):
            raise ContractError("Mattermost outbox policy key binding rejected")
        self._lock = threading.RLock()
        self._connection = self._connect()
        try:
            # ``_connect`` began EXCLUSIVE before this first integrity/schema
            # read.  Keep it through all startup authentication, then release
            # only the transaction (not the persistent exclusive lock).
            self._integrity_check()
            self._instance_id = self._meta()
            self._enc_key = _derive(master_key, self._instance_id, b"aes-256-gcm")
            self._tag_key = _derive(master_key, self._instance_id, b"lookup-hmac-sha256")
            self._row_key = _derive(master_key, self._instance_id, b"row-hmac-sha256")
            self._nonce_key = _derive(master_key, self._instance_id, b"nonce-registry-hmac-sha256")
            self._history_key = _derive(master_key, self._instance_id, b"record-history-hmac-sha256")
            self._bootstrap_nonce_registry(bootstrap_nonce_registry)
            self._verify_all_rows()
            self._database_write_probe()
            self._connection.execute("COMMIT" if bootstrap_nonce_registry else "ROLLBACK")
        except ContractError:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            self.close()
            raise
        except sqlite3.Error as exc:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            self.close()
            raise ContractError("Mattermost outbox startup ownership rejected") from exc

    @classmethod
    def initialize(cls, state_dir: Path, key_path: Path, *, expected_fingerprint: str) -> "MattermostOutbox":
        """Explicit operator-only initialization; runtime open never creates state."""
        database = state_dir / OUTBOX_DB_NAME
        key = _key_file(key_path)
        if not hmac.compare_digest(key_fingerprint(key), expected_fingerprint):
            raise ContractError("Mattermost outbox policy key binding rejected")
        directory = _initialization_directory(state_dir)
        connection: sqlite3.Connection | None = None
        try:
            if directory is not None:
                try:
                    os.stat(OUTBOX_DB_NAME, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ContractError("Mattermost outbox initialization state is not empty")
                database_for_create = Path(f"/proc/self/fd/{directory}/{OUTBOX_DB_NAME}")
            else:
                database_for_create = database
            connection = sqlite3.connect(database_for_create, isolation_level=None)
            cls._configure(connection)
            cls._create_schema(connection, secrets.token_bytes(16), key_fingerprint(key))
        except ContractError:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise ContractError("Mattermost outbox database initialization unavailable") from exc
        finally:
            if connection is not None:
                connection.close()
            if directory is not None:
                os.close(directory)
        if os.name != "nt":
            try:
                os.chmod(database, 0o600)
            except OSError as exc:
                raise ContractError("Mattermost outbox database mode unavailable") from exc
        return cls(
            database,
            key,
            expected_fingerprint=expected_fingerprint,
            bootstrap_nonce_registry=True,
        )

    @classmethod
    def open(cls, state_dir: Path, key_path: Path, *, expected_fingerprint: str) -> "MattermostOutbox":
        _state_dir(state_dir, create=False)
        database = state_dir / OUTBOX_DB_NAME
        try:
            details = database.lstat()
            current_uid = getattr(os, "geteuid", lambda: details.st_uid)()
            if (
                not stat.S_ISREG(details.st_mode) or stat.S_ISLNK(details.st_mode)
                or details.st_uid != current_uid
                or (os.name != "nt" and stat.S_IMODE(details.st_mode) != 0o600)
            ):
                raise ContractError("Mattermost outbox database is not initialized")
        except ContractError:
            raise
        except OSError as exc:
            raise ContractError("Mattermost outbox database is not initialized") from exc
        cls._state_write_probe(state_dir)
        return cls(database, _key_file(key_path), expected_fingerprint=expected_fingerprint)

    @staticmethod
    def _state_write_probe(state_dir: Path) -> None:
        """Prove the protected state directory can create and remove a file."""
        descriptor: int | None = None
        directory: int | None = None
        name = ".mattermost-outbox-write-probe-" + secrets.token_hex(16)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            if os.name != "nt":
                directory = os.open(state_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
                descriptor = os.open(name, flags, 0o600, dir_fd=directory)
            else:
                descriptor = os.open(state_dir / name, flags, 0o600)
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            if directory is not None:
                os.unlink(name, dir_fd=directory)
            else:
                os.unlink(state_dir / name)
        except OSError as exc:
            raise ContractError("Mattermost outbox state is not writable") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                try:
                    os.unlink(name, dir_fd=directory)
                except FileNotFoundError:
                    pass
                finally:
                    os.close(directory)

    @staticmethod
    def _configure(connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        locking_mode = connection.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()
        if locking_mode != ("exclusive",):
            raise ContractError("Mattermost outbox exclusive ownership rejected")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=5000")

    @staticmethod
    def _create_schema(connection: sqlite3.Connection, instance_id: bytes, fingerprint: str) -> None:
        connection.execute("BEGIN EXCLUSIVE")
        try:
            connection.execute("CREATE TABLE meta (schema_version TEXT NOT NULL, instance_id BLOB NOT NULL, key_fingerprint TEXT NOT NULL)")
            connection.execute("INSERT INTO meta VALUES (?, ?, ?)", (_META_SCHEMA, instance_id, fingerprint))
            connection.execute(
                "CREATE TABLE records (record_tag TEXT PRIMARY KEY, source_tag TEXT UNIQUE NOT NULL, root_tag TEXT NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, payload_expires_at INTEGER NOT NULL, policy_expires_at INTEGER NOT NULL, policy_digest TEXT NOT NULL, nonce_sequence INTEGER NOT NULL, nonce BLOB, ciphertext BLOB, reason TEXT, returned_post_tag TEXT, auth_tag TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE nonce_tombstones (sequence INTEGER PRIMARY KEY, nonce BLOB UNIQUE NOT NULL, chain_tag TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE nonce_registry (singleton INTEGER PRIMARY KEY CHECK(singleton=1), sequence INTEGER NOT NULL, root_tag TEXT NOT NULL)"
            )
            connection.execute("INSERT INTO nonce_registry VALUES (1, 0, '')")
            connection.execute(
                "CREATE TABLE record_history (nonce_sequence INTEGER PRIMARY KEY, record_tag TEXT NOT NULL, generation INTEGER NOT NULL, state TEXT NOT NULL, row_auth_tag TEXT NOT NULL, history_tag TEXT NOT NULL)"
            )
            connection.execute("CREATE TABLE recovery_cursor (singleton INTEGER PRIMARY KEY CHECK(singleton=1), root_tag TEXT NOT NULL, created_at INTEGER NOT NULL, record_tag TEXT NOT NULL)")
            connection.execute("INSERT INTO recovery_cursor VALUES (1, '', -1, '')")
            connection.execute("CREATE INDEX records_root_order ON records(root_tag, created_at, record_tag)")
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise

    def _connect(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
            self._configure(connection)
            connection.execute("BEGIN EXCLUSIVE")
            return connection
        except ContractError:
            if connection is not None:
                connection.close()
            raise
        except (sqlite3.Error, OSError) as exc:
            if connection is not None:
                connection.close()
            raise ContractError("Mattermost outbox database unavailable") from exc

    def _integrity_check(self) -> None:
        try:
            if self._connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise ContractError("Mattermost outbox integrity check failed")
        except ContractError:
            raise
        except sqlite3.Error as exc:
            raise ContractError("Mattermost outbox integrity check failed") from exc

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

    def _database_write_probe(self) -> None:
        """Acquire a durable SQLite write transaction without changing outbox state."""
        try:
            with self._lock:
                if self._connection.in_transaction:
                    self._connection.execute("UPDATE meta SET schema_version=schema_version")
                    return
                self._connection.execute("BEGIN IMMEDIATE")
                try:
                    self._connection.execute("UPDATE meta SET schema_version=schema_version")
                finally:
                    if self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
        except sqlite3.Error as exc:
            raise ContractError("Mattermost outbox database is not writable") from exc

    def close(self) -> None:
        self._connection.close()

    def _tag(self, domain: str, *parts: str) -> str:
        payload = domain.encode("ascii") + b"\0" + b"\0".join(part.encode("utf-8") for part in parts)
        return hmac.new(self._tag_key, payload, hashlib.sha256).hexdigest()

    def _nonce_genesis(self) -> str:
        return hmac.new(
            self._nonce_key,
            jcs_bytes({"schema_version": OUTBOX_SCHEMA, "domain": "nonce-registry.v1"}),
            hashlib.sha256,
        ).hexdigest()

    def _nonce_chain_tag(self, *, sequence: int, nonce: bytes, previous: str) -> str:
        try:
            return hmac.new(
                self._nonce_key,
                jcs_bytes(
                    {
                        "schema_version": OUTBOX_SCHEMA,
                        "sequence": sequence,
                        "nonce": nonce.hex(),
                        "previous": previous,
                    }
                ),
                hashlib.sha256,
            ).hexdigest()
        except (TypeError, ValueError, UnicodeError, ContractError) as exc:
            raise ContractError("Mattermost outbox nonce registry rejected") from exc

    def _bootstrap_nonce_registry(self, allowed: bool) -> None:
        """Seal the empty registry only during the explicit initialization path."""
        try:
            self._connection.row_factory = sqlite3.Row
            row = self._connection.execute(
                "SELECT singleton, sequence, root_tag FROM nonce_registry WHERE singleton=1"
            ).fetchone()
            if row is None or row["singleton"] != 1:
                raise ContractError("Mattermost outbox nonce registry rejected")
            if row["sequence"] != 0 or row["root_tag"] != "":
                if allowed:
                    raise ContractError("Mattermost outbox nonce registry rejected")
                return
            if not allowed:
                raise ContractError("Mattermost outbox nonce registry rejected")
            # Startup already owns an EXCLUSIVE transaction.  The genesis
            # write must remain inside it so no unauthenticated empty registry
            # can be observed between bootstrap and startup verification.
            if self._connection.execute("SELECT COUNT(*) FROM nonce_tombstones").fetchone()[0] != 0:
                raise ContractError("Mattermost outbox nonce registry rejected")
            updated = self._connection.execute(
                "UPDATE nonce_registry SET root_tag=? WHERE singleton=1 AND sequence=0 AND root_tag=''",
                (self._nonce_genesis(),),
            )
            if updated.rowcount != 1:
                raise ContractError("Mattermost outbox nonce registry rejected")
        except ContractError:
            raise
        except sqlite3.Error as exc:
            raise ContractError("Mattermost outbox nonce registry rejected") from exc

    def _verify_nonce_registry(self) -> int:
        try:
            registry_rows = self._connection.execute(
                "SELECT singleton, sequence, root_tag FROM nonce_registry"
            ).fetchall()
            if (
                len(registry_rows) != 1
                or registry_rows[0]["singleton"] != 1
                or not isinstance(registry_rows[0]["sequence"], int)
                or isinstance(registry_rows[0]["sequence"], bool)
                or registry_rows[0]["sequence"] < 0
                or not isinstance(registry_rows[0]["root_tag"], str)
                or len(registry_rows[0]["root_tag"]) != 64
            ):
                raise ContractError("Mattermost outbox nonce registry rejected")
            previous = self._nonce_genesis()
            expected_sequence = 1
            nonce_rows = self._connection.execute(
                "SELECT sequence, nonce, chain_tag FROM nonce_tombstones ORDER BY sequence"
            ).fetchall()
            for row in nonce_rows:
                sequence, nonce, chain_tag = row["sequence"], row["nonce"], row["chain_tag"]
                if (
                    not isinstance(sequence, int)
                    or isinstance(sequence, bool)
                    or sequence != expected_sequence
                    or not isinstance(nonce, bytes)
                    or len(nonce) != 12
                    or not isinstance(chain_tag, str)
                    or len(chain_tag) != 64
                    or not hmac.compare_digest(
                        chain_tag,
                        self._nonce_chain_tag(sequence=sequence, nonce=nonce, previous=previous),
                    )
                ):
                    raise ContractError("Mattermost outbox nonce registry rejected")
                previous = chain_tag
                expected_sequence += 1
            if (
                registry_rows[0]["sequence"] != expected_sequence - 1
                or not hmac.compare_digest(registry_rows[0]["root_tag"], previous)
            ):
                raise ContractError("Mattermost outbox nonce registry rejected")
            return registry_rows[0]["sequence"]
        except ContractError:
            raise
        except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise ContractError("Mattermost outbox nonce registry rejected") from exc

    def _append_nonce(self, nonce: bytes) -> int:
        """Append one irreversible GCM nonce within the caller's SQLite transaction."""
        try:
            row = self._connection.execute(
                "SELECT singleton, sequence, root_tag FROM nonce_registry WHERE singleton=1"
            ).fetchone()
            if (
                row is None
                or row["singleton"] != 1
                or not isinstance(row["sequence"], int)
                or isinstance(row["sequence"], bool)
                or row["sequence"] < 0
                or not isinstance(row["root_tag"], str)
                or len(row["root_tag"]) != 64
            ):
                raise ContractError("Mattermost outbox nonce registry rejected")
            sequence = row["sequence"] + 1
            chain_tag = self._nonce_chain_tag(sequence=sequence, nonce=nonce, previous=row["root_tag"])
            try:
                self._connection.execute(
                    "INSERT INTO nonce_tombstones(sequence,nonce,chain_tag) VALUES(?,?,?)",
                    (sequence, nonce, chain_tag),
                )
            except sqlite3.IntegrityError as exc:
                raise ContractError("Mattermost outbox nonce reuse rejected") from exc
            updated = self._connection.execute(
                "UPDATE nonce_registry SET sequence=?, root_tag=? WHERE singleton=1 AND sequence=? AND root_tag=?",
                (sequence, chain_tag, row["sequence"], row["root_tag"]),
            )
            if updated.rowcount != 1:
                raise ContractError("Mattermost outbox nonce registry rejected")
            return sequence
        except ContractError:
            raise
        except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise ContractError("Mattermost outbox nonce registry rejected") from exc

    def _fresh_nonce(self) -> bytes:
        nonce = secrets.token_bytes(12)
        if not isinstance(nonce, bytes) or len(nonce) != 12:
            raise ContractError("Mattermost outbox nonce rejected")
        return nonce

    def _history_anchor_sequence(self) -> int:
        """Burn a nonce-chain entry for an erased-payload state transition."""
        try:
            row = self._connection.execute(
                "SELECT sequence FROM nonce_registry WHERE singleton=1"
            ).fetchone()
            if (
                row is None
                or not isinstance(row["sequence"], int)
                or isinstance(row["sequence"], bool)
                or row["sequence"] < 0
            ):
                raise ContractError("Mattermost outbox nonce registry rejected")
            sequence = row["sequence"] + 1
            anchor = hmac.new(
                self._history_key,
                b"record-history-anchor\0" + sequence.to_bytes(8, "big"),
                hashlib.sha256,
            ).digest()[:12]
            return self._append_nonce(anchor)
        except ContractError:
            raise
        except (sqlite3.Error, KeyError, OverflowError, TypeError, ValueError) as exc:
            raise ContractError("Mattermost outbox nonce registry rejected") from exc

    def _history_auth(
        self,
        *,
        nonce_sequence: int,
        record_tag: str,
        generation: int,
        state: str,
        row_auth_tag: str,
    ) -> str:
        try:
            if (
                not isinstance(nonce_sequence, int)
                or isinstance(nonce_sequence, bool)
                or nonce_sequence < 1
                or not isinstance(record_tag, str)
                or len(record_tag) != 64
                or not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation < 0
                or not isinstance(state, str)
                or not isinstance(row_auth_tag, str)
                or len(row_auth_tag) != 64
            ):
                raise TypeError("record history")
            DeliveryState(state)
            return hmac.new(
                self._history_key,
                jcs_bytes(
                    {
                        "schema_version": OUTBOX_SCHEMA,
                        "domain": "record-history.v1",
                        "nonce_sequence": nonce_sequence,
                        "record_tag": record_tag,
                        "generation": generation,
                        "state": state,
                        "row_auth_tag": row_auth_tag,
                    }
                ),
                hashlib.sha256,
            ).hexdigest()
        except (TypeError, ValueError, UnicodeError, ContractError) as exc:
            raise ContractError("Mattermost outbox record history rejected") from exc

    def _append_record_history(self, values: dict[str, Any], row_auth_tag: str) -> None:
        try:
            nonce_sequence = values["nonce_sequence"]
            record_tag = values["record_tag"]
            generation = values["generation"]
            state = values["state"]
            history_tag = self._history_auth(
                nonce_sequence=nonce_sequence,
                record_tag=record_tag,
                generation=generation,
                state=state,
                row_auth_tag=row_auth_tag,
            )
            self._connection.execute(
                "INSERT INTO record_history(nonce_sequence,record_tag,generation,state,row_auth_tag,history_tag) VALUES(?,?,?,?,?,?)",
                (nonce_sequence, record_tag, generation, state, row_auth_tag, history_tag),
            )
        except ContractError:
            raise
        except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise ContractError("Mattermost outbox record history rejected") from exc

    def _verify_record_history(self, rows: list[sqlite3.Row], nonce_registry_sequence: int) -> None:
        try:
            history_rows = self._connection.execute(
                "SELECT nonce_sequence,record_tag,generation,state,row_auth_tag,history_tag FROM record_history ORDER BY nonce_sequence"
            ).fetchall()
            if len(history_rows) != nonce_registry_sequence:
                raise ContractError("Mattermost outbox record history rejected")
            latest: dict[str, sqlite3.Row] = {}
            for expected_sequence, history in enumerate(history_rows, start=1):
                nonce_sequence = history["nonce_sequence"]
                record_tag = history["record_tag"]
                generation = history["generation"]
                state = history["state"]
                row_auth_tag = history["row_auth_tag"]
                history_tag = history["history_tag"]
                if (
                    nonce_sequence != expected_sequence
                    or not isinstance(history_tag, str)
                    or len(history_tag) != 64
                    or not hmac.compare_digest(
                        history_tag,
                        self._history_auth(
                            nonce_sequence=nonce_sequence,
                            record_tag=record_tag,
                            generation=generation,
                            state=state,
                            row_auth_tag=row_auth_tag,
                        ),
                    )
                ):
                    raise ContractError("Mattermost outbox record history rejected")
                previous = latest.get(record_tag)
                if (previous is None and generation != 0) or (
                    previous is not None and generation != previous["generation"] + 1
                ):
                    raise ContractError("Mattermost outbox record history rejected")
                latest[record_tag] = history
            records = {row["record_tag"]: row for row in rows}
            if len(records) != len(rows) or set(records) != set(latest):
                raise ContractError("Mattermost outbox record history rejected")
            for record_tag, row in records.items():
                history = latest[record_tag]
                if (
                    history["nonce_sequence"] != row["nonce_sequence"]
                    or history["generation"] != row["generation"]
                    or history["state"] != row["state"]
                    or not hmac.compare_digest(history["row_auth_tag"], row["auth_tag"])
                ):
                    raise ContractError("Mattermost outbox record history rejected")
        except ContractError:
            raise
        except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise ContractError("Mattermost outbox record history rejected") from exc

    def _row_auth(self, row: Any) -> str:
        try:
            material: dict[str, Any] = {"schema_version": OUTBOX_SCHEMA}
            for name in _ROW_FIELDS:
                value = row[name]
                if name in {"nonce", "ciphertext"}:
                    if value is not None and not isinstance(value, bytes):
                        raise TypeError(name)
                    material[name] = value.hex() if value is not None else None
                elif value is None or isinstance(value, (str, int)) and not isinstance(value, bool):
                    material[name] = value
                else:
                    raise TypeError(name)
            return hmac.new(self._row_key, jcs_bytes(material), hashlib.sha256).hexdigest()
        except (KeyError, TypeError, ValueError, UnicodeError, ContractError) as exc:
            raise ContractError("Mattermost outbox row authentication failed") from exc

    def _verify_row(self, row: sqlite3.Row) -> None:
        try:
            state = DeliveryState(row["state"])
            auth_tag = row["auth_tag"]
            if not isinstance(auth_tag, str) or not hmac.compare_digest(auth_tag, self._row_auth(row)):
                raise ContractError("Mattermost outbox row authentication failed")
            nonce_sequence = row["nonce_sequence"]
            if not isinstance(nonce_sequence, int) or isinstance(nonce_sequence, bool) or nonce_sequence < 1:
                raise ContractError("Mattermost outbox row authentication failed")
            nonce, ciphertext = row["nonce"], row["ciphertext"]
            if (nonce is None) != (ciphertext is None):
                raise ContractError("Mattermost outbox row authentication failed")
            if state.value in _TERMINAL:
                if nonce is not None or ciphertext is not None:
                    raise ContractError("Mattermost outbox row authentication failed")
                if state is DeliveryState.DELIVERED:
                    if not isinstance(row["returned_post_tag"], str) or not row["returned_post_tag"]:
                        raise ContractError("Mattermost outbox row authentication failed")
                elif row["returned_post_tag"] is not None:
                    raise ContractError("Mattermost outbox row authentication failed")
            elif nonce is None or ciphertext is None or row["returned_post_tag"] is not None:
                raise ContractError("Mattermost outbox row authentication failed")
        except ContractError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ContractError("Mattermost outbox row authentication failed") from exc

    def _verify_all_rows(self) -> None:
        try:
            self._connection.row_factory = sqlite3.Row
            nonce_registry_sequence = self._verify_nonce_registry()
            cursor_rows = self._connection.execute("SELECT singleton, root_tag, created_at, record_tag FROM recovery_cursor").fetchall()
            if (
                len(cursor_rows) != 1 or cursor_rows[0]["singleton"] != 1
                or not isinstance(cursor_rows[0]["root_tag"], str)
                or not isinstance(cursor_rows[0]["created_at"], int)
                or not isinstance(cursor_rows[0]["record_tag"], str)
                or (cursor_rows[0]["root_tag"] and len(cursor_rows[0]["root_tag"]) != 64)
                or (cursor_rows[0]["record_tag"] and len(cursor_rows[0]["record_tag"]) != 64)
                or bool(cursor_rows[0]["root_tag"]) != bool(cursor_rows[0]["record_tag"])
            ):
                raise ContractError("Mattermost outbox recovery cursor rejected")
            rows = self._connection.execute("SELECT * FROM records").fetchall()
            for row in rows:
                self._verify_row(row)
                if row["nonce_sequence"] > nonce_registry_sequence:
                    raise ContractError("Mattermost outbox nonce registry rejected")
            self._verify_record_history(rows, nonce_registry_sequence)
            for row in rows:
                if row["nonce"] is not None:
                    self._open_envelope(row)
        except ContractError:
            raise
        except sqlite3.Error as exc:
            raise ContractError("Mattermost outbox row authentication failed") from exc

    def source_tag(self, envelope: dict[str, Any]) -> str:
        return self._tag("source", envelope["tenant_id"], envelope["origin"], envelope["channel_id"], envelope["source_id"])

    def root_tag(self, envelope: dict[str, Any]) -> str:
        return self._tag("root", envelope["tenant_id"], envelope["origin"], envelope["channel_id"], envelope["root_id"])

    def record_tag(self, envelope: dict[str, Any]) -> str:
        return self._tag("record", envelope["tenant_id"], envelope["origin"], envelope["channel_id"], envelope["source_id"])

    def _aad(self, *, record_tag: str, source_tag: str, root_tag: str, policy_digest: str) -> bytes:
        return jcs_bytes({"schema_version": OUTBOX_SCHEMA, "record_tag": record_tag, "source_tag": source_tag, "root_tag": root_tag, "policy_digest": policy_digest})

    def _seal(self, envelope: dict[str, Any], *, record_tag: str, source_tag: str, root_tag: str) -> tuple[bytes, bytes, int]:
        if not _valid_envelope(envelope):
            raise ContractError("Mattermost outbox envelope schema rejected")
        nonce = self._fresh_nonce()
        nonce_sequence = self._append_nonce(nonce)
        payload = AESGCM(self._enc_key).encrypt(nonce, jcs_bytes(envelope), self._aad(record_tag=record_tag, source_tag=source_tag, root_tag=root_tag, policy_digest=envelope["policy_digest"]))
        return nonce, payload, nonce_sequence

    def _open_envelope(self, row: sqlite3.Row) -> dict[str, Any]:
        self._verify_row(row)
        if row["nonce"] is None or row["ciphertext"] is None:
            raise ContractError("Mattermost outbox payload was erased")
        try:
            raw = AESGCM(self._enc_key).decrypt(row["nonce"], row["ciphertext"], self._aad(record_tag=row["record_tag"], source_tag=row["source_tag"], root_tag=row["root_tag"], policy_digest=row["policy_digest"]))
            envelope = load_closed_json(raw)
        except Exception as exc:
            raise ContractError("Mattermost outbox payload authentication failed") from exc
        if not isinstance(envelope, dict) or not _valid_envelope(envelope):
            raise ContractError("Mattermost outbox envelope schema rejected")
        if (
            not hmac.compare_digest(self.source_tag(envelope), row["source_tag"])
            or not hmac.compare_digest(self.root_tag(envelope), row["root_tag"])
            or not hmac.compare_digest(self.record_tag(envelope), row["record_tag"])
            or envelope["policy_digest"] != row["policy_digest"]
        ):
            raise ContractError("Mattermost outbox lookup binding rejected")
        return envelope

    def _record(self, row: sqlite3.Row, envelope: dict[str, Any] | None) -> OutboxRecord:
        self._verify_row(row)
        return OutboxRecord(
            row["record_tag"], row["source_tag"], row["root_tag"], DeliveryState(row["state"]),
            row["generation"], row["created_at"], row["updated_at"], row["payload_expires_at"],
            row["policy_expires_at"], envelope, row["reason"], row["returned_post_tag"],
        )

    def _fetch(self, record_tag: str, *, decrypt: bool = True) -> OutboxRecord | None:
        self._verify_all_rows()
        self._connection.row_factory = sqlite3.Row
        row = self._connection.execute("SELECT * FROM records WHERE record_tag=?", (record_tag,)).fetchone()
        if row is None:
            return None
        envelope = self._open_envelope(row) if decrypt and row["nonce"] is not None else None
        return self._record(row, envelope)

    def reserve(self, envelope: dict[str, Any], *, payload_capacity: int, tombstone_capacity: int) -> tuple[OutboxRecord, bool]:
        """Commit the encrypted reservation before any UDS request."""
        record_tag, source_tag, root_tag = self.record_tag(envelope), self.source_tag(envelope), self.root_tag(envelope)
        now = _now()
        with self._lock:
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._verify_all_rows()
                rows = self._connection.execute("SELECT * FROM records").fetchall()
                for row in rows:
                    self._verify_row(row)
                row = next((item for item in rows if item["source_tag"] == source_tag), None)
                if row is not None:
                    result = self._record(row, self._open_envelope(row) if row["nonce"] is not None else None)
                    self._connection.execute("COMMIT")
                    return result, False
                if any(item["root_tag"] == root_tag and item["state"] != DeliveryState.DELIVERED.value for item in rows):
                    raise ContractError("Mattermost outbox root is fenced")
                active = sum(item["nonce"] is not None for item in rows)
                tombstones = len(rows) - active
                # Every active record must be able to become a permanent
                # tombstone without exceeding the signed total fence bound.
                # Limiting only existing erased rows would admit more active
                # work than the database can safely retain after completion.
                if active >= payload_capacity or active + tombstones >= tombstone_capacity:
                    raise ContractError("Mattermost outbox capacity reached")
                nonce, ciphertext, nonce_sequence = self._seal(
                    envelope, record_tag=record_tag, source_tag=source_tag, root_tag=root_tag
                )
                values = {
                    "record_tag": record_tag, "source_tag": source_tag, "root_tag": root_tag,
                    "state": DeliveryState.WAITING_COMMIT.value, "generation": 0, "created_at": now,
                    "updated_at": now, "payload_expires_at": envelope["payload_expires_at"],
                    "policy_expires_at": envelope["policy_expires_at"], "policy_digest": envelope["policy_digest"],
                    "nonce_sequence": nonce_sequence,
                    "nonce": nonce, "ciphertext": ciphertext, "reason": None, "returned_post_tag": None,
                }
                row_auth_tag = self._row_auth(values)
                self._connection.execute(
                    "INSERT INTO records(record_tag,source_tag,root_tag,state,generation,created_at,updated_at,payload_expires_at,policy_expires_at,policy_digest,nonce_sequence,nonce,ciphertext,reason,returned_post_tag,auth_tag) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(values[name] for name in _ROW_FIELDS) + (row_auth_tag,),
                )
                self._append_record_history(values, row_auth_tag)
                row = self._connection.execute("SELECT * FROM records WHERE record_tag=?", (record_tag,)).fetchone()
                result = self._record(row, envelope)
                self._connection.execute("COMMIT")
                return result, True
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def update_waiting(self, record: OutboxRecord, envelope: dict[str, Any]) -> OutboxRecord:
        return self._transition(record, DeliveryState.WAITING_COMMIT, DeliveryState.WAITING_COMMIT, envelope=envelope)

    def mark_ready(self, record: OutboxRecord, envelope: dict[str, Any]) -> OutboxRecord:
        return self._transition(record, DeliveryState.WAITING_COMMIT, DeliveryState.READY, envelope=envelope)

    def claim_delivery(self, record: OutboxRecord) -> OutboxRecord | None:
        return self._transition(record, DeliveryState.READY, DeliveryState.IN_FLIGHT, envelope=record.envelope, missing_ok=True)

    def terminal(self, record: OutboxRecord, state: DeliveryState, *, reason: str) -> OutboxRecord | None:
        if state.value not in _TERMINAL or state is DeliveryState.DELIVERED:
            raise ContractError("Mattermost outbox terminal state rejected")
        return self._transition(record, record.state, state, envelope=None, reason=reason, missing_ok=True)

    def delivered(self, record: OutboxRecord, *, returned_post_id: str) -> OutboxRecord | None:
        if not isinstance(returned_post_id, str) or not returned_post_id:
            raise ContractError("Mattermost returned post receipt rejected")
        return self._transition(
            record, DeliveryState.IN_FLIGHT, DeliveryState.DELIVERED, envelope=None,
            reason="exact_immediate_binding", missing_ok=True,
            returned_post_tag=self._tag("returned-post", record.record_tag, returned_post_id),
        )

    def _transition(self, record: OutboxRecord, expected: DeliveryState, target: DeliveryState, *, envelope: dict[str, Any] | None, reason: str | None = None, missing_ok: bool = False, returned_post_tag: str | None = None) -> OutboxRecord | None:
        if record.state != expected:
            raise ContractError("Mattermost outbox transition state rejected")
        now = _now()
        with self._lock:
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._verify_all_rows()
                current = self._connection.execute("SELECT * FROM records WHERE record_tag=?", (record.record_tag,)).fetchone()
                if current is None:
                    if missing_ok:
                        self._connection.execute("COMMIT")
                        return None
                    raise ContractError("Mattermost outbox compare-and-set rejected")
                self._verify_row(current)
                if current["state"] != expected.value or current["generation"] != record.generation:
                    if missing_ok:
                        self._connection.execute("COMMIT")
                        return None
                    raise ContractError("Mattermost outbox compare-and-set rejected")
                nonce = ciphertext = None
                if envelope is not None:
                    nonce, ciphertext, nonce_sequence = self._seal(
                        envelope, record_tag=record.record_tag, source_tag=record.source_tag, root_tag=record.root_tag
                    )
                else:
                    nonce_sequence = self._history_anchor_sequence()
                values = {name: current[name] for name in _ROW_FIELDS}
                values.update({
                    "state": target.value, "generation": current["generation"] + 1, "updated_at": now,
                    "nonce_sequence": nonce_sequence, "nonce": nonce, "ciphertext": ciphertext, "reason": reason,
                    "returned_post_tag": returned_post_tag,
                })
                row_auth_tag = self._row_auth(values)
                cursor = self._connection.execute(
                    "UPDATE records SET state=?, generation=?, updated_at=?, nonce_sequence=?, nonce=?, ciphertext=?, reason=?, returned_post_tag=?, auth_tag=? WHERE record_tag=? AND state=? AND generation=?",
                    (
                        values["state"], values["generation"], values["updated_at"], values["nonce_sequence"],
                        values["nonce"], values["ciphertext"], values["reason"], values["returned_post_tag"], row_auth_tag,
                        record.record_tag, expected.value, record.generation,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ContractError("Mattermost outbox compare-and-set rejected")
                self._append_record_history(values, row_auth_tag)
                refreshed_row = self._connection.execute("SELECT * FROM records WHERE record_tag=?", (record.record_tag,)).fetchone()
                if refreshed_row is None:
                    raise ContractError("Mattermost outbox record disappeared")
                refreshed = self._record(
                    refreshed_row, self._open_envelope(refreshed_row) if refreshed_row["nonce"] is not None else None
                )
                self._connection.execute("COMMIT")
                return refreshed
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def get(self, record_tag: str) -> OutboxRecord | None:
        with self._lock:
            self._connection.row_factory = sqlite3.Row
            self._verify_all_rows()
            row = self._connection.execute("SELECT * FROM records WHERE record_tag=?", (record_tag,)).fetchone()
            if row is None:
                return None
            return self._record(row, self._open_envelope(row) if row["nonce"] is not None else None)

    def stale_inflight_to_ambiguous(self) -> int:
        with self._lock:
            self._connection.row_factory = sqlite3.Row
            self._verify_all_rows()
            rows = self._connection.execute(
                "SELECT * FROM records WHERE state=?", (DeliveryState.IN_FLIGHT.value,)
            ).fetchall()
            records = [self._record(row, self._open_envelope(row)) for row in rows]
            return sum(
                self.terminal(record, DeliveryState.AMBIGUOUS, reason="restart_in_flight") is not None
                for record in records
            )

    def candidates(self, limit: int) -> list[OutboxRecord]:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ContractError("Mattermost outbox scan limit rejected")
        with self._lock:
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._verify_all_rows()
                cursor = self._connection.execute(
                    "SELECT root_tag, created_at, record_tag FROM recovery_cursor WHERE singleton=1"
                ).fetchone()
                if (
                    cursor is None or not isinstance(cursor["root_tag"], str)
                    or not isinstance(cursor["created_at"], int) or not isinstance(cursor["record_tag"], str)
                ):
                    raise ContractError("Mattermost outbox recovery cursor rejected")
                states = tuple(item.value for item in (DeliveryState.WAITING_COMMIT, DeliveryState.READY, DeliveryState.IN_FLIGHT))
                rows = self._connection.execute(
                    "SELECT * FROM records WHERE state IN (?,?,?) AND (root_tag>? OR (root_tag=? AND (created_at>? OR (created_at=? AND record_tag>?)))) ORDER BY root_tag, created_at, record_tag LIMIT ?",
                    states + (cursor["root_tag"], cursor["root_tag"], cursor["created_at"], cursor["created_at"], cursor["record_tag"], limit),
                ).fetchall()
                if len(rows) < limit:
                    rows.extend(self._connection.execute(
                        "SELECT * FROM records WHERE state IN (?,?,?) AND (root_tag<? OR (root_tag=? AND (created_at<? OR (created_at=? AND record_tag<=?)))) ORDER BY root_tag, created_at, record_tag LIMIT ?",
                        states + (cursor["root_tag"], cursor["root_tag"], cursor["created_at"], cursor["created_at"], cursor["record_tag"], limit - len(rows)),
                    ).fetchall())
                if rows:
                    self._connection.execute(
                        "UPDATE recovery_cursor SET root_tag=?, created_at=?, record_tag=? WHERE singleton=1",
                        (rows[-1]["root_tag"], rows[-1]["created_at"], rows[-1]["record_tag"]),
                    )
                result = [
                    self._record(row, self._open_envelope(row) if row["nonce"] is not None else None)
                    for row in rows
                ]
                self._connection.execute("COMMIT")
                return result
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
