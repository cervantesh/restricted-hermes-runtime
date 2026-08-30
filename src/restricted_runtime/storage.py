"""PostgreSQL-only repositories. Transaction time and DB constraints are authoritative."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import psycopg
from psycopg.rows import dict_row

from .contracts import AttemptState, ContractError, TurnState
from .gateway import GatewayEnvelope
from .vertex import ProviderResult


class PostgresLedger:
    """Ledger mutations use one transaction; it never stores envelope content."""
    def __init__(self, connection_string: str, policy): self.connection_string, self.policy = connection_string, policy
    def _connect(self): return psycopg.connect(self.connection_string, row_factory=dict_row)
    def reserve(self, envelope: GatewayEnvelope, principal: str, mac: bytes, key_resource: str, key_version: str) -> AttemptState:
        sink = {k: self.policy.values[k] for k in ("vertex_project_id", "vertex_project_number", "model_resource", "generate_content_path", "location", "hostname", "method", "model")}
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT state, turn_id, client_request_id FROM inference_ledger.attempts WHERE tenant_id=%s AND (turn_id=%s OR client_request_id=%s) FOR UPDATE", (envelope.tenant_id, envelope.turn_id, envelope.client_request_id))
            row = cur.fetchone()
            if row:
                if str(row["turn_id"]) != envelope.turn_id or str(row["client_request_id"]) != envelope.client_request_id: raise ContractError("ledger identifier remap")
                return AttemptState(row["state"])
            cur.execute("SELECT 1 FROM inference_ledger.cancellation_tombstones WHERE tenant_id=%s AND (turn_id=%s OR client_request_id=%s)", (envelope.tenant_id, envelope.turn_id, envelope.client_request_id))
            if cur.fetchone(): return AttemptState.CANCELLED_NO_DISPATCH
            cur.execute("INSERT INTO inference_ledger.attempts (tenant_id,turn_id,client_request_id,decision_id,conversation_epoch,authenticated_caller_principal,request_mac,mac_key_resource,mac_key_version,policy_epoch,policy_digest,sink_tuple,state) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'RESERVED')", (envelope.tenant_id, envelope.turn_id, envelope.client_request_id, str(uuid.uuid4()), envelope.conversation_epoch, principal, mac, key_resource, key_version, envelope.policy_epoch, envelope.policy_digest, psycopg.types.json.Jsonb(sink)))
            return AttemptState.RESERVED
    def start_dispatch(self, tenant_id: str, turn_id: str) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE inference_ledger.attempts SET state='DISPATCH_STARTED', updated_at=transaction_timestamp() WHERE tenant_id=%s AND turn_id=%s AND state='RESERVED'", (tenant_id, turn_id)); return cur.rowcount == 1
    def finish(self, tenant_id: str, turn_id: str, result: ProviderResult) -> None:
        state = result.state if result.state in {"SUCCEEDED", "FAILED", "INDETERMINATE"} else "INDETERMINATE"
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE inference_ledger.attempts SET state=%s, failure_class=%s, provider_request_id=%s, updated_at=transaction_timestamp() WHERE tenant_id=%s AND turn_id=%s AND state='DISPATCH_STARTED'", (state, result.failure_class, result.request_id, tenant_id, turn_id))
            if cur.rowcount != 1: raise ContractError("ledger terminal CAS failed")
    def status(self, tenant_id: str, turn_id: str) -> AttemptState | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT state FROM inference_ledger.attempts WHERE tenant_id=%s AND turn_id=%s", (tenant_id, turn_id)); row=cur.fetchone(); return AttemptState(row["state"]) if row else None
    def fence(self, tenant_id: str, turn_id: str) -> AttemptState:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT state, client_request_id, policy_epoch, policy_digest FROM inference_ledger.attempts WHERE tenant_id=%s AND turn_id=%s FOR UPDATE", (tenant_id, turn_id)); row=cur.fetchone()
            if row is None: raise ContractError("fence requires complete identity for NOT_FOUND tombstone")
            if row["state"] == "RESERVED":
                cur.execute("UPDATE inference_ledger.attempts SET state='CANCELLED_NO_DISPATCH', fence_generation=fence_generation+1, updated_at=transaction_timestamp() WHERE tenant_id=%s AND turn_id=%s AND state='RESERVED'", (tenant_id, turn_id)); return AttemptState.CANCELLED_NO_DISPATCH
            return AttemptState(row["state"])


class PostgresContentStore:
    """Content service only. No ledger schema access is requested or used."""
    def __init__(self, connection_string: str): self.connection_string = connection_string
    def _connect(self): return psycopg.connect(self.connection_string, row_factory=dict_row)
    def claim_expired_lease(self, tenant_id: str, turn_id: str, owner: str, seconds: int = 30) -> int | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE restricted_content.turns SET lease_owner=%s, lease_generation=lease_generation+1, lease_expires_at=transaction_timestamp()+(%s || ' seconds')::interval, updated_at=transaction_timestamp() WHERE tenant_id=%s AND turn_id=%s AND state NOT IN ('COMMITTED','REJECTED','FAILED','INDETERMINATE') AND lease_expires_at < transaction_timestamp() RETURNING lease_generation", (owner, seconds, tenant_id, turn_id)); row=cur.fetchone(); return row["lease_generation"] if row else None
    def commit_response_cas(self, tenant_id: str, turn_id: str, generation: int, ciphertext: bytes, nonce: bytes, decision_id: str) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE restricted_content.turns SET response_ciphertext=%s,response_nonce=%s,gateway_decision_id=%s,state='COMMITTED',updated_at=transaction_timestamp() WHERE tenant_id=%s AND turn_id=%s AND lease_generation=%s AND state='RESPONSE_RECEIVED'", (ciphertext, nonce, decision_id, tenant_id, turn_id, generation)); return cur.rowcount == 1
    def mark_terminal_cas(self, tenant_id: str, turn_id: str, generation: int, state: TurnState, failure_class: str | None) -> bool:
        if state not in {TurnState.FAILED, TurnState.INDETERMINATE}:
            raise ContractError("reconciler may only write failure terminals")
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE restricted_content.turns SET state=%s,failure_class=%s,updated_at=transaction_timestamp() WHERE tenant_id=%s AND turn_id=%s AND lease_generation=%s AND state NOT IN ('COMMITTED','REJECTED','FAILED','INDETERMINATE')", (state.value, failure_class, tenant_id, turn_id, generation)); return cur.rowcount == 1
