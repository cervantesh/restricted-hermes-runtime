"""PostgreSQL-only durable stores. No SQLite fallback and no plaintext SQL parameters."""
from __future__ import annotations
import uuid
from typing import Any
import psycopg
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from .contracts import AttemptState, ContractError, ProviderResult, TurnState
from .crypto import GATEWAY_MAC_DOMAIN, MacRecord, kms_mac_input
from .conversation import TurnRow
from .gateway import GatewayEnvelope

class PostgresLedger:
    def __init__(self, connection_string: str, policy, mac_key=None): self.connection_string, self.policy, self.mac_key = connection_string, policy, mac_key
    def _connect(self): return psycopg.connect(self.connection_string, row_factory=dict_row)
    def _same(self, row, envelope, principal, mac):
        sink = {k: self.policy.values[k] for k in ("vertex_project_id","vertex_project_number","model_resource","generate_content_path","location","hostname","method","model")}
        actual = (str(row["turn_id"]),str(row["client_request_id"]),row["authenticated_caller_principal"],row["conversation_epoch"],row["policy_epoch"],row["policy_digest"],bytes(row["request_mac"]),row["sink_tuple"])
        wanted = (envelope.turn_id,envelope.client_request_id,principal,envelope.conversation_epoch,envelope.policy_epoch,envelope.policy_digest,mac,sink)
        if actual != wanted: raise ContractError("ledger replay association conflict")
        if self.mac_key and not self.mac_key.verify(MacRecord(row["mac_key_resource"],row["mac_key_version"],bytes(row["request_mac"])),kms_mac_input(GATEWAY_MAC_DOMAIN,envelope.canonical(principal))): raise ContractError("stored ledger MAC verification failed")
    def reserve(self, envelope: GatewayEnvelope, principal: str, mac: bytes, key_resource: str, key_version: str) -> AttemptState:
        sink = {k: self.policy.values[k] for k in ("vertex_project_id","vertex_project_number","model_resource","generate_content_path","location","hostname","method","model")}
        with self._connect() as conn, conn.cursor() as cur:
            # Both reserve and NOT_FOUND fence lock this durable identity guard;
            # neither can observe an absent attempt while the other writes a tombstone.
            cur.execute("INSERT INTO inference_ledger.dispatch_guards (tenant_id,turn_id,client_request_id,policy_epoch,policy_digest) VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",(envelope.tenant_id,envelope.turn_id,envelope.client_request_id,envelope.policy_epoch,envelope.policy_digest))
            cur.execute("SELECT * FROM inference_ledger.dispatch_guards WHERE tenant_id=%s AND (turn_id=%s OR client_request_id=%s) FOR UPDATE",(envelope.tenant_id,envelope.turn_id,envelope.client_request_id));guard=cur.fetchone()
            if (str(guard["turn_id"]),str(guard["client_request_id"]),guard["policy_epoch"],guard["policy_digest"]) != (envelope.turn_id,envelope.client_request_id,envelope.policy_epoch,envelope.policy_digest): raise ContractError("guard remap conflict")
            cur.execute("SELECT * FROM inference_ledger.attempts WHERE tenant_id=%s AND (turn_id=%s OR client_request_id=%s) FOR UPDATE", (envelope.tenant_id,envelope.turn_id,envelope.client_request_id)); row=cur.fetchone()
            if row: self._same(row,envelope,principal,mac); return AttemptState(row["state"])
            cur.execute("SELECT * FROM inference_ledger.cancellation_tombstones WHERE tenant_id=%s AND (turn_id=%s OR client_request_id=%s) FOR UPDATE", (envelope.tenant_id,envelope.turn_id,envelope.client_request_id)); tomb=cur.fetchone()
            if tomb:
                if (str(tomb["turn_id"]),str(tomb["client_request_id"]),tomb["policy_epoch"],tomb["policy_digest"]) != (envelope.turn_id,envelope.client_request_id,envelope.policy_epoch,envelope.policy_digest): raise ContractError("tombstone remap conflict")
                return AttemptState.CANCELLED_NO_DISPATCH
            cur.execute("INSERT INTO inference_ledger.attempts (tenant_id,turn_id,client_request_id,decision_id,conversation_epoch,authenticated_caller_principal,request_mac,mac_key_resource,mac_key_version,policy_epoch,policy_digest,sink_tuple,state) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'RESERVED') ON CONFLICT DO NOTHING", (envelope.tenant_id,envelope.turn_id,envelope.client_request_id,str(uuid.uuid4()),envelope.conversation_epoch,principal,mac,key_resource,key_version,envelope.policy_epoch,envelope.policy_digest,psycopg.types.json.Jsonb(sink)))
            if cur.rowcount == 1: return AttemptState.RESERVED
            cur.execute("SELECT * FROM inference_ledger.attempts WHERE tenant_id=%s AND (turn_id=%s OR client_request_id=%s) FOR UPDATE", (envelope.tenant_id,envelope.turn_id,envelope.client_request_id)); row=cur.fetchone()
            if not row: raise ContractError("concurrent reservation did not converge")
            self._same(row,envelope,principal,mac); return AttemptState(row["state"])
    def start_dispatch(self, tenant_id: str, turn_id: str) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE inference_ledger.attempts SET state='DISPATCH_STARTED',updated_at=transaction_timestamp() WHERE tenant_id=%s AND turn_id=%s AND state='RESERVED'",(tenant_id,turn_id)); return cur.rowcount == 1
    def finish(self, tenant_id: str, turn_id: str, result: ProviderResult) -> None:
        state=result.state if result.state in {"SUCCEEDED","FAILED","INDETERMINATE"} else "INDETERMINATE"
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE inference_ledger.attempts SET state=%s,failure_class=%s,provider_request_id=%s,updated_at=transaction_timestamp() WHERE tenant_id=%s AND turn_id=%s AND state='DISPATCH_STARTED'",(state,result.failure_class,result.request_id,tenant_id,turn_id))
            if cur.rowcount != 1: raise ContractError("ledger terminal CAS failed")
    def status(self, tenant_id: str, turn_id: str, *, client_request_id: str|None=None, policy_epoch: str|None=None, policy_digest: str|None=None) -> AttemptState|None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM inference_ledger.attempts WHERE tenant_id=%s AND turn_id=%s",(tenant_id,turn_id)); row=cur.fetchone()
            if row:
                if not all((client_request_id,policy_epoch,policy_digest)) or (str(row["client_request_id"]),row["policy_epoch"],row["policy_digest"]) != (client_request_id,policy_epoch,policy_digest):raise ContractError("status identity mismatch")
                return AttemptState(row["state"])
            cur.execute("SELECT * FROM inference_ledger.cancellation_tombstones WHERE tenant_id=%s AND turn_id=%s",(tenant_id,turn_id)); tomb=cur.fetchone()
            if tomb and (not all((client_request_id,policy_epoch,policy_digest)) or (str(tomb["client_request_id"]),tomb["policy_epoch"],tomb["policy_digest"]) != (client_request_id,policy_epoch,policy_digest)):raise ContractError("tombstone identity mismatch")
            return AttemptState.CANCELLED_NO_DISPATCH if tomb else None
    def fence(self, tenant_id: str, turn_id: str, *, client_request_id: str|None=None, policy_epoch: str|None=None, policy_digest: str|None=None) -> AttemptState:
        with self._connect() as conn, conn.cursor() as cur:
            if not all((client_request_id,policy_epoch,policy_digest)):
                # Existing attempts may supply identity after their durable guard
                # is locked; NOT_FOUND has no safe abbreviated form.
                cur.execute("SELECT client_request_id,policy_epoch,policy_digest FROM inference_ledger.dispatch_guards WHERE tenant_id=%s AND turn_id=%s FOR UPDATE",(tenant_id,turn_id));known=cur.fetchone()
                if known: client_request_id,policy_epoch,policy_digest=str(known["client_request_id"]),known["policy_epoch"],known["policy_digest"]
                else: raise ContractError("NOT_FOUND fence requires complete identity")
            cur.execute("INSERT INTO inference_ledger.dispatch_guards (tenant_id,turn_id,client_request_id,policy_epoch,policy_digest) VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",(tenant_id,turn_id,client_request_id,policy_epoch,policy_digest))
            cur.execute("SELECT * FROM inference_ledger.dispatch_guards WHERE tenant_id=%s AND (turn_id=%s OR client_request_id=%s) FOR UPDATE",(tenant_id,turn_id,client_request_id));guard=cur.fetchone()
            if (str(guard["turn_id"]),str(guard["client_request_id"]),guard["policy_epoch"],guard["policy_digest"]) != (turn_id,client_request_id,policy_epoch,policy_digest): raise ContractError("guard remap conflict")
            cur.execute("SELECT * FROM inference_ledger.attempts WHERE tenant_id=%s AND turn_id=%s FOR UPDATE",(tenant_id,turn_id)); row=cur.fetchone()
            if row is None:
                cur.execute("INSERT INTO inference_ledger.cancellation_tombstones (tenant_id,turn_id,client_request_id,policy_epoch,policy_digest) VALUES (%s,%s,%s,%s,%s) ON CONFLICT (tenant_id,turn_id) DO NOTHING",(tenant_id,turn_id,client_request_id,policy_epoch,policy_digest)); return AttemptState.CANCELLED_NO_DISPATCH
            if row["state"] == "RESERVED":
                cur.execute("UPDATE inference_ledger.attempts SET state='CANCELLED_NO_DISPATCH',fence_generation=fence_generation+1,updated_at=transaction_timestamp() WHERE tenant_id=%s AND turn_id=%s AND state='RESERVED'",(tenant_id,turn_id)); return AttemptState.CANCELLED_NO_DISPATCH
            return AttemptState(row["state"])

class PostgresContentStore:
    def __init__(self, connection_string: str): self.connection_string=connection_string
    def _connect(self): return psycopg.connect(self.connection_string,row_factory=dict_row)
    def create_conversation(self, tenant_id: str, conversation_id: str) -> str:
        epoch=str(uuid.uuid4())
        with self._connect() as conn,conn.cursor() as cur:
            cur.execute("INSERT INTO restricted_content.conversations (tenant_id,conversation_id,conversation_epoch) VALUES (%s,%s,%s) ON CONFLICT (tenant_id,conversation_id) DO NOTHING RETURNING conversation_epoch",(tenant_id,conversation_id,epoch));row=cur.fetchone()
            if row:return row["conversation_epoch"]
            cur.execute("SELECT conversation_epoch FROM restricted_content.conversations WHERE tenant_id=%s AND conversation_id=%s",(tenant_id,conversation_id));return cur.fetchone()["conversation_epoch"]
    @staticmethod
    def _row(r:dict[str,Any])->TurnRow:
        return TurnRow(r["tenant_id"],r["conversation_id"],r["conversation_epoch"],str(r["turn_id"]),str(r["client_request_id"]),r["authenticated_caller_principal"],bytes(r["request_mac"]),r["mac_key_resource"],r["mac_key_version"],r["policy_digest"],TurnState(r["state"]),bytes(r["request_ciphertext"]),bytes(r["request_nonce"]),bytes(r["response_ciphertext"]) if r["response_ciphertext"] else None,bytes(r["response_nonce"]) if r["response_nonce"] else None,bytes(r["wrapped_data_key"]),r["lease_generation"])
    def admit(self,c:TurnRow)->tuple[TurnRow,bool]:
        with self._connect() as conn,conn.cursor() as cur:
            cur.execute("SELECT * FROM restricted_content.turns WHERE tenant_id=%s AND client_request_id=%s FOR UPDATE",(c.tenant_id,c.client_request_id)); old=cur.fetchone()
            if old:return self._row(old),False
            cur.execute("INSERT INTO restricted_content.conversations (tenant_id,conversation_id,conversation_epoch) VALUES (%s,%s,%s) ON CONFLICT (tenant_id,conversation_id) DO UPDATE SET conversation_id=EXCLUDED.conversation_id RETURNING conversation_epoch",(c.tenant_id,c.conversation_id,c.conversation_epoch));
            if cur.fetchone()["conversation_epoch"]!=c.conversation_epoch:raise ContractError("stale conversation epoch")
            # A concurrent same-key admission can win while this transaction
            # waits for the conversation row lock. Recheck before ACTIVE_TURN.
            cur.execute("SELECT * FROM restricted_content.turns WHERE tenant_id=%s AND client_request_id=%s FOR UPDATE",(c.tenant_id,c.client_request_id));old=cur.fetchone()
            if old:return self._row(old),False
            cur.execute("SELECT 1 FROM restricted_content.turns WHERE tenant_id=%s AND conversation_id=%s AND conversation_epoch=%s AND state NOT IN ('COMMITTED','REJECTED','FAILED','INDETERMINATE')",(c.tenant_id,c.conversation_id,c.conversation_epoch))
            if cur.fetchone():raise ContractError("ACTIVE_TURN")
            cur.execute("INSERT INTO restricted_content.turns (tenant_id,conversation_id,conversation_epoch,turn_id,client_request_id,authenticated_caller_principal,schema_version,request_mac,mac_key_resource,mac_key_version,request_ciphertext,request_nonce,wrapped_data_key,policy_digest,state,lease_owner,lease_generation,lease_expires_at) VALUES (%s,%s,%s,%s,%s,%s,'restricted-turn.v1',%s,%s,%s,%s,%s,%s,%s,%s,'handler',0,transaction_timestamp()+interval '90 seconds') ON CONFLICT (tenant_id,client_request_id) DO NOTHING",(c.tenant_id,c.conversation_id,c.conversation_epoch,c.turn_id,c.client_request_id,c.principal,c.request_mac,c.mac_key_resource,c.mac_key_version,c.request_ciphertext,c.request_nonce,c.wrapped_data_key,c.policy_digest,c.state.value))
            if cur.rowcount:return c,True
            cur.execute("SELECT * FROM restricted_content.turns WHERE tenant_id=%s AND client_request_id=%s FOR UPDATE",(c.tenant_id,c.client_request_id)); return self._row(cur.fetchone()),False
    def admit_with_history(self, *, tenant_id: str, conversation_id: str, conversation_epoch: str,
                           client_request_id: str, build_row) -> tuple[TurnRow, bool]:
        """Admit a turn while the conversation lock also protects its history read.

        ``build_row`` is called only after the idempotency lookup and the
        conversation row lock have both succeeded.  This keeps the exact
        ordered history encrypted into a newly admitted request from racing a
        terminal turn committed by another replica.
        """
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM restricted_content.turns WHERE tenant_id=%s AND client_request_id=%s FOR UPDATE", (tenant_id, client_request_id)); old=cur.fetchone()
            if old:
                return self._row(old), False
            cur.execute("INSERT INTO restricted_content.conversations (tenant_id,conversation_id,conversation_epoch) VALUES (%s,%s,%s) ON CONFLICT (tenant_id,conversation_id) DO NOTHING", (tenant_id,conversation_id,conversation_epoch))
            cur.execute("SELECT * FROM restricted_content.conversations WHERE tenant_id=%s AND conversation_id=%s FOR UPDATE", (tenant_id,conversation_id)); conversation=cur.fetchone()
            if not conversation or conversation["conversation_epoch"] != conversation_epoch:
                raise ContractError("stale conversation epoch")
            cur.execute("SELECT * FROM restricted_content.turns WHERE tenant_id=%s AND client_request_id=%s FOR UPDATE", (tenant_id, client_request_id)); old=cur.fetchone()
            if old:
                return self._row(old), False
            cur.execute("SELECT 1 FROM restricted_content.turns WHERE tenant_id=%s AND conversation_id=%s AND conversation_epoch=%s AND state NOT IN ('COMMITTED','REJECTED','FAILED','INDETERMINATE')", (tenant_id,conversation_id,conversation_epoch))
            if cur.fetchone():
                raise ContractError("ACTIVE_TURN")
            cur.execute("SELECT * FROM restricted_content.turns WHERE tenant_id=%s AND conversation_id=%s AND conversation_epoch=%s AND state='COMMITTED' ORDER BY created_at,turn_id", (tenant_id,conversation_id,conversation_epoch))
            history=[self._row(row) for row in cur.fetchall()]
            candidate = build_row(history)
            cur.execute("INSERT INTO restricted_content.turns (tenant_id,conversation_id,conversation_epoch,turn_id,client_request_id,authenticated_caller_principal,schema_version,request_mac,mac_key_resource,mac_key_version,request_ciphertext,request_nonce,wrapped_data_key,policy_digest,state,lease_owner,lease_generation,lease_expires_at) VALUES (%s,%s,%s,%s,%s,%s,'restricted-turn.v1',%s,%s,%s,%s,%s,%s,%s,%s,'handler',0,transaction_timestamp()+interval '90 seconds') ON CONFLICT (tenant_id,client_request_id) DO NOTHING", (candidate.tenant_id,candidate.conversation_id,candidate.conversation_epoch,candidate.turn_id,candidate.client_request_id,candidate.principal,candidate.request_mac,candidate.mac_key_resource,candidate.mac_key_version,candidate.request_ciphertext,candidate.request_nonce,candidate.wrapped_data_key,candidate.policy_digest,candidate.state.value))
            if cur.rowcount:
                return candidate, True
            cur.execute("SELECT * FROM restricted_content.turns WHERE tenant_id=%s AND client_request_id=%s FOR UPDATE", (tenant_id,client_request_id)); return self._row(cur.fetchone()),False
    def committed_history(self,t:str,c:str,e:str)->list[TurnRow]:
        with self._connect() as conn,conn.cursor() as cur:
            cur.execute("SELECT * FROM restricted_content.turns WHERE tenant_id=%s AND conversation_id=%s AND conversation_epoch=%s AND state='COMMITTED' ORDER BY created_at,turn_id",(t,c,e));return [self._row(x) for x in cur.fetchall()]
    def read_turn(self,t:str,turn:str)->TurnRow:
        with self._connect() as conn,conn.cursor() as cur:
            cur.execute("SELECT * FROM restricted_content.turns WHERE tenant_id=%s AND turn_id=%s",(t,turn));row=cur.fetchone()
            if not row:raise ContractError("turn not found")
            return self._row(row)
    def set_state_cas(self,t:str,turn:str,g:int,expected:TurnState,target:TurnState,**u:object)->bool:
        if set(u)-{"response_ciphertext","response_nonce"}:raise ContractError("unapproved content transition field")
        sets=["state=%s","updated_at=transaction_timestamp()"]+[f"{k}=%s" for k in u]
        with self._connect() as conn,conn.cursor() as cur:
            cur.execute(f"UPDATE restricted_content.turns SET {','.join(sets)} WHERE tenant_id=%s AND turn_id=%s AND lease_generation=%s AND state=%s",[target.value,*u.values(),t,turn,g,expected.value]);return cur.rowcount==1
    def reset(self,t:str,c:str,e:str)->str:
        with self._connect() as conn,conn.cursor() as cur:
            cur.execute("SELECT conversation_epoch FROM restricted_content.conversations WHERE tenant_id=%s AND conversation_id=%s FOR UPDATE",(t,c));row=cur.fetchone()
            if not row or row["conversation_epoch"]!=e:raise ContractError("stale conversation epoch")
            cur.execute("SELECT 1 FROM restricted_content.turns WHERE tenant_id=%s AND conversation_id=%s AND conversation_epoch=%s AND state NOT IN ('COMMITTED','REJECTED','FAILED','INDETERMINATE')",(t,c,e))
            if cur.fetchone():raise ContractError("ACTIVE_TURN")
            nxt=str(uuid.uuid4());cur.execute("UPDATE restricted_content.conversations SET conversation_epoch=%s WHERE tenant_id=%s AND conversation_id=%s",(nxt,t,c));return nxt
    def claim_expired_lease(self,t:str,turn:str,owner:str,seconds:int=30)->int|None:
        with self._connect() as conn,conn.cursor() as cur:
            cur.execute("UPDATE restricted_content.turns SET lease_owner=%s,lease_generation=lease_generation+1,lease_expires_at=transaction_timestamp()+(%s || ' seconds')::interval,updated_at=transaction_timestamp() WHERE tenant_id=%s AND turn_id=%s AND state NOT IN ('COMMITTED','REJECTED','FAILED','INDETERMINATE') AND lease_expires_at<transaction_timestamp() RETURNING lease_generation",(owner,seconds,t,turn));row=cur.fetchone();return row["lease_generation"] if row else None
    def renew_lease(self,t:str,turn:str,g:int,seconds:int=90)->bool:
        with self._connect() as conn,conn.cursor() as cur:
            cur.execute("UPDATE restricted_content.turns SET lease_expires_at=transaction_timestamp()+(%s || ' seconds')::interval,updated_at=transaction_timestamp() WHERE tenant_id=%s AND turn_id=%s AND lease_generation=%s AND state='INFERENCE_PENDING'",(seconds,t,turn,g));return cur.rowcount==1
    def expired_turns(self, limit:int=32)->list[TurnRow]:
        with self._connect() as conn,conn.cursor() as cur:
            cur.execute("SELECT * FROM restricted_content.turns WHERE state NOT IN ('COMMITTED','REJECTED','FAILED','INDETERMINATE') AND lease_expires_at<transaction_timestamp() ORDER BY lease_expires_at LIMIT %s",(limit,));return [self._row(r) for r in cur.fetchall()]
    def mark_terminal_cas(self,t:str,turn:str,g:int,state:TurnState,failure_class:str|None)->bool:
        if state not in {TurnState.FAILED,TurnState.INDETERMINATE}:raise ContractError("reconciler terminal restriction")
        with self._connect() as conn,conn.cursor() as cur:
            cur.execute("UPDATE restricted_content.turns SET state=%s,failure_class=%s,updated_at=transaction_timestamp() WHERE tenant_id=%s AND turn_id=%s AND lease_generation=%s AND state NOT IN ('COMMITTED','REJECTED','FAILED','INDETERMINATE')",(state.value,failure_class,t,turn,g));return cur.rowcount==1
