"""The restricted turn state machine: admission, one gateway call, commit, readback."""
from __future__ import annotations

import os
import threading
import uuid
from dataclasses import dataclass, replace
from typing import Callable, Protocol

from .contracts import ContractError, ProviderResult, TurnRequest, TurnState, content_aad, jcs_bytes
from .crypto import Ciphertext, MacKey, MacRecord, SERVICE_MAC_DOMAIN, decrypt, encrypt, kms_mac_input
from .gateway import GatewayEnvelope
from .policy import PolicyBundle, SYSTEM_INSTRUCTION


class DataKeyWrapper(Protocol):
    def wrap(self, data_key: bytes) -> bytes: ...
    def unwrap(self, wrapped: bytes) -> bytes: ...


@dataclass(frozen=True)
class TurnRow:
    tenant_id: str; conversation_id: str; conversation_epoch: str; turn_id: str; client_request_id: str
    principal: str; request_mac: bytes; mac_key_resource: str; mac_key_version: str; policy_digest: str
    state: TurnState; request_ciphertext: bytes; request_nonce: bytes; response_ciphertext: bytes | None; response_nonce: bytes | None; wrapped_data_key: bytes
    lease_generation: int
    policy_epoch: str = "legacy"
    gateway_decision_id: str | None = None
    gateway_attempt_classification: str | None = None

class ContentStore(Protocol):
    def admit(self, row: TurnRow) -> tuple[TurnRow, bool]: ...
    def committed_history(self, tenant_id: str, conversation_id: str, epoch: str) -> list[TurnRow]: ...
    def set_state_cas(self, tenant_id: str, turn_id: str, generation: int, expected: TurnState, target: TurnState, **updates: object) -> bool: ...
    def read_turn(self, tenant_id: str, turn_id: str) -> TurnRow: ...
    def reset(self, tenant_id: str, conversation_id: str, requested_epoch: str) -> str: ...

class GatewayClient(Protocol):
    def infer_once(self, envelope: GatewayEnvelope, principal: str) -> ProviderResult: ...

@dataclass
class ConversationService:
    store: ContentStore
    gateway: GatewayClient
    mac_key: MacKey
    data_keys: DataKeyWrapper
    policy: PolicyBundle
    tenant_id: str
    lease_heartbeat_seconds: float = 20
    admission_enabled: bool = True
    authorization_gate: Callable[[], None] | None = None

    def _aad(self, row: TurnRow, direction: str) -> bytes:
        return content_aad(tenant_id=row.tenant_id, conversation_id=row.conversation_id, conversation_epoch=row.conversation_epoch, turn_id=row.turn_id, client_request_id=row.client_request_id, direction=direction, policy_digest=row.policy_digest)
    def _verify_duplicate(self, row: TurnRow, request: TurnRequest, principal: str, conversation_id: str) -> None:
        if (row.principal, row.conversation_id, row.conversation_epoch, row.client_request_id) != (principal, conversation_id, request.conversation_epoch, request.client_request_id):
            raise ContractError("idempotency association conflict")
        canonical = jcs_bytes(request.identity(principal=principal, tenant_id=self.tenant_id, conversation_id=conversation_id))
        record = MacRecord(row.mac_key_resource, row.mac_key_version, row.request_mac)
        if not self.mac_key.verify(record, kms_mac_input(SERVICE_MAC_DOMAIN, canonical)):
            raise ContractError("idempotency MAC verification failed")

    def _mark_indeterminate(self, row: TurnRow) -> None:
        """Best-effort durable truth for an exception after admission.

        An exception crossing the provider or durable-response boundary is an
        ambiguous outcome.  The handler must not turn it into success or try a
        second provider call.  CAS keeps a reconciler/new lease owner from
        being overwritten by this stale handler.
        """
        try:
            if row.state == TurnState.INFERENCE_PENDING and self.store.set_state_cas(self.tenant_id, row.turn_id, row.lease_generation, TurnState.INFERENCE_PENDING, TurnState.INDETERMINATE, failure_class="HANDLER_EXCEPTION"):
                return
            if self.store.set_state_cas(self.tenant_id, row.turn_id, row.lease_generation, TurnState.RESPONSE_RECEIVED, TurnState.INDETERMINATE, failure_class="RESPONSE_COMMIT_FAILURE"):
                return
        except Exception:
            # The original exception remains the observable failure.  A
            # reconciler can fence/claim the still non-terminal row later.
            pass
    def submit(self, request: TurnRequest, *, principal: str, conversation_id: str) -> dict[str, str]:
        if not self.admission_enabled:
            raise ContractError("restricted admission is disabled")
        if self.authorization_gate is not None:
            self.authorization_gate()
        canonical = jcs_bytes(request.identity(principal=principal, tenant_id=self.tenant_id, conversation_id=conversation_id))
        if len(canonical) > self.policy.values["max_canonical_input_utf8_bytes"]:
            raise ContractError("canonical input exceeds policy")
        key_record = self.mac_key.sign(kms_mac_input(SERVICE_MAC_DOMAIN, canonical))
        data_key = os.urandom(32)
        turn_id = str(uuid.uuid4())
        messages_for_turn: list[dict[str, str]] = []
        envelope_for_turn: GatewayEnvelope | None = None
        def build_initial(history: list[TurnRow]) -> TurnRow:
            nonlocal messages_for_turn,envelope_for_turn
            initial = TurnRow(self.tenant_id, conversation_id, request.conversation_epoch, turn_id, request.client_request_id, principal, key_record.mac, key_record.key_resource, key_record.key_version, self.policy.digest, TurnState.REQUEST_COMMITTED, b"", b"", None, None, self.data_keys.wrap(data_key), 0, policy_epoch=self.policy.epoch)
            messages_for_turn = self._decrypt_history(history) + [{"role": "user", "text": request.message}]
            envelope_for_turn = GatewayEnvelope(self.tenant_id, conversation_id, request.conversation_epoch, initial.turn_id, request.client_request_id, initial.policy_epoch, initial.policy_digest, "restricted-phi-system.v1", SYSTEM_INSTRUCTION, "PHI", messages_for_turn, self.policy.values["max_canonical_input_utf8_bytes"], authenticated_external_principal=principal)
            if len(envelope_for_turn.canonical()) > self.policy.values["max_canonical_input_utf8_bytes"]:
                raise ContractError("gateway envelope exceeds policy")
            request_payload = jcs_bytes({"system_instruction": SYSTEM_INSTRUCTION, "messages": messages_for_turn})
            encrypted = encrypt(data_key, request_payload, self._aad(initial, "request"))
            return replace(initial, request_ciphertext=encrypted.ciphertext, request_nonce=encrypted.nonce)
        if hasattr(self.store, "admit_with_history"):
            row, created = self.store.admit_with_history(tenant_id=self.tenant_id, conversation_id=conversation_id, conversation_epoch=request.conversation_epoch, client_request_id=request.client_request_id, build_row=build_initial)
        else:
            row, created = self.store.admit(build_initial(self.store.committed_history(self.tenant_id, conversation_id, request.conversation_epoch)))
        self._verify_duplicate(row, request, principal, conversation_id)
        if not created:
            return self._duplicate_result(row)
        if not self.store.set_state_cas(self.tenant_id, row.turn_id, row.lease_generation, TurnState.REQUEST_COMMITTED, TurnState.INFERENCE_PENDING):
            raise ContractError("admitted turn lease lost")
        row = self.store.read_turn(self.tenant_id, row.turn_id)
        if hasattr(self.store,"renew_lease") and not self.store.renew_lease(self.tenant_id,row.turn_id,row.lease_generation):
            raise ContractError("lease renewal failed before provider dispatch")
        if envelope_for_turn is None:
            raise ContractError("admitted turn lacks gateway envelope")
        envelope = envelope_for_turn
        lease_stop=threading.Event();lease_lost=threading.Event()
        def heartbeat():
            while not lease_stop.wait(self.lease_heartbeat_seconds):
                try:
                    renewed=self.store.renew_lease(self.tenant_id,row.turn_id,row.lease_generation)
                except Exception:
                    lease_lost.set();return
                if not renewed:
                    lease_lost.set();return
        heartbeat_thread=threading.Thread(target=heartbeat,name="restricted-lease-heartbeat",daemon=True)
        heartbeat_thread.start()
        try:
            # The local adapter receives the configured internal identity; the
            # production HTTP client obtains its real audience-bound ID token
            # itself and deliberately does not trust this value.
            result = self.gateway.infer_once(envelope, self.policy.values["gateway_invoker_principal"])
        except Exception as exc:
            self._mark_indeterminate(row)
            raise ContractError("inference outcome is indeterminate") from exc
        finally:
            lease_stop.set();heartbeat_thread.join(timeout=1)
        # One final DB-time CAS renewal closes the interval between the last
        # heartbeat and the provider return before any response transition.
        if hasattr(self.store,"renew_lease"):
            try:
                if not self.store.renew_lease(self.tenant_id,row.turn_id,row.lease_generation):lease_lost.set()
            except Exception:
                lease_lost.set()
        if lease_lost.is_set():
            self._mark_indeterminate(row)
            raise ContractError("lease lost during provider operation")
        if result.state != "SUCCEEDED" or result.text is None:
            target = TurnState.FAILED if result.state in {"FAILED","CANCELLED_NO_DISPATCH"} else TurnState.INDETERMINATE
            if not self.store.set_state_cas(self.tenant_id, row.turn_id, row.lease_generation, TurnState.INFERENCE_PENDING, target):
                raise ContractError("terminal transition did not commit")
            return {"schema_version": "restricted-turn-status.v1", "turn_id": row.turn_id, "conversation_epoch": row.conversation_epoch, "status": target.value}
        if (result.policy_epoch,result.policy_digest)!=(row.policy_epoch,row.policy_digest) or not result.decision_id:
            self._mark_indeterminate(row)
            raise ContractError("gateway result association mismatch")
        try:
            response_cipher = encrypt(data_key, result.text.encode("utf-8"), self._aad(row, "response"))
            if not self.store.set_state_cas(self.tenant_id, row.turn_id, row.lease_generation, TurnState.INFERENCE_PENDING, TurnState.RESPONSE_RECEIVED):
                raise ContractError("response received transition failed")
            if not self.store.set_state_cas(self.tenant_id, row.turn_id, row.lease_generation, TurnState.RESPONSE_RECEIVED, TurnState.COMMITTED, response_ciphertext=response_cipher.ciphertext, response_nonce=response_cipher.nonce, gateway_decision_id=result.decision_id, gateway_attempt_classification=result.state):
                raise ContractError("response durable commit failed")
        except Exception as exc:
            self._mark_indeterminate(row)
            raise ContractError("response is not durably committed") from exc
        return self._committed_result(self.store.read_turn(self.tenant_id, row.turn_id))
    def _decrypt_history(self, rows: list[TurnRow]) -> list[dict[str, str]]:
        history: list[dict[str, str]] = []
        for row in rows:
            key = self.data_keys.unwrap(row.wrapped_data_key)
            req = decrypt(key, Ciphertext(row.request_nonce, row.request_ciphertext), self._aad(row, "request"))
            # Payload contains the original ordered history; retain only that turn's user input.
            import json
            history.append(json.loads(req)["messages"][-1])
            if row.response_ciphertext and row.response_nonce:
                history.append({"role": "model", "text": decrypt(key, Ciphertext(row.response_nonce, row.response_ciphertext), self._aad(row, "response")).decode("utf-8")})
        return history
    def _committed_result(self, row: TurnRow) -> dict[str, str]:
        if row.state != TurnState.COMMITTED or not row.response_ciphertext or not row.response_nonce or not row.gateway_decision_id or row.gateway_attempt_classification != "SUCCEEDED":
            raise ContractError("committed readback unavailable")
        key = self.data_keys.unwrap(row.wrapped_data_key)
        text = decrypt(key, Ciphertext(row.response_nonce, row.response_ciphertext), self._aad(row, "response")).decode("utf-8")
        return {"schema_version": "restricted-turn-result.v1", "turn_id": row.turn_id, "conversation_epoch": row.conversation_epoch, "status": "COMMITTED", "message": text}
    def _duplicate_result(self, row: TurnRow) -> dict[str, str]:
        return self._committed_result(row) if row.state == TurnState.COMMITTED else {"schema_version": "restricted-turn-status.v1", "turn_id": row.turn_id, "conversation_epoch": row.conversation_epoch, "status": row.state.value}
