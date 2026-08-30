"""The restricted turn state machine: admission, one gateway call, commit, readback."""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, replace
from typing import Protocol

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

    def _aad(self, row: TurnRow, direction: str) -> bytes:
        return content_aad(tenant_id=row.tenant_id, conversation_id=row.conversation_id, conversation_epoch=row.conversation_epoch, turn_id=row.turn_id, client_request_id=row.client_request_id, direction=direction, policy_digest=row.policy_digest)
    def _verify_duplicate(self, row: TurnRow, request: TurnRequest, principal: str, conversation_id: str) -> None:
        if (row.principal, row.conversation_id, row.conversation_epoch, row.client_request_id) != (principal, conversation_id, request.conversation_epoch, request.client_request_id):
            raise ContractError("idempotency association conflict")
        canonical = jcs_bytes(request.identity(principal=principal, tenant_id=self.tenant_id, conversation_id=conversation_id))
        record = MacRecord(row.mac_key_resource, row.mac_key_version, row.request_mac)
        if not self.mac_key.verify(record, kms_mac_input(SERVICE_MAC_DOMAIN, canonical)):
            raise ContractError("idempotency MAC verification failed")
    def submit(self, request: TurnRequest, *, principal: str, conversation_id: str) -> dict[str, str]:
        canonical = jcs_bytes(request.identity(principal=principal, tenant_id=self.tenant_id, conversation_id=conversation_id))
        if len(canonical) > self.policy.values["max_canonical_input_utf8_bytes"]:
            raise ContractError("canonical input exceeds policy")
        key_record = self.mac_key.sign(kms_mac_input(SERVICE_MAC_DOMAIN, canonical))
        data_key = os.urandom(32)
        turn_id = str(uuid.uuid4())
        initial = TurnRow(self.tenant_id, conversation_id, request.conversation_epoch, turn_id, request.client_request_id, principal, key_record.mac, key_record.key_resource, key_record.key_version, self.policy.digest, TurnState.RECEIVED, b"", b"", None, None, self.data_keys.wrap(data_key), 0)
        history = self.store.committed_history(self.tenant_id, conversation_id, request.conversation_epoch)
        messages = self._decrypt_history(history) + [{"role": "user", "text": request.message}]
        request_payload = jcs_bytes({"system_instruction": SYSTEM_INSTRUCTION, "messages": messages})
        encrypted = encrypt(data_key, request_payload, self._aad(initial, "request"))
        initial = replace(initial, request_ciphertext=encrypted.ciphertext, request_nonce=encrypted.nonce)
        row, created = self.store.admit(initial)
        self._verify_duplicate(row, request, principal, conversation_id)
        if not created:
            return self._duplicate_result(row)
        if not self.store.set_state_cas(self.tenant_id, row.turn_id, row.lease_generation, TurnState.RECEIVED, TurnState.INFERENCE_PENDING):
            raise ContractError("admitted turn lease lost")
        row = self.store.read_turn(self.tenant_id, row.turn_id)
        envelope = GatewayEnvelope(self.tenant_id, conversation_id, request.conversation_epoch, row.turn_id, request.client_request_id, self.policy.epoch, self.policy.digest, "restricted-phi-system.v1", SYSTEM_INSTRUCTION, "PHI", messages, 0)
        envelope = GatewayEnvelope(**{**envelope.__dict__, "content_limit": len(envelope.canonical(principal))})
        result = self.gateway.infer_once(envelope, principal)
        if result.state != "SUCCEEDED" or result.text is None:
            target = TurnState.FAILED if result.state == "FAILED" else TurnState.INDETERMINATE
            self.store.set_state_cas(self.tenant_id, row.turn_id, row.lease_generation, TurnState.INFERENCE_PENDING, target)
            return {"schema_version": "restricted-turn-status.v1", "turn_id": row.turn_id, "conversation_epoch": row.conversation_epoch, "status": target.value}
        response_cipher = encrypt(data_key, result.text.encode("utf-8"), self._aad(row, "response"))
        if not self.store.set_state_cas(self.tenant_id, row.turn_id, row.lease_generation, TurnState.INFERENCE_PENDING, TurnState.COMMITTED, response_ciphertext=response_cipher.ciphertext, response_nonce=response_cipher.nonce):
            raise ContractError("response durable commit failed")
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
        if row.state != TurnState.COMMITTED or not row.response_ciphertext or not row.response_nonce:
            raise ContractError("committed readback unavailable")
        key = self.data_keys.unwrap(row.wrapped_data_key)
        text = decrypt(key, Ciphertext(row.response_nonce, row.response_ciphertext), self._aad(row, "response")).decode("utf-8")
        return {"schema_version": "restricted-turn-result.v1", "turn_id": row.turn_id, "conversation_epoch": row.conversation_epoch, "status": "COMMITTED", "message": text}
    def _duplicate_result(self, row: TurnRow) -> dict[str, str]:
        return self._committed_result(row) if row.state == TurnState.COMMITTED else {"schema_version": "restricted-turn-status.v1", "turn_id": row.turn_id, "conversation_epoch": row.conversation_epoch, "status": row.state.value}
