"""Gateway envelope validation and one-attempt state transitions."""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable, Protocol

from .contracts import AttemptState, Classification, ContractError, ProviderResult
from .crypto import GATEWAY_MAC_DOMAIN, MacKey, kms_mac_input
from .gateway_contracts import GatewayEnvelope
from .messages import validate_internal_messages
from .policy import PolicyBundle, SYSTEM_INSTRUCTION, SYSTEM_INSTRUCTION_SHA256


class Ledger(Protocol):
    def reserve(self, envelope: GatewayEnvelope, principal: str, mac: bytes, key_resource: str, key_version: str) -> AttemptState: ...
    def start_dispatch(self, tenant_id: str, turn_id: str) -> bool: ...
    def finish(self, tenant_id: str, turn_id: str, result: ProviderResult) -> None: ...
    def lookup(self, tenant_id: str, turn_id: str, *, client_request_id: str, policy_epoch: str, policy_digest: str): ...
    def status(self, tenant_id: str, turn_id: str) -> AttemptState | None: ...
    def fence(self, tenant_id: str, turn_id: str, *, client_request_id: str, policy_epoch: str, policy_digest: str) -> AttemptState: ...

class Gateway:
    def __init__(self, policy: PolicyBundle, mac_key: MacKey, ledger: Ledger, vertex, *, admission_enabled: bool = True, authorization_gate: Callable[[], None] | None = None):
        policy.validate(); self.policy, self.mac_key, self.ledger, self.vertex, self.admission_enabled, self.authorization_gate = policy, mac_key, ledger, vertex, admission_enabled, authorization_gate
        if getattr(ledger, "mac_key", None) is None:
            ledger.mac_key = mac_key
    def validate(self, envelope: GatewayEnvelope, principal: str) -> bytes:
        p = self.policy.values
        if principal != p["gateway_invoker_principal"] or envelope.authenticated_external_principal != p["external_runner_principal"] or envelope.tenant_id != p["tenant_id"] or envelope.classification != Classification.PHI:
            raise ContractError("identity, tenant, or classification rejected")
        if envelope.policy_epoch != self.policy.epoch or envelope.policy_digest != self.policy.digest:
            raise ContractError("policy pair mismatch")
        if envelope.system_instruction_version != p["system_instruction_version"] or envelope.system_instruction != SYSTEM_INSTRUCTION or p["system_instruction_sha256"] != SYSTEM_INSTRUCTION_SHA256:
            raise ContractError("system instruction mismatch")
        validate_internal_messages(envelope.messages)
        canonical = envelope.canonical()
        if envelope.content_limit != p["max_canonical_input_utf8_bytes"] or len(canonical) > envelope.content_limit:
            raise ContractError("content limit mismatch")
        return canonical
    def infer_once(self, envelope: GatewayEnvelope, principal: str) -> ProviderResult:
        # This is intentionally before validation, MAC, reservation, and the
        # provider. A kill switch must also stop a durable pre-existing turn
        # from crossing the only Vertex dispatch boundary.
        if not self.admission_enabled:
            raise ContractError("gateway admission is disabled")
        if self.authorization_gate is not None:
            self.authorization_gate()
        canonical = self.validate(envelope, principal)
        record = self.mac_key.sign(kms_mac_input(GATEWAY_MAC_DOMAIN, canonical))
        state = self.ledger.reserve(envelope, principal, record.mac, record.key_resource, record.key_version)
        attempt = self.ledger.lookup(envelope.tenant_id,envelope.turn_id,client_request_id=envelope.client_request_id,policy_epoch=envelope.policy_epoch,policy_digest=envelope.policy_digest)
        if state != AttemptState.RESERVED:
            return ProviderResult(str(state),decision_id=attempt.decision_id if attempt else None,provider_request_id=attempt.provider_request_id if attempt else None,policy_epoch=envelope.policy_epoch,policy_digest=envelope.policy_digest)
        if self.authorization_gate is not None:
            self.authorization_gate()
        if not self.ledger.start_dispatch(envelope.tenant_id, envelope.turn_id):
            return ProviderResult("CANCELLED_NO_DISPATCH",decision_id=attempt.decision_id if attempt else None,policy_epoch=envelope.policy_epoch,policy_digest=envelope.policy_digest)
        result = self.vertex.generate_content(envelope.messages)
        self.ledger.finish(envelope.tenant_id, envelope.turn_id, result)
        attempt = self.ledger.lookup(envelope.tenant_id,envelope.turn_id,client_request_id=envelope.client_request_id,policy_epoch=envelope.policy_epoch,policy_digest=envelope.policy_digest)
        if not attempt:
            raise ContractError("ledger association unavailable after dispatch")
        return replace(result,decision_id=attempt.decision_id,provider_request_id=attempt.provider_request_id,policy_epoch=attempt.policy_epoch,policy_digest=attempt.policy_digest)
    def status(self, tenant_id: str, turn_id: str, *, client_request_id: str, policy_epoch: str, policy_digest: str) -> AttemptState | None: return self.ledger.status(tenant_id, turn_id,client_request_id=client_request_id,policy_epoch=policy_epoch,policy_digest=policy_digest)
    def fence(self, tenant_id: str, turn_id: str, *, client_request_id: str, policy_epoch: str, policy_digest: str) -> AttemptState: return self.ledger.fence(tenant_id, turn_id, client_request_id=client_request_id, policy_epoch=policy_epoch, policy_digest=policy_digest)
