"""Lease-expiry reconciliation. It can fence/status only; it can never infer."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .contracts import AttemptState, TurnState


class ContentReconciliationStore(Protocol):
    def claim_expired_lease(self, tenant_id: str, turn_id: str, owner: str, seconds: int = 30) -> int | None: ...
    def mark_terminal_cas(self, tenant_id: str, turn_id: str, generation: int, state: TurnState, failure_class: str | None) -> bool: ...

class GatewayStatusFence(Protocol):
    def status(self, tenant_id: str, turn_id: str, *, client_request_id: str, policy_epoch: str, policy_digest: str) -> AttemptState | None: ...
    def fence(self, tenant_id: str, turn_id: str, *, client_request_id: str, policy_epoch: str, policy_digest: str) -> AttemptState: ...


@dataclass
class Reconciler:
    content: ContentReconciliationStore
    gateway: GatewayStatusFence

    def reconcile_expired(self, *, tenant_id: str, turn_id: str, client_request_id: str, policy_epoch: str, policy_digest: str, owner: str) -> TurnState | None:
        generation = self.content.claim_expired_lease(tenant_id, turn_id, owner)
        if generation is None:
            return None
        current = self.gateway.status(tenant_id, turn_id,client_request_id=client_request_id,policy_epoch=policy_epoch,policy_digest=policy_digest)
        if current in (None, AttemptState.RESERVED):
            # A cancellation tombstone/RESERVED cancellation must commit before FAILED.
            current = self.gateway.fence(tenant_id, turn_id,client_request_id=client_request_id,policy_epoch=policy_epoch,policy_digest=policy_digest)
        if current in (None, AttemptState.RESERVED):
            return None  # ambiguous gateway; retain claimed non-terminal lease
        if current in (AttemptState.CANCELLED_NO_DISPATCH, AttemptState.FAILED):
            self.content.mark_terminal_cas(tenant_id, turn_id, generation, TurnState.FAILED, "GATEWAY_NO_SUCCESS")
            return TurnState.FAILED
        self.content.mark_terminal_cas(tenant_id, turn_id, generation, TurnState.INDETERMINATE, "DISPATCH_MAY_HAVE_OCCURRED")
        return TurnState.INDETERMINATE
