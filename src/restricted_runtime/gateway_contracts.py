"""Provider-neutral envelope contract shared by conversation and gateway roles."""
from __future__ import annotations

from dataclasses import dataclass

from .contracts import jcs_bytes


@dataclass(frozen=True)
class GatewayEnvelope:
    tenant_id: str; conversation_id: str; conversation_epoch: str; turn_id: str; client_request_id: str
    policy_epoch: str; policy_digest: str; system_instruction_version: str; system_instruction: str
    classification: str; messages: list[dict[str, str]]; content_limit: int
    authenticated_external_principal: str = ""

    def canonical(self) -> bytes:
        return jcs_bytes(self.__dict__)
