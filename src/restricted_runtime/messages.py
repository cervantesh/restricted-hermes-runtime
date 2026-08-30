"""Closed internal conversation-message contract shared by gateway and Vertex."""
from __future__ import annotations

from .contracts import ContractError


def validate_internal_messages(messages: object) -> list[dict[str, str]]:
    if not isinstance(messages, list) or not messages:
        raise ContractError("internal messages must be a non-empty list")
    for message in messages:
        if not isinstance(message, dict) or set(message) != {"role", "text"}:
            raise ContractError("internal message schema rejected")
        if message["role"] not in {"user", "model"} or not isinstance(message["text"], str) or not message["text"]:
            raise ContractError("internal message value rejected")
    return messages
