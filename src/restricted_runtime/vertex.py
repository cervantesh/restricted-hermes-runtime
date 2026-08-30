"""The only provider dispatch surface: one fixed, non-streaming Vertex request."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from .contracts import ContractError, load_closed_json
from .policy import PolicyBundle, SYSTEM_INSTRUCTION


@dataclass(frozen=True)
class ProviderResult:
    state: str
    text: str | None = None
    failure_class: str | None = None
    request_id: str | None = None


def _closed_keys(value: dict[str, Any], allowed: set[str]) -> None:
    if set(value) - allowed:
        raise ContractError("unknown Vertex response field")


def parse_vertex_response(status_code: int, raw: bytes) -> ProviderResult:
    if status_code != 200:
        return ProviderResult("FAILED", failure_class=f"VERTEX_HTTP_{status_code}")
    if len(raw) > 1_048_576:
        return ProviderResult("INDETERMINATE", failure_class="RESPONSE_TOO_LARGE")
    try:
        root = load_closed_json(raw)
        if not isinstance(root, dict): raise ContractError("root")
        _closed_keys(root, {"candidates", "usageMetadata", "modelVersion", "createTime", "responseId", "promptFeedback"})
        feedback = root.get("promptFeedback")
        if feedback is not None:
            if not isinstance(feedback, dict): raise ContractError("feedback")
            _closed_keys(feedback, {"blockReason", "blockReasonMessage", "safetyRatings"})
            if "blockReason" in feedback:
                return ProviderResult("FAILED", failure_class="PROMPT_BLOCK") if feedback["blockReason"] in {"SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT"} else ProviderResult("INDETERMINATE", failure_class="UNKNOWN_REFUSAL")
        candidates = root.get("candidates")
        if not isinstance(candidates, list) or len(candidates) != 1: raise ContractError("candidate count")
        candidate = candidates[0]
        if not isinstance(candidate, dict): raise ContractError("candidate")
        _closed_keys(candidate, {"content", "finishReason", "index", "safetyRatings", "avgLogprobs"})
        reason = candidate.get("finishReason")
        if reason in {"SAFETY", "RECITATION"}: return ProviderResult("FAILED", failure_class=reason)
        if candidate.get("index") != 0 or not isinstance(reason, str): raise ContractError("candidate identity")
        content = candidate.get("content")
        if not isinstance(content, dict) or set(content) != {"role", "parts"} or content["role"] != "model": raise ContractError("content")
        parts = content["parts"]
        if not isinstance(parts, list) or len(parts) != 1 or not isinstance(parts[0], dict) or set(parts[0]) != {"text"} or not isinstance(parts[0]["text"], str) or not parts[0]["text"]:
            raise ContractError("text part")
        if reason != "STOP": return ProviderResult("INDETERMINATE", failure_class="NON_FINAL_FINISH")
        return ProviderResult("SUCCEEDED", text=parts[0]["text"], request_id=root.get("responseId"))
    except ContractError:
        return ProviderResult("INDETERMINATE", failure_class="MALFORMED_RESPONSE")


class VertexClient:
    """No retry, no redirects, no streaming, and a policy-constructed URI."""
    def __init__(self, policy: PolicyBundle, token_supplier):
        self.policy, self._token_supplier = policy, token_supplier
        self.dispatch_count = 0
    def generate_content(self, messages: list[dict[str, str]]) -> ProviderResult:
        body = {"systemInstruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]}, "contents": messages, "generationConfig": {"candidateCount": 1, "maxOutputTokens": 4096}}
        # system instruction never comes from a caller; injected by gateway only.
        url = "https://" + self.policy.values["hostname"] + self.policy.values["generate_content_path"]
        self.dispatch_count += 1
        try:
            with httpx.Client(follow_redirects=False, timeout=httpx.Timeout(connect=5, read=30, write=5, pool=5), transport=None) as client:
                response = client.post(url, headers={"Authorization": "Bearer " + self._token_supplier(), "Content-Type": "application/json"}, content=json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
            return parse_vertex_response(response.status_code, response.content)
        except httpx.TransportError:
            return ProviderResult("INDETERMINATE", failure_class="TRANSPORT_AFTER_DISPATCH")
