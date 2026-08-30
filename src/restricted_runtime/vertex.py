"""The only provider dispatch surface: one fixed, non-streaming Vertex request."""
from __future__ import annotations

import json
import math
import time
from typing import Any, Protocol

import httpx

from .contracts import ContractError, ProviderResult, load_closed_json
from .policy import PolicyBundle, SYSTEM_INSTRUCTION



def _closed_keys(value: dict[str, Any], allowed: set[str]) -> None:
    if set(value) - allowed:
        raise ContractError("unknown Vertex response field")

def _ratings(value: Any) -> None:
    if not isinstance(value,list): raise ContractError("ratings")
    for rating in value:
        if not isinstance(rating,dict): raise ContractError("rating")
        _closed_keys(rating,{"category","probability","blocked","severity","probabilityScore","severityScore"})
        for key in ("category","probability","severity"):
            if key in rating and not isinstance(rating[key],str): raise ContractError("rating string")
        if "blocked" in rating and not isinstance(rating["blocked"],bool): raise ContractError("rating bool")
        for key in ("probabilityScore","severityScore"):
            if key in rating and (not isinstance(rating[key],(int,float)) or isinstance(rating[key],bool) or not math.isfinite(rating[key])): raise ContractError("rating number")

def _validate_optional(root: dict[str,Any]) -> None:
    if "usageMetadata" in root:
        usage=root["usageMetadata"]
        if not isinstance(usage,dict):raise ContractError("usage")
        counts={"promptTokenCount","candidatesTokenCount","totalTokenCount","thoughtsTokenCount","cachedContentTokenCount","toolUsePromptTokenCount"}
        arrays={"promptTokensDetails","candidatesTokensDetails","cacheTokensDetails","toolUsePromptTokensDetails"}
        _closed_keys(usage,counts|arrays)
        for key in counts:
            if key in usage and (not isinstance(usage[key],int) or isinstance(usage[key],bool) or usage[key]<0):raise ContractError("token count")
        for key in arrays:
            if key in usage:
                if not isinstance(usage[key],list):raise ContractError("token detail")
                for item in usage[key]:
                    if not isinstance(item,dict) or set(item)!={"modality","tokenCount"} or not isinstance(item["modality"],str) or not isinstance(item["tokenCount"],int) or isinstance(item["tokenCount"],bool) or item["tokenCount"]<0:raise ContractError("token detail")
    for key in ("modelVersion","createTime","responseId"):
        if key in root and not isinstance(root[key],str):raise ContractError("root string")


def parse_vertex_response(status_code: int, raw: bytes) -> ProviderResult:
    if status_code != 200:
        return ProviderResult("FAILED", failure_class=f"VERTEX_HTTP_{status_code}")
    if len(raw) > 1_048_576:
        return ProviderResult("INDETERMINATE", failure_class="RESPONSE_TOO_LARGE")
    try:
        root = load_closed_json(raw)
        if not isinstance(root, dict): raise ContractError("root")
        _closed_keys(root, {"candidates", "usageMetadata", "modelVersion", "createTime", "responseId", "promptFeedback"})
        _validate_optional(root)
        feedback = root.get("promptFeedback")
        if feedback is not None:
            if not isinstance(feedback, dict): raise ContractError("feedback")
            _closed_keys(feedback, {"blockReason", "blockReasonMessage", "safetyRatings"})
            if "blockReasonMessage" in feedback and not isinstance(feedback["blockReasonMessage"],str): raise ContractError("block message")
            if "safetyRatings" in feedback: _ratings(feedback["safetyRatings"])
            if "blockReason" in feedback:
                return ProviderResult("FAILED", failure_class="PROMPT_BLOCK") if feedback["blockReason"] in {"SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT"} else ProviderResult("INDETERMINATE", failure_class="UNKNOWN_REFUSAL")
        candidates = root.get("candidates")
        if not isinstance(candidates, list) or len(candidates) != 1: raise ContractError("candidate count")
        candidate = candidates[0]
        if not isinstance(candidate, dict): raise ContractError("candidate")
        _closed_keys(candidate, {"content", "finishReason", "index", "safetyRatings", "avgLogprobs"})
        if "safetyRatings" in candidate: _ratings(candidate["safetyRatings"])
        if "avgLogprobs" in candidate and (not isinstance(candidate["avgLogprobs"],(int,float)) or isinstance(candidate["avgLogprobs"],bool) or not math.isfinite(candidate["avgLogprobs"])): raise ContractError("avgLogprobs")
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
        body = build_vertex_payload(messages)
        if body is None:
            return ProviderResult("INDETERMINATE",failure_class="INVALID_INTERNAL_MESSAGE")
        # system instruction never comes from a caller; injected by gateway only.
        url = "https://" + self.policy.values["hostname"] + self.policy.values["generate_content_path"]
        self.dispatch_count += 1
        try:
            started=time.monotonic(); data=bytearray()
            with httpx.Client(follow_redirects=False, trust_env=False, timeout=httpx.Timeout(connect=5, read=30, write=5, pool=5)) as client:
                with client.stream("POST",url,headers={"Authorization": "Bearer " + self._token_supplier(), "Content-Type": "application/json", "Accept-Encoding": "identity"}, content=json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) as response:
                    declared=response.headers.get("content-length")
                    if declared is not None and (not declared.isdigit() or int(declared)>1_048_576):return ProviderResult("INDETERMINATE",failure_class="RESPONSE_TOO_LARGE")
                    for chunk in response.iter_bytes():
                        if time.monotonic()-started>40:return ProviderResult("INDETERMINATE",failure_class="TOTAL_DEADLINE")
                        data.extend(chunk)
                        if len(data)>1_048_576:return ProviderResult("INDETERMINATE",failure_class="RESPONSE_TOO_LARGE")
                    return parse_vertex_response(response.status_code,bytes(data))
        except httpx.TransportError:
            return ProviderResult("INDETERMINATE", failure_class="TRANSPORT_AFTER_DISPATCH")

def build_vertex_payload(messages: list[dict[str,str]]) -> dict[str,Any] | None:
        contents=[]
        for message in messages:
            if set(message)!={"role","text"} or message["role"] not in {"user","model"} or not isinstance(message["text"],str) or not message["text"]:
                return None
            contents.append({"role":message["role"],"parts":[{"text":message["text"]}]})
        return {"systemInstruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]}, "contents": contents, "generationConfig": {"candidateCount": 1, "maxOutputTokens": 4096}}
