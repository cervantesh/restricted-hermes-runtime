"""Closed, offline-signed policy bundle validation."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import ContractError, jcs_bytes, load_closed_json

POLICY_SCHEMA = "restricted-phi-inference-policy.v1"
LOCAL_POLICY_SCHEMA = "restricted-self-hosted-inference-policy.v1"
REQUIRED_FIELDS = {
    "schema_version", "policy_epoch", "system_instruction_version", "system_instruction_sha256", "authorization_status", "external_runner_principal", "gateway_invoker_principal", "tenant_id", "classification", "provider", "model", "vertex_project_id", "vertex_project_number", "model_resource", "generate_content_path", "location", "hostname", "method", "streaming", "fallbacks", "max_provider_attempts", "allowed_modalities", "tools_allowed", "candidate_count", "max_output_tokens", "max_canonical_input_utf8_bytes", "response_profile", "provider_request_logging", "provider_response_logging", "vertex_data_access_payload_logging", "vertex_in_memory_cache", "training_use", "retention_profile",
}
LOCAL_REQUIRED_FIELDS = {
    "schema_version", "policy_epoch", "system_instruction_version", "system_instruction_sha256",
    "authorization_status", "external_runner_principal", "gateway_invoker_principal", "tenant_id",
    "classification", "provider", "socket_path", "method", "model", "model_sha256",
    "response_profile", "streaming", "fallbacks", "max_provider_attempts", "allowed_modalities",
    "tools_allowed", "candidate_count", "max_output_tokens", "max_canonical_input_utf8_bytes",
}
SYSTEM_INSTRUCTION = "You are Hermes, a text-only assistant for non-clinical administrative work involving PHI. Answer only from the supplied conversation. Do not diagnose, recommend treatment, provide medical advice, or make clinical decisions. You have no tools or external access. Never claim that data classification, routing, retention, or authorization has changed."
SYSTEM_INSTRUCTION_SHA256 = "afcf847cd029409e53bbcb07e92b9d407876e3190e9cf951844829cb34599c1b"


@dataclass(frozen=True)
class PolicyBundle:
    values: dict[str, Any]
    digest: str
    @property
    def epoch(self) -> str: return str(self.values["policy_epoch"])

    def validate(self) -> None:
        if self.values.get("schema_version") == LOCAL_POLICY_SCHEMA:
            self._validate_local()
            return
        if set(self.values) != REQUIRED_FIELDS or self.values.get("schema_version") != POLICY_SCHEMA:
            raise ContractError("policy schema is closed")
        expected = {
            "classification": "PHI", "provider": "vertex-ai", "model": "gemini-3.5-flash", "location": "us", "hostname": "aiplatform.us.rep.googleapis.com", "method": "generateContent", "streaming": False, "fallbacks": [], "max_provider_attempts": 1, "allowed_modalities": ["text"], "tools_allowed": False, "candidate_count": 1, "max_output_tokens": 4096, "max_canonical_input_utf8_bytes": 131072, "response_profile": "restricted-vertex-text-response.v1", "system_instruction_version": "restricted-phi-system.v1", "system_instruction_sha256": SYSTEM_INSTRUCTION_SHA256,
        }
        for key, expected_value in expected.items():
            if self.values.get(key) != expected_value:
                raise ContractError("policy does not match frozen v0 contract")
        if self.values.get("authorization_status") != "synthetic-non-phi-only":
            raise ContractError("policy is not a truthful synthetic-only authorization")
        principals=("external_runner_principal", "gateway_invoker_principal")
        if not all(isinstance(self.values.get(key), str) and self.values[key] and not self.values[key].startswith("REQUIRED_") for key in principals):
            raise ContractError("policy principal binding is incomplete")
        if self.values["external_runner_principal"] == self.values["gateway_invoker_principal"]:
            raise ContractError("policy principal bindings are conflated")
        posture=("provider_request_logging", "provider_response_logging", "vertex_data_access_payload_logging", "vertex_in_memory_cache", "training_use", "retention_profile")
        if any(self.values[key] != "synthetic-unverified-no-phi" for key in posture):
            raise ContractError("unproven external posture is not truthful")
        number = str(self.values["vertex_project_number"])
        if self.values["model_resource"] != f"projects/{number}/locations/us/publishers/google/models/gemini-3.5-flash" or self.values["generate_content_path"] != f"/v1/projects/{number}/locations/us/publishers/google/models/gemini-3.5-flash:generateContent":
            raise ContractError("policy sink tuple is not exact")
        if hashlib.sha256(SYSTEM_INSTRUCTION.encode()).hexdigest() != SYSTEM_INSTRUCTION_SHA256:
            raise ContractError("system instruction digest mismatch")

    def _validate_local(self) -> None:
        if set(self.values) != LOCAL_REQUIRED_FIELDS:
            raise ContractError("local policy schema is closed")
        expected = {
            "classification": "PHI", "provider": "local-uds", "method": "restrictedGenerate",
            "streaming": False, "fallbacks": [], "max_provider_attempts": 1,
            "allowed_modalities": ["text"], "tools_allowed": False, "candidate_count": 1,
            "max_output_tokens": 4096, "max_canonical_input_utf8_bytes": 131072,
            "response_profile": "restricted-local-text-response.v1",
            "system_instruction_version": "restricted-phi-system.v1",
            "system_instruction_sha256": SYSTEM_INSTRUCTION_SHA256,
            "authorization_status": "operator-authorization-required",
        }
        for key, expected_value in expected.items():
            if self.values.get(key) != expected_value:
                raise ContractError("local policy does not match closed contract")
        principals = ("external_runner_principal", "gateway_invoker_principal")
        if not all(isinstance(self.values.get(key), str) and self.values[key] and not self.values[key].startswith("REQUIRED_") for key in principals):
            raise ContractError("local policy principal binding is incomplete")
        if self.values["external_runner_principal"] == self.values["gateway_invoker_principal"]:
            raise ContractError("local policy principal bindings are conflated")
        if not isinstance(self.values["tenant_id"], str) or not self.values["tenant_id"]:
            raise ContractError("local policy tenant is required")
        socket_path = self.values["socket_path"]
        if not isinstance(socket_path, str) or not socket_path.endswith(".sock"):
            raise ContractError("local socket path is invalid")
        normalized = str(PurePosixPath(socket_path))
        if normalized != socket_path or not socket_path.startswith("/run/restricted-inference/"):
            raise ContractError("local socket path is outside the closed namespace")
        if not isinstance(self.values["model"], str) or not self.values["model"]:
            raise ContractError("local model name is required")
        model_digest = self.values["model_sha256"]
        if not isinstance(model_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", model_digest):
            raise ContractError("local model digest is invalid")
        if hashlib.sha256(SYSTEM_INSTRUCTION.encode()).hexdigest() != SYSTEM_INSTRUCTION_SHA256:
            raise ContractError("system instruction digest mismatch")

    def sink_tuple(self) -> dict[str, Any]:
        """Exact durable sink identity; Vertex keys stay frozen byte-for-byte."""
        if self.values["schema_version"] == POLICY_SCHEMA:
            return {key: self.values[key] for key in ("vertex_project_id", "vertex_project_number", "model_resource", "generate_content_path", "location", "hostname", "method", "model")}
        return {key: self.values[key] for key in ("schema_version", "provider", "socket_path", "method", "model", "model_sha256", "response_profile")}


def load_signed_policy(path: Path, signature_path: Path, public_key_b64: str) -> PolicyBundle:
    raw = path.read_bytes()
    try:
        values = load_closed_json(raw)
        signature = base64.b64decode(signature_path.read_text(encoding="ascii"), validate=True)
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True))
        key.verify(signature, jcs_bytes(values))
    except Exception as exc:
        raise ContractError("policy signature validation failed") from exc
    policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest())
    policy.validate()
    return policy
