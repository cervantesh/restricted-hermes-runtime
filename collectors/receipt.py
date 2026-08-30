"""Offline receipt guard: collectors may report evidence, never promote PHI readiness."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping
import re

SECRET_MARKERS=("token","secret","password","authorization","database_url","private_key")
REQUIRED_DEPLOYED_GATES=frozenset({
    "immutable_revisions_digests", "real_runner_provider_turn", "one_dispatch",
    "encrypted_commit_readback", "iam_oidc_vertex_negatives", "fault_crash_matrix",
    "privacy_canaries", "kms_rotation_iam", "rollback_kill_switch",
    "network_baseline", "lifecycle_ttl",
})
IMMUTABLE_EVIDENCE_FIELDS={
    "contract_revision":re.compile(r"^[0-9a-f]{40,64}$"),
    "runtime_revision":re.compile(r"^[0-9a-f]{40,64}$"),
    "conversation_image_digest":re.compile(r"^sha256:[0-9a-f]{64}$"),
    "gateway_image_digest":re.compile(r"^sha256:[0-9a-f]{64}$"),
    "runner_image_digest":re.compile(r"^sha256:[0-9a-f]{64}$"),
    "migration_image_digest":re.compile(r"^sha256:[0-9a-f]{64}$"),
    "policy_epoch":re.compile(r"^.{1,256}$"),
    "policy_digest":re.compile(r"^sha256:[0-9a-f]{64}$"),
}
_SENSITIVE_VALUE=re.compile(r"(?:postgres(?:ql)?://|(?:password|secret|token)\s*[=:]|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+\S+|\bya29\.[A-Za-z0-9._-]+)",re.I)

@dataclass(frozen=True)
class DiagnosticReceipt:
    state: str
    fqdn_sni_witness: str
    fields: dict[str,str]


def redact(fields: Mapping[str,object]) -> dict[str,str]:
    return {str(k):("[REDACTED]" if any(marker in str(k).lower() for marker in SECRET_MARKERS) or _SENSITIVE_VALUE.search(str(v)) else str(v)) for k,v in fields.items()}


def make_receipt(*, fqdn_sni_witness: str, fields: Mapping[str,object]) -> DiagnosticReceipt:
    if fqdn_sni_witness not in {"PASS","UNDETERMINED","FAIL"}: raise ValueError("closed FQDN/SNI state")
    # A network witness is only one gate.  Deployed proof must be explicitly
    # complete; a missing collector result never promotes a synthetic receipt.
    immutable_evidence_valid=all(pattern.fullmatch(str(fields.get(name,""))) for name,pattern in IMMUTABLE_EVIDENCE_FIELDS.items())
    all_gates_pass=all(fields.get(gate)=="PASS" for gate in REQUIRED_DEPLOYED_GATES) and immutable_evidence_valid
    state="FAILED" if fqdn_sni_witness=="FAIL" else ("READY" if fqdn_sni_witness=="PASS" and all_gates_pass else "PARTIAL")
    return DiagnosticReceipt(state,fqdn_sni_witness,redact(fields))
