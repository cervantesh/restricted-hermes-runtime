"""Offline receipt guard: collectors may report evidence, never promote PHI readiness."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping
import re

SECRET_MARKERS=("token","secret","password","authorization","database_url","private_key")
REQUIRED_DEPLOYED_GATES=frozenset({
    "artifact_image", "policy_bundle", "database_migration", "iam",
    "cloud_run", "runner", "network_egress", "image_proof",
})
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
    all_gates_pass=fields.get("deployed_gates")=="PASS" and all(fields.get(gate)=="PASS" for gate in REQUIRED_DEPLOYED_GATES)
    state="FAILED" if fqdn_sni_witness=="FAIL" else ("READY" if fqdn_sni_witness=="PASS" and all_gates_pass else "PARTIAL")
    return DiagnosticReceipt(state,fqdn_sni_witness,redact(fields))
