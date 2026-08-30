"""Offline receipt guard: collectors may report evidence, never promote PHI readiness."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping

SECRET_MARKERS=("token","secret","password","authorization","database_url","private_key")

@dataclass(frozen=True)
class DiagnosticReceipt:
    state: str
    fqdn_sni_witness: str
    fields: dict[str,str]


def redact(fields: Mapping[str,object]) -> dict[str,str]:
    return {str(k):("[REDACTED]" if any(marker in str(k).lower() for marker in SECRET_MARKERS) else str(v)) for k,v in fields.items()}


def make_receipt(*, fqdn_sni_witness: str, fields: Mapping[str,object]) -> DiagnosticReceipt:
    if fqdn_sni_witness not in {"PASS","UNDETERMINED","FAIL"}: raise ValueError("closed FQDN/SNI state")
    # An unknown network witness is intentionally a partial synthetic result.
    state="PARTIAL" if fqdn_sni_witness=="UNDETERMINED" else ("READY" if fqdn_sni_witness=="PASS" else "FAILED")
    return DiagnosticReceipt(state,fqdn_sni_witness,redact(fields))
