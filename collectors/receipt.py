"""Offline receipt guard: collectors may report evidence, never promote PHI readiness."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping
from pathlib import Path
import hashlib
import json
import re
import subprocess

SECRET_MARKERS=("token","secret","password","authorization","database_url","private_key")
REQUIRED_DEPLOYED_GATES=frozenset({
    "immutable_revisions_digests", "real_runner_provider_turn", "one_dispatch",
    "encrypted_commit_readback", "iam_oidc_vertex_negatives", "fault_crash_matrix",
    "privacy_canaries", "kms_rotation_iam", "rollback_kill_switch",
    "network_baseline", "lifecycle_ttl",
})
IMMUTABLE_EVIDENCE_FIELDS={
    "contract_base_revision":re.compile(r"^[0-9a-f]{40,64}$"),
    "contract_head_revision":re.compile(r"^[0-9a-f]{40,64}$"),
    "runtime_head_revision":re.compile(r"^[0-9a-f]{40,64}$"),
    "conversation_image_digest":re.compile(r"^sha256:[0-9a-f]{64}$"),
    "gateway_image_digest":re.compile(r"^sha256:[0-9a-f]{64}$"),
    "runner_image_digest":re.compile(r"^sha256:[0-9a-f]{64}$"),
    "migration_image_digest":re.compile(r"^sha256:[0-9a-f]{64}$"),
    "policy_epoch":re.compile(r"^.{1,256}$"),
    "policy_digest":re.compile(r"^sha256:[0-9a-f]{64}$"),
    "instruction_sha256":re.compile(r"^[0-9a-f]{64}$"),
    "response_profile":re.compile(r"^restricted-vertex-text-response\.v1$"),
    "migration_sha256":re.compile(r"^[0-9a-f]{64}$"),
    "test_command":re.compile(r"^python -m pytest .+"),
    "test_result":re.compile(r"^PASS$"),
    "test_count":re.compile(r"^[1-9][0-9]*$"),
    "test_output_sha256":re.compile(r"^[0-9a-f]{64}$"),
    "postgres_version":re.compile(r"^PostgreSQL [0-9]+\.[0-9]+.*$"),
}
_SENSITIVE_VALUE=re.compile(r"(?:postgres(?:ql)?://|(?:password|secret|token)\s*[=:]|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+\S+|\bya29\.[A-Za-z0-9._-]+)",re.I)

@dataclass(frozen=True)
class DiagnosticReceipt:
    state: str
    fqdn_sni_witness: str
    fields: dict[str,str]


def redact(fields: Mapping[str,object]) -> dict[str,str]:
    return {str(k):("[REDACTED]" if any(marker in str(k).lower() for marker in SECRET_MARKERS) or _SENSITIVE_VALUE.search(str(v)) else str(v)) for k,v in fields.items()}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_revision(root: Path, revision: str) -> str:
    completed=subprocess.run(["git","-C",str(root),"rev-parse","--verify",f"{revision}^{{commit}}"],capture_output=True,text=True,check=False)
    if completed.returncode:
        raise ValueError("provenance revision is not a commit in its declared repository")
    return completed.stdout.strip()


def collect_provenance(*, runtime_root: Path, contract_root: Path, contract_base: str, contract_head: str, policy_epoch: str, policy_path: Path, test_command: str, test_count: int, postgres_version: str, test_output_path: Path) -> dict[str,str]:
    """Derive local immutable evidence; callers cannot promote arbitrary text."""
    runtime_root=runtime_root.resolve(); contract_root=contract_root.resolve()
    if not re.fullmatch(r"python -m pytest .+",test_command) or test_count < 1 or not re.fullmatch(r"PostgreSQL [0-9]+\.[0-9]+.*",postgres_version):
        raise ValueError("collector command, count, or PostgreSQL result is invalid")
    policy=json.loads(policy_path.read_text(encoding="utf-8"))
    from restricted_runtime.contracts import jcs_bytes
    if policy.get("policy_epoch") != policy_epoch:
        raise ValueError("collector policy epoch does not match the exact policy artifact")
    test_output=test_output_path.read_text(encoding="utf-8")
    if test_command not in test_output or f"{test_count} passed" not in test_output or postgres_version not in test_output:
        raise ValueError("collector output does not bind command, result count, and PostgreSQL version")
    instruction=(runtime_root/"src"/"restricted_runtime"/"policy.py").read_text(encoding="utf-8")
    instruction_match=re.search(r'SYSTEM_INSTRUCTION_SHA256 = "([0-9a-f]{64})"',instruction)
    if instruction_match is None:
        raise ValueError("instruction provenance is unavailable")
    return {
        "contract_base_revision":_git_revision(contract_root,contract_base),
        "contract_head_revision":_git_revision(contract_root,contract_head),
        "runtime_head_revision":_git_revision(runtime_root,"HEAD"),
        "policy_epoch":policy_epoch,
        "policy_digest":"sha256:"+hashlib.sha256(jcs_bytes(policy)).hexdigest(),
        "instruction_sha256":instruction_match.group(1),
        "response_profile":str(policy["response_profile"]),
        "migration_sha256":_sha256(runtime_root/"migrations"/"001_restricted_runtime.sql"),
        "test_command":test_command,
        "test_result":"PASS",
        "test_count":str(test_count),
        "test_output_sha256":hashlib.sha256(test_output.encode("utf-8")).hexdigest(),
        "postgres_version":postgres_version,
    }


def make_receipt(*, fqdn_sni_witness: str, fields: Mapping[str,object], provenance: Mapping[str,object] | None = None) -> DiagnosticReceipt:
    if fqdn_sni_witness not in {"PASS","UNDETERMINED","FAIL"}: raise ValueError("closed FQDN/SNI state")
    # A network witness is only one gate.  Deployed proof must be explicitly
    # complete; a missing collector result never promotes a synthetic receipt.
    immutable_evidence_valid=provenance is not None and all(pattern.fullmatch(str(fields.get(name,""))) and str(fields.get(name))==str(provenance.get(name)) for name,pattern in IMMUTABLE_EVIDENCE_FIELDS.items())
    all_gates_pass=all(fields.get(gate)=="PASS" for gate in REQUIRED_DEPLOYED_GATES) and immutable_evidence_valid
    state="FAILED" if fqdn_sni_witness=="FAIL" else ("READY" if fqdn_sni_witness=="PASS" and all_gates_pass else "PARTIAL")
    return DiagnosticReceipt(state,fqdn_sni_witness,redact(fields))
