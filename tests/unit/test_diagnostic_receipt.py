from pathlib import Path
import json
import subprocess

import pytest

from collectors.receipt import REQUIRED_DEPLOYED_GATES, collect_provenance, make_receipt


def complete_fields():
    head=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip()
    policy=json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"))
    provenance=collect_provenance(runtime_root=Path("."),contract_root=Path("."),contract_base=head,contract_head=head,policy_epoch=policy["policy_epoch"],policy_path=Path("policy/policy.template.json"),test_command="python -m pytest tests/unit/test_diagnostic_receipt.py -q",test_count=1,postgres_version="PostgreSQL 18.4",test_output_path=Path("tests/fixtures/receipt/synthetic_collector_output.txt"))
    return {
        **{gate:"PASS" for gate in REQUIRED_DEPLOYED_GATES},
        "conversation_image_digest":"sha256:"+"1"*64,
        "gateway_image_digest":"sha256:"+"2"*64,
        "runner_image_digest":"sha256:"+"3"*64,
        "migration_image_digest":"sha256:"+"4"*64,
        **provenance,
    }


def test_undetermined_fqdn_sni_can_never_be_labeled_ready_and_secrets_are_redacted():
    receipt=make_receipt(fqdn_sni_witness="UNDETERMINED",fields={"conversation_digest":"sha256:abc","database_url":"postgresql://secret","authorization":"Bearer x"})
    assert receipt.state=="PARTIAL"
    assert receipt.fields["database_url"]=="[REDACTED]" and receipt.fields["authorization"]=="[REDACTED]"

def test_a_passing_network_witness_without_all_deployed_gates_is_still_partial():
    assert make_receipt(fqdn_sni_witness="PASS",fields={}).state=="PARTIAL"
    incomplete={gate:"PASS" for gate in REQUIRED_DEPLOYED_GATES-{"one_dispatch"}}
    assert make_receipt(fqdn_sni_witness="PASS",fields=incomplete).state=="PARTIAL"
    complete=complete_fields()
    assert make_receipt(fqdn_sni_witness="PASS",fields=complete,provenance=complete).state=="READY"


def test_sensitive_dsn_and_private_key_values_are_redacted_even_with_benign_keys():
    receipt=make_receipt(fqdn_sni_witness="UNDETERMINED",fields={
        "operator_note":"postgresql://admin:secret@private/db",
        "other":"-----BEGIN PRIVATE KEY-----\nopaque",
    })
    assert receipt.fields == {"operator_note":"[REDACTED]", "other":"[REDACTED]"}


def test_receipt_requires_immutable_revision_digest_and_policy_evidence_not_only_pass_words():
    incomplete=complete_fields(); incomplete["policy_digest"]="PASS"
    assert make_receipt(fqdn_sni_witness="PASS",fields=incomplete).state=="PARTIAL"
    incomplete=complete_fields(); del incomplete["runtime_head_revision"]
    assert make_receipt(fqdn_sni_witness="PASS",fields=incomplete).state=="PARTIAL"
    assert make_receipt(fqdn_sni_witness="UNDETERMINED",fields=complete_fields()).state=="PARTIAL"


def test_fabricated_pass_strings_or_unresolvable_contract_revision_never_promote_ready():
    fabricated={**complete_fields(),"contract_head_revision":"f"*40}
    assert make_receipt(fqdn_sni_witness="PASS",fields=fabricated).state=="PARTIAL"
    with pytest.raises(ValueError,match="not a commit"):
        collect_provenance(runtime_root=Path("."),contract_root=Path("."),contract_base="0"*40,contract_head="0"*40,policy_epoch="REQUIRED_MONOTONIC_EPOCH",policy_path=Path("policy/policy.template.json"),test_command="python -m pytest tests/unit/test_diagnostic_receipt.py -q",test_count=1,postgres_version="PostgreSQL 18.4",test_output_path=Path("tests/fixtures/receipt/synthetic_collector_output.txt"))
