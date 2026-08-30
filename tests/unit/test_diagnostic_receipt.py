from collectors.receipt import REQUIRED_DEPLOYED_GATES, make_receipt


def test_undetermined_fqdn_sni_can_never_be_labeled_ready_and_secrets_are_redacted():
    receipt=make_receipt(fqdn_sni_witness="UNDETERMINED",fields={"conversation_digest":"sha256:abc","database_url":"postgresql://secret","authorization":"Bearer x"})
    assert receipt.state=="PARTIAL"
    assert receipt.fields["database_url"]=="[REDACTED]" and receipt.fields["authorization"]=="[REDACTED]"

def test_a_passing_network_witness_without_all_deployed_gates_is_still_partial():
    assert make_receipt(fqdn_sni_witness="PASS",fields={}).state=="PARTIAL"
    incomplete={"deployed_gates":"PASS",**{gate:"PASS" for gate in REQUIRED_DEPLOYED_GATES-{"image_proof"}}}
    assert make_receipt(fqdn_sni_witness="PASS",fields=incomplete).state=="PARTIAL"
    complete={"deployed_gates":"PASS",**{gate:"PASS" for gate in REQUIRED_DEPLOYED_GATES}}
    assert make_receipt(fqdn_sni_witness="PASS",fields=complete).state=="READY"


def test_sensitive_dsn_and_private_key_values_are_redacted_even_with_benign_keys():
    receipt=make_receipt(fqdn_sni_witness="UNDETERMINED",fields={
        "operator_note":"postgresql://admin:secret@private/db",
        "other":"-----BEGIN PRIVATE KEY-----\nopaque",
    })
    assert receipt.fields == {"operator_note":"[REDACTED]", "other":"[REDACTED]"}
