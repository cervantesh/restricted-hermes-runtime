from collectors.receipt import make_receipt


def test_undetermined_fqdn_sni_can_never_be_labeled_ready_and_secrets_are_redacted():
    receipt=make_receipt(fqdn_sni_witness="UNDETERMINED",fields={"conversation_digest":"sha256:abc","database_url":"postgresql://secret","authorization":"Bearer x"})
    assert receipt.state=="PARTIAL"
    assert receipt.fields["database_url"]=="[REDACTED]" and receipt.fields["authorization"]=="[REDACTED]"
