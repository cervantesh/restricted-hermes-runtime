import os
import pytest
from restricted_runtime.contracts import ContractError, content_aad
from restricted_runtime.crypto import decrypt, encrypt

def test_aad_binds_row_identity_and_non_repeating_nonces():
    key = os.urandom(32)
    aad = content_aad(tenant_id="t", conversation_id="c", conversation_epoch="e", turn_id="1", client_request_id="2", direction="response", policy_digest="p")
    one, two = encrypt(key, b"secret", aad), encrypt(key, b"secret", aad)
    assert one.nonce != two.nonce and decrypt(key, one, aad) == b"secret"
    swapped = content_aad(tenant_id="t", conversation_id="other", conversation_epoch="e", turn_id="1", client_request_id="2", direction="response", policy_digest="p")
    with pytest.raises(ContractError): decrypt(key, one, swapped)
