import pytest
from restricted_runtime.contracts import ContractError, TurnRequest, jcs_bytes, load_closed_json
from restricted_runtime.crypto import LocalHmacKey, SERVICE_MAC_DOMAIN, kms_mac_input

def test_duplicate_key_and_surrogate_reject_before_admission():
    with pytest.raises(ContractError): load_closed_json('{"a":1,"a":2}')
    with pytest.raises(ContractError): load_closed_json('"\\ud800"')

def test_identity_binds_all_associations_and_mac_is_fixed_size():
    request = TurnRequest.parse({"schema_version":"restricted-turn.v1", "client_request_id":"00000000-0000-0000-0000-000000000001", "conversation_epoch":"epoch", "message":"x"})
    a = jcs_bytes(request.identity(principal="caller-a", tenant_id="t", conversation_id="c"))
    b = jcs_bytes(request.identity(principal="caller-b", tenant_id="t", conversation_id="c"))
    assert a != b
    mac_input = kms_mac_input(SERVICE_MAC_DOMAIN, a)
    assert len(mac_input) == len(SERVICE_MAC_DOMAIN) + 1 + 8 + 32
    assert b"caller-a" not in mac_input
