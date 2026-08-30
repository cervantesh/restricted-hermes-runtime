import os
import pytest
from restricted_runtime.crypto import LocalHmacKey,SERVICE_MAC_DOMAIN,kms_mac_input
def test_large_canonical_inputs_have_fixed_kms_mac_shape():
    for size in (65_537,131_072):
        data=b"x"*size;value=kms_mac_input(SERVICE_MAC_DOMAIN,data)
        assert len(value)==len(SERVICE_MAC_DOMAIN)+1+8+32 and data not in value
def test_retired_separate_key_is_verify_only():
    active=LocalHmacKey("active","1",b"a"*32);retired=LocalHmacKey("retired","1",b"r"*32,can_sign=False)
    record=LocalHmacKey("retired","1",b"r"*32).sign(b"input")
    assert retired.verify(record,b"input")
    with pytest.raises(PermissionError):retired.sign(b"input")
