import os
import pytest
from restricted_runtime.auth import SyntheticAuthenticator, production_authenticator
from restricted_runtime.contracts import ContractError

def test_synthetic_authenticator_is_explicit_and_does_not_accept_header_spoofing():
    auth=SyntheticAuthenticator("caller")
    assert auth.authenticate("Synthetic test credential")=="caller"
    with pytest.raises(ContractError):auth.authenticate("x-restricted-verified-principal: caller")

def test_production_composition_rejects_synthetic_mode(monkeypatch):
    monkeypatch.setenv("RESTRICTED_RUNTIME_MODE","synthetic")
    with pytest.raises(RuntimeError):production_authenticator(audience="a",caller_principal="p")
