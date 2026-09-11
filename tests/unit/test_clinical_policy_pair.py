from __future__ import annotations

import base64
import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[2]
SRC = str(ROOT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
CONTROL = ROOT / "tests" / "deployment" / "clinical-composed-e2e" / "control.py"


def load_control():
    spec = importlib.util.spec_from_file_location("clinical_control", CONTROL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("fail_at", ["before-signature", "before-policy"])
def test_policy_pair_interruption_is_fail_closed_and_retryable(tmp_path: Path, fail_at: str):
    module = load_control()
    private = Ed25519PrivateKey.generate()
    old_raw = b'{"policy_epoch":"old"}'
    old_sig = base64.b64encode(private.sign(old_raw))
    (tmp_path / "policy.json").write_bytes(old_raw)
    (tmp_path / "policy.sig").write_bytes(old_sig)
    new_raw = b'{"policy_epoch":"new"}'
    new_sig = base64.b64encode(private.sign(new_raw))

    with pytest.raises(RuntimeError, match="injected"):
        module.install_policy_pair(tmp_path, new_raw, new_sig, private.public_key(), fail_at=fail_at)
    if fail_at == "before-signature":
        assert module.verify_policy_pair(tmp_path, private.public_key()) == module.hashlib.sha256(old_raw).hexdigest()
    else:
        with pytest.raises(RuntimeError, match="mismatch"):
            module.verify_policy_pair(tmp_path, private.public_key())

    module.install_policy_pair(tmp_path, new_raw, new_sig, private.public_key())
    assert module.verify_policy_pair(tmp_path, private.public_key()) == module.hashlib.sha256(new_raw).hexdigest()


def test_active_policy_binding_uses_the_same_verified_bytes_for_epoch_and_digest(tmp_path: Path, monkeypatch):
    module = load_control()
    verified_raw = b'{"policy_epoch":"verified"}'
    replacement = b'{"policy_epoch":"replaced"}'
    monkeypatch.setattr(module, "INGRESS", tmp_path)
    monkeypatch.setattr(module, "policy_private", lambda: type("Key", (), {"public_key": lambda self: None})())
    (tmp_path / "policy.json").write_bytes(verified_raw)
    def replace_after_verification(*_args):
        (tmp_path / "policy.json").write_bytes(replacement)
        return verified_raw, hashlib.sha256(verified_raw).hexdigest()
    monkeypatch.setattr(module, "verified_policy_bytes", replace_after_verification)
    assert module.active_policy_binding() == {"epoch": "verified", "digest": "sha256:" + hashlib.sha256(verified_raw).hexdigest()}
