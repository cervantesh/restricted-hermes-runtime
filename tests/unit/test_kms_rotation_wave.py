"""Adversarial checks for the retired-key contract and startup configuration."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

from restricted_runtime.crypto import MacRecord
from restricted_runtime.google_kms import GoogleKmsHmacKey
from restricted_runtime.kms_config import parse_retired_versions


class FakeKms:
    def mac_sign(self, request):
        return type("Reply", (), {"mac": hashlib.sha256(request["name"].encode()+request["data"]).digest()})()

    def mac_verify(self, request):
        expected=hashlib.sha256(request["name"].encode()+request["data"]).digest()
        return type("Reply", (), {"success": request["mac"] == expected})()


def key(resource, version, retired=None):
    value=object.__new__(GoogleKmsHmacKey);value.key_resource=resource;value.key_version=version;value.retired_versions=retired or {};value.client=FakeKms();return value


def test_active_sign_and_retired_verify_preserve_old_record():
    active=key("active", "active-v1", {("retired", "retired-v1"): "retired-v1"})
    record=active.sign(b"canonical digest")
    assert active.verify(record,b"canonical digest")
    old=MacRecord("retired","retired-v1",hashlib.sha256(b"retired-v1canonical digest").digest())
    assert active.verify(old,b"canonical digest")


def test_signing_is_bound_to_the_configured_active_key_not_a_retired_mapping():
    active=key("active","active-v2",{("retired","retired-v1"):"retired-v1"})
    record=active.sign(b"new canonical digest")
    assert (record.key_resource,record.key_version)==("active","active-v2")


def test_production_roots_must_not_discard_retired_key_configuration():
    for path in (Path("src/restricted_runtime/services/production_conversation.py"),Path("src/restricted_runtime/services/production_gateway.py")):
        tree=ast.parse(path.read_text(encoding="utf-8"));calls=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="GoogleKmsHmacKey": calls.append(node)
        assert calls
        assert all(not (isinstance(c.args[2],ast.Dict) and not c.args[2].keys) for c in calls), path

def test_production_retired_key_configuration_is_closed_and_rejects_active_or_ambiguous_aliases():
    active_resource="projects/p/locations/l/keyRings/r/cryptoKeys/service"
    active_version=active_resource+"/cryptoKeyVersions/7"
    retired_resource="projects/p/locations/l/keyRings/r/cryptoKeys/retired"
    good=json.dumps([{"key_resource":retired_resource,"key_version":"retired-id","verify_version":retired_resource+"/cryptoKeyVersions/3"}])
    assert parse_retired_versions(good,active_resource=active_resource,active_version=active_version)=={(retired_resource,"retired-id"):retired_resource+"/cryptoKeyVersions/3"}
    bad=(
        "{",
        '[{"key_resource":"a","key_resource":"b","key_version":"x","verify_version":"b/cryptoKeyVersions/1"}]',
        json.dumps([{"key_resource":active_resource,"key_version":active_version,"verify_version":active_version}]),
        json.dumps([{"key_resource":retired_resource,"key_version":"retired-id","verify_version":active_version}]),
        json.dumps([{"key_resource":retired_resource,"key_version":"retired-id","verify_version":"other/cryptoKeyVersions/3"}]),
        json.dumps([{"key_resource":retired_resource,"key_version":"retired-id","verify_version":retired_resource+"/cryptoKeyVersions/3"},{"key_resource":retired_resource,"key_version":"retired-id","verify_version":retired_resource+"/cryptoKeyVersions/4"}]),
    )
    for raw in bad:
        with pytest.raises(RuntimeError):
            parse_retired_versions(raw,active_resource=active_resource,active_version=active_version)
