"""Adversarial checks for the retired-key contract and startup configuration."""
from __future__ import annotations

import ast
import hashlib
import json
import os
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


def test_retired_key_cannot_sign_new_records():
    retired=key("retired","retired-v1")
    with pytest.raises(PermissionError):
        retired.sign(b"new canonical digest")


def test_production_roots_must_not_discard_retired_key_configuration():
    for path in (Path("src/restricted_runtime/services/production_conversation.py"),Path("src/restricted_runtime/services/production_gateway.py")):
        tree=ast.parse(path.read_text(encoding="utf-8"));calls=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="GoogleKmsHmacKey": calls.append(node)
        assert calls
        assert all(not (isinstance(c.args[2],ast.Dict) and not c.args[2].keys) for c in calls), path

def test_production_retired_key_configuration_is_closed_and_duplicate_free(monkeypatch):
    valid=json.dumps([{"key_resource":"old","key_version":"v1","verify_version":"old/cryptoKeyVersions/v1"}])
    assert parse_retired_versions(valid,active_resource="active",active_version="active-v1")=={("old","v1"):"old/cryptoKeyVersions/v1"}
    for raw in ("{",json.dumps({"key_resource":"old"}),json.dumps([{"key_resource":"old","key_version":"v1","verify_version":"x","extra":1}]),json.dumps([{"key_resource":"old","key_version":"v1","verify_version":"old/cryptoKeyVersions/v1"},{"key_resource":"old","key_version":"v1","verify_version":"old/cryptoKeyVersions/v2"}]),'{"x":1,"x":2}'):
        with pytest.raises((RuntimeError,ValueError)): parse_retired_versions(raw,active_resource="active",active_version="active-v1")
