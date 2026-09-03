"""Directed mutations against a pip-installed Mattermost outbox artifact.

These probes deliberately never patch the checkout import path.  Each child
gets a copied wheel installation, mutates that installed production module,
and reports the observable forbidden state.  They are not substitutes for the
TLS/WebSocket process witnesses; they prove that the persistence guarantees
are not merely nominal unit assertions.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def installed_artifact(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("installed-mattermost-outbox")
    wheelhouse = root / "wheelhouse"
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", ".", "--wheel-dir", str(wheelhouse)],
        cwd=ROOT, check=True, capture_output=True, text=True, timeout=120,
    )
    wheel = next(wheelhouse.glob("restricted_hermes_runtime-*.whl"))
    site = root / "site"
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(site), str(wheel)],
        cwd=ROOT, check=True, capture_output=True, text=True, timeout=120,
    )
    return site


def _copy_artifact(installed_artifact: Path, tmp_path: Path) -> Path:
    target = tmp_path / "site"
    shutil.copytree(installed_artifact, target)
    # ``pip --target`` may carry bytecode built before the directed edit.  The
    # child runs with ``-B`` but Python may still consume an already-valid pyc,
    # which would turn this into a checkout/source mutation in disguise.
    for cache in target.rglob("__pycache__"):
        shutil.rmtree(cache)
    return target


def _mutate(site: Path, relative: str, old: str, new: str) -> None:
    path = site / relative
    source = path.read_text(encoding="utf-8")
    assert old in source, f"mutation anchor disappeared: {relative}"
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def _run(site: Path, program: str) -> dict[str, object]:
    environment = {**os.environ, "PYTHONPATH": str(site), "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(
        [sys.executable, "-B", "-c", program], cwd=ROOT, env=environment,
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode:
        raise AssertionError(f"installed-artifact child failed: {result.stderr[-2000:]}")
    return json.loads(result.stdout)


_PROGRAM = r'''
import json, os, tempfile
from pathlib import Path
from restricted_runtime.contracts import ContractError
import restricted_runtime.mattermost_outbox as module
from restricted_runtime.mattermost_outbox import DeliveryState, MattermostOutbox, key_fingerprint
root=Path(tempfile.mkdtemp()); key=root/'key'; key.write_bytes(bytes(range(32))); os.chmod(key,0o600)
env={"schema_version":"restricted-mattermost-outbox.v1","tenant_id":"tenant","origin":"https://mm.example","channel_id":"channel","root_id":"root","source_id":"source","actor_id":"actor","message":"MUTATION_MESSAGE_CANARY","conversation_id":"conversation","conversation_epoch":None,"client_request_id":"request","policy_epoch":"policy","policy_digest":"a"*64,"key_fingerprint":key_fingerprint(bytes(range(32))),"policy_expires_at":4000000000,"payload_expires_at":4000000000,"response":None,"pending_post_id":"pending","returned_post_id":None}
store=MattermostOutbox.initialize(root/'state',key,expected_fingerprint=env['key_fingerprint'])
record,_=store.reserve(env,payload_capacity=3,tombstone_capacity=3)
database=root/'state'/'mattermost-outbox.sqlite3'
raw=b''.join(path.read_bytes() for path in (database, database.with_name(database.name+'-wal'), database.with_name(database.name+'-journal')) if path.exists())
store._connection.execute("UPDATE records SET source_tag=CASE WHEN substr(source_tag,1,1)='0' THEN '1' || substr(source_tag,2) ELSE '0' || substr(source_tag,2) END WHERE record_tag=?",(record.record_tag,))
try:
    value=store.get(record.record_tag)
    tamper="accepted" if value is not None else "empty"
except ContractError:
    tamper="rejected"
print(json.dumps({"plaintext":b"MUTATION_MESSAGE_CANARY" in raw,"tamper":tamper,"module":module.__file__}))
'''


def test_installed_plaintext_mutation_bites(installed_artifact, tmp_path):
    baseline = _run(_copy_artifact(installed_artifact, tmp_path / "baseline"), _PROGRAM)
    assert baseline["plaintext"] is False
    assert baseline["tamper"] == "rejected"
    assert str(baseline["module"]).startswith(str(tmp_path / "baseline" / "site"))
    mutant = _copy_artifact(installed_artifact, tmp_path / "mutant")
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        "payload = AESGCM(self._enc_key).encrypt(nonce, jcs_bytes(envelope), self._aad(record_tag=record_tag, source_tag=source_tag, root_tag=root_tag, policy_digest=envelope[\"policy_digest\"]))",
        "payload = jcs_bytes(envelope)",
    )
    result = _run(mutant, _PROGRAM)
    assert result["plaintext"] is True, result


def test_installed_lookup_aad_and_tag_check_mutation_bites(installed_artifact, tmp_path):
    mutant = _copy_artifact(installed_artifact, tmp_path / "mutant")
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        'return jcs_bytes({"schema_version": OUTBOX_SCHEMA, "record_tag": record_tag, "source_tag": source_tag, "root_tag": root_tag, "policy_digest": policy_digest})',
        'return jcs_bytes({"schema_version": OUTBOX_SCHEMA, "policy_digest": policy_digest})',
    )
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        "if (\n            not hmac.compare_digest(self.source_tag(envelope), row[\"source_tag\"])\n            or not hmac.compare_digest(self.root_tag(envelope), row[\"root_tag\"])\n            or not hmac.compare_digest(self.record_tag(envelope), row[\"record_tag\"])\n            or envelope[\"policy_digest\"] != row[\"policy_digest\"]\n        ):",
        "if False:",
    )
    result = _run(mutant, _PROGRAM)
    assert result["plaintext"] is False
    assert result["tamper"] == "accepted"


def test_installed_effective_source_uniqueness_mutation_admits_duplicate_rows(installed_artifact, tmp_path):
    """All durable duplicate backstops must be removed before the fault bites.

    The SQL ``source_tag UNIQUE`` declaration alone is deliberately redundant:
    ``reserve`` first resolves the existing source and the deterministic
    ``record_tag`` primary key is a second conflict backstop.  This compound
    installed-artifact mutant removes exactly those three effective branches;
    the forbidden observable is two independently reserved records for one
    Mattermost source.  Keeping the single-layer declaration mutation green
    would be a useful defense-in-depth observation, but is not counted as the
    required directed-mutation bite.
    """
    mutant = _copy_artifact(installed_artifact, tmp_path / "mutant")
    _mutate(mutant, "restricted_runtime/mattermost_outbox.py", "source_tag TEXT UNIQUE NOT NULL", "source_tag TEXT NOT NULL")
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        'row = self._connection.execute("SELECT * FROM records WHERE source_tag=?", (source_tag,)).fetchone()',
        "row = None",
    )
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        'return self._tag("record", envelope["tenant_id"], envelope["origin"], envelope["channel_id"], envelope["source_id"])',
        'return self._tag("record", envelope["tenant_id"], envelope["origin"], envelope["channel_id"], envelope["source_id"], secrets.token_hex(16))',
    )
    program = _PROGRAM.replace(
        'print(json.dumps({"plaintext":b"MUTATION_MESSAGE_CANARY" in raw,"tamper":tamper,"module":module.__file__}))',
        'store.terminal(record, DeliveryState.DELIVERED, reason="test"); duplicate, created=store.reserve(env,payload_capacity=3,tombstone_capacity=3); print(json.dumps({"created":created,"distinct":duplicate.record_tag!=record.record_tag,"rows":store._connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]}))',
    )
    result = _run(mutant, program)
    assert result == {"created": True, "distinct": True, "rows": 2}


_STATE_PROGRAM = _PROGRAM.replace(
    'store._connection.execute("UPDATE records SET source_tag=CASE WHEN substr(source_tag,1,1)=\'0\' THEN \'1\' || substr(source_tag,2) ELSE \'0\' || substr(source_tag,2) END WHERE record_tag=?",(record.record_tag,))\ntry:\n    value=store.get(record.record_tag)\n    tamper="accepted" if value is not None else "empty"\nexcept ContractError:\n    tamper="rejected"\nprint(json.dumps({"plaintext":b"MUTATION_MESSAGE_CANARY" in raw,"tamper":tamper,"module":module.__file__}))',
    'ready=store.mark_ready(record, {**env,"response":"answer"}); claimed=store.claim_delivery(ready); assert claimed is not None; changed=store.stale_inflight_to_ambiguous(); after=store.get(record.record_tag); print(json.dumps({"changed":changed,"state":after.state.value}))',
)


def test_installed_stale_inflight_ready_mutation_bites(installed_artifact, tmp_path):
    baseline = _run(_copy_artifact(installed_artifact, tmp_path / "baseline"), _STATE_PROGRAM)
    assert baseline == {"changed": 1, "state": "AMBIGUOUS"}
    mutant = _copy_artifact(installed_artifact, tmp_path / "mutant")
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        '(DeliveryState.AMBIGUOUS.value, now, "restart_in_flight", DeliveryState.IN_FLIGHT.value),',
        '(DeliveryState.READY.value, now, "restart_in_flight", DeliveryState.IN_FLIGHT.value),',
    )
    assert _run(mutant, _STATE_PROGRAM) == {"changed": 1, "state": "READY"}


_CAS_PROGRAM = _PROGRAM.replace(
    'store._connection.execute("UPDATE records SET source_tag=CASE WHEN substr(source_tag,1,1)=\'0\' THEN \'1\' || substr(source_tag,2) ELSE \'0\' || substr(source_tag,2) END WHERE record_tag=?",(record.record_tag,))\ntry:\n    value=store.get(record.record_tag)\n    tamper="accepted" if value is not None else "empty"\nexcept ContractError:\n    tamper="rejected"\nprint(json.dumps({"plaintext":b"MUTATION_MESSAGE_CANARY" in raw,"tamper":tamper,"module":module.__file__}))',
    'ready=store.mark_ready(record,{**env,"response":"answer"}); stale=store.get(record.record_tag); first=store.claim_delivery(ready); second=store.claim_delivery(stale); print(json.dumps({"first":first is not None,"second":second is not None}))',
)


def test_installed_non_cas_delivery_mutation_bites(installed_artifact, tmp_path):
    baseline = _run(_copy_artifact(installed_artifact, tmp_path / "baseline"), _CAS_PROGRAM)
    assert baseline == {"first": True, "second": False}
    mutant = _copy_artifact(installed_artifact, tmp_path / "mutant")
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        'WHERE record_tag=? AND state=? AND generation=?",',
        'WHERE record_tag=?",',
    )
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        '(target.value, now, nonce, ciphertext, reason, record.record_tag, expected.value, record.generation),',
        '(target.value, now, nonce, ciphertext, reason, record.record_tag),',
    )
    assert _run(mutant, _CAS_PROGRAM) == {"first": True, "second": True}


_FENCE_PROGRAM = _PROGRAM.replace(
    'store._connection.execute("UPDATE records SET source_tag=CASE WHEN substr(source_tag,1,1)=\'0\' THEN \'1\' || substr(source_tag,2) ELSE \'0\' || substr(source_tag,2) END WHERE record_tag=?",(record.record_tag,))\ntry:\n    value=store.get(record.record_tag)\n    tamper="accepted" if value is not None else "empty"\nexcept ContractError:\n    tamper="rejected"\nprint(json.dumps({"plaintext":b"MUTATION_MESSAGE_CANARY" in raw,"tamper":tamper,"module":module.__file__}))',
    'store.terminal(record, DeliveryState.AMBIGUOUS, reason="test"); later={**env,"source_id":"later-source","message":"later"};\ntry:\n second,created=store.reserve(later,payload_capacity=3,tombstone_capacity=3); fenced=not created\nexcept ContractError:\n fenced=True\nprint(json.dumps({"fenced":fenced}))',
)


def test_installed_removed_root_fence_mutation_bites(installed_artifact, tmp_path):
    assert _run(_copy_artifact(installed_artifact, tmp_path / "baseline"), _FENCE_PROGRAM) == {"fenced": True}
    mutant = _copy_artifact(installed_artifact, tmp_path / "mutant")
    _mutate(mutant, "restricted_runtime/mattermost_outbox.py", "if fence is not None:", "if False:")
    assert _run(mutant, _FENCE_PROGRAM) == {"fenced": False}
