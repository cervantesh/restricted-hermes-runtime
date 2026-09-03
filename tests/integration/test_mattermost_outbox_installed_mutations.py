"""Directed mutations against a pip-installed Mattermost outbox artifact.

These probes deliberately never patch the checkout import path.  Each child
gets a copied wheel installation, mutates that installed production module,
and reports the observable forbidden state.  They are not substitutes for the
TLS/WebSocket process witnesses; they prove that the persistence guarantees
are not merely nominal unit assertions.
"""
from __future__ import annotations

import json
import importlib.util
import os
import shutil
import socketserver
import ssl
import subprocess
import sys
import threading
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
        'if not isinstance(auth_tag, str) or not hmac.compare_digest(auth_tag, self._row_auth(row)):',
        "if False:",
    )
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


_TERMINAL_TAMPER_PROGRAM = r'''
import json, os, sqlite3, tempfile
from pathlib import Path
from restricted_runtime.contracts import ContractError
from restricted_runtime.mattermost_outbox import DeliveryState, MattermostOutbox, key_fingerprint
root=Path(tempfile.mkdtemp()); key=root/'key'; key.write_bytes(bytes(range(32))); os.chmod(key,0o600)
env={"schema_version":"restricted-mattermost-outbox.v1","tenant_id":"tenant","origin":"https://mm.example","channel_id":"channel","root_id":"root","source_id":"source","actor_id":"actor","message":"MUTATION_MESSAGE_CANARY","conversation_id":"conversation","conversation_epoch":None,"client_request_id":"request","policy_epoch":"policy","policy_digest":"a"*64,"key_fingerprint":key_fingerprint(bytes(range(32))),"policy_expires_at":4000000000,"payload_expires_at":4000000000,"response":None,"pending_post_id":"pending","returned_post_id":None}
store=MattermostOutbox.initialize(root/'state',key,expected_fingerprint=env['key_fingerprint'])
record,_=store.reserve(env,payload_capacity=3,tombstone_capacity=3)
store.terminal(record,DeliveryState.BLOCKED,reason='test'); store.close()
database=root/'state'/'mattermost-outbox.sqlite3'; conn=sqlite3.connect(database)
conn.execute("UPDATE records SET root_tag=?, state='READY' WHERE record_tag=?",('0'*64,record.record_tag)); conn.commit(); conn.close()
try:
 MattermostOutbox.open(root/'state',key,expected_fingerprint=env['key_fingerprint']); outcome='accepted'
except ContractError:
 outcome='rejected'
print(json.dumps({'outcome':outcome}))
'''


def test_installed_terminal_metadata_authentication_mutation_bites(installed_artifact, tmp_path):
    baseline = _run(_copy_artifact(installed_artifact, tmp_path / "baseline"), _TERMINAL_TAMPER_PROGRAM)
    assert baseline == {"outcome": "rejected"}
    mutant = _copy_artifact(installed_artifact, tmp_path / "mutant")
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        "                self._verify_row(row)\n",
        "                pass\n",
    )
    assert _run(mutant, _TERMINAL_TAMPER_PROGRAM) == {"outcome": "accepted"}


_NONCE_REUSE_PROGRAM = r'''
import json, os, tempfile
from pathlib import Path
from restricted_runtime.contracts import ContractError
import restricted_runtime.mattermost_outbox as module
from restricted_runtime.mattermost_outbox import DeliveryState, MattermostOutbox, key_fingerprint
root=Path(tempfile.mkdtemp()); key=root/'key'; key.write_bytes(bytes(range(32))); os.chmod(key,0o600)
fp=key_fingerprint(bytes(range(32)))
env={"schema_version":"restricted-mattermost-outbox.v1","tenant_id":"tenant","origin":"https://mm.example","channel_id":"channel","root_id":"root","source_id":"source","actor_id":"actor","message":"nonce test","conversation_id":"conversation","conversation_epoch":None,"client_request_id":"request","policy_epoch":"policy","policy_digest":"a"*64,"key_fingerprint":fp,"policy_expires_at":4000000000,"payload_expires_at":4000000000,"response":None,"pending_post_id":"pending","returned_post_id":None}
store=MattermostOutbox.initialize(root/'state',key,expected_fingerprint=fp)
module.secrets.token_bytes=lambda size: b'n'*size
first,_=store.reserve(env,payload_capacity=3,tombstone_capacity=3); store.terminal(first,DeliveryState.BLOCKED,reason='test')
try:
 store.reserve({**env,"source_id":"second","root_id":"second"},payload_capacity=3,tombstone_capacity=3); outcome='reused'
except ContractError:
 outcome='rejected'
print(json.dumps({'outcome':outcome,'nonces':store._connection.execute('SELECT COUNT(*) FROM nonce_tombstones').fetchone()[0]}))
'''


def test_installed_nonce_registry_mutation_allows_repeated_entropy_reuse(installed_artifact, tmp_path):
    baseline = _run(_copy_artifact(installed_artifact, tmp_path / "baseline"), _NONCE_REUSE_PROGRAM)
    assert baseline == {"outcome": "rejected", "nonces": 1}
    mutant = _copy_artifact(installed_artifact, tmp_path / "mutant")
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        'self._connection.execute(\n                    "INSERT INTO nonce_tombstones(sequence,nonce,chain_tag) VALUES(?,?,?)",\n                    (sequence, nonce, chain_tag),\n                )',
        "pass",
    )
    assert _run(mutant, _NONCE_REUSE_PROGRAM) == {"outcome": "reused", "nonces": 0}


_READINESS_PROGRAM = r'''
import json, os, tempfile
from pathlib import Path
from restricted_runtime.mattermost_outbox import MattermostOutbox, key_fingerprint
from restricted_runtime.mattermost_ingress import Ingress
root=Path(tempfile.mkdtemp()); key=root/'key'; key.write_bytes(bytes(range(32))); os.chmod(key,0o600); fp=key_fingerprint(bytes(range(32)))
class Policy:
 digest='a'*64; origin='https://mm.example'
 values={'policy_epoch':'policy','outbox_key_fingerprint':fp,'bot_user_id':'bot','bot_username':'bot','tenant_id':'tenant','team_id':'team','allowed_channel_ids':['channel'],'allowed_user_ids':['user'],'max_message_utf8_bytes':4096,'inference_policy_epoch':'inference','inference_policy_digest':'b'*64,'outbox_scan_limit':3,'conversation_deadline_seconds':4}
 def validate(self): pass
class Rest:
 def __init__(self): self.posts=0
 def get_me(self,*,definitive=False): return {'id':'bot','username':'bot'}
 def get_post(self,_,*,definitive=False): return source
 def get_channel(self,_,*,definitive=False): return {'id':'channel','team_id':'team','type':'P'}
 def get_channel_member(self,channel,user,*,definitive=False): return {'channel_id':channel,'user_id':user}
 def create_post(self,body): self.posts+=1; return {'id':'returned','channel_id':body['channel_id'],'root_id':body['root_id'],'pending_post_id':body['pending_post_id']}
class Conversation:
 def __init__(self): self.calls=0
 def ready(self): return {'status':'ready'}
 def create_conversation(self,*,conversation_id,deadline=None): return {'conversation_id':conversation_id,'conversation_epoch':'epoch'}
 def submit_turn(self,**_): self.calls+=1; return {'schema_version':'restricted-turn-result.v1','turn_id':'turn','conversation_epoch':'epoch','status':'COMMITTED','message':'answer'}
source={'id':'source','root_id':'','channel_id':'channel','user_id':'user','message':'@bot hello','type':'','file_ids':[],'edit_at':0,'delete_at':0}
policy=Policy(); rest=Rest(); conversation=Conversation(); store=MattermostOutbox.initialize(root/'state',key,expected_fingerprint=fp); service=Ingress(policy,rest,conversation,store)
env={'schema_version':'restricted-mattermost-outbox.v1','tenant_id':'tenant','origin':'https://mm.example','channel_id':'channel','root_id':'source','source_id':'source','actor_id':'user','message':'@bot hello','conversation_id':'conversation','conversation_epoch':None,'client_request_id':'request','policy_epoch':'policy','policy_digest':'a'*64,'key_fingerprint':fp,'policy_expires_at':4000000000,'payload_expires_at':4000000000,'response':None,'pending_post_id':'pending','returned_post_id':None}
record,_=store.reserve(env,payload_capacity=3,tombstone_capacity=3); service.executor.drain(); state=store.get(record.record_tag)
print(json.dumps({'state':state.state.value,'calls':conversation.calls,'posts':rest.posts}))
'''


def test_installed_readiness_binding_bypass_releases_recovery_work(installed_artifact, tmp_path):
    baseline = _run(_copy_artifact(installed_artifact, tmp_path / "baseline"), _READINESS_PROGRAM)
    assert baseline == {"state": "WAITING_COMMIT", "calls": 0, "posts": 0}
    mutant = _copy_artifact(installed_artifact, tmp_path / "mutant")
    _mutate(
        mutant,
        "restricted_runtime/mattermost_ingress.py",
        "    def _readiness_binding(self) -> None:\n",
        "    def _readiness_binding(self) -> None:\n        return\n",
    )
    assert _run(mutant, _READINESS_PROGRAM) == {"state": "DELIVERED", "calls": 1, "posts": 1}


_DUPLICATE_PROGRAM = r'''
import json, os, tempfile
from pathlib import Path
from restricted_runtime.mattermost_outbox import MattermostOutbox, key_fingerprint
root=Path(tempfile.mkdtemp()); key=root/'key'; key.write_bytes(bytes(range(32))); os.chmod(key,0o600)
env={"schema_version":"restricted-mattermost-outbox.v1","tenant_id":"tenant","origin":"https://mm.example","channel_id":"channel","root_id":"root","source_id":"source","actor_id":"actor","message":"MUTATION_MESSAGE_CANARY","conversation_id":"conversation","conversation_epoch":None,"client_request_id":"request","policy_epoch":"policy","policy_digest":"a"*64,"key_fingerprint":key_fingerprint(bytes(range(32))),"policy_expires_at":4000000000,"payload_expires_at":4000000000,"response":None,"pending_post_id":"pending","returned_post_id":None}
store=MattermostOutbox.initialize(root/'state',key,expected_fingerprint=env['key_fingerprint']); record,_=store.reserve(env,payload_capacity=3,tombstone_capacity=3)
ready=store.mark_ready(record,{**env,"response":"answer"}); flight=store.claim_delivery(ready); store.delivered(flight,returned_post_id="returned")
duplicate,created=store.reserve(env,payload_capacity=3,tombstone_capacity=3)
print(json.dumps({"created":created,"distinct":duplicate.record_tag!=record.record_tag,"rows":store._connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]}))
'''


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
        'row = next((item for item in rows if item["source_tag"] == source_tag), None)',
        "row = None",
    )
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        'return self._tag("record", envelope["tenant_id"], envelope["origin"], envelope["channel_id"], envelope["source_id"])',
        'return self._tag("record", envelope["tenant_id"], envelope["origin"], envelope["channel_id"], envelope["source_id"], secrets.token_hex(16))',
    )
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        "if (\n            not hmac.compare_digest(self.source_tag(envelope), row[\"source_tag\"])\n            or not hmac.compare_digest(self.root_tag(envelope), row[\"root_tag\"])\n            or not hmac.compare_digest(self.record_tag(envelope), row[\"record_tag\"])\n            or envelope[\"policy_digest\"] != row[\"policy_digest\"]\n        ):",
        "if False:",
    )
    result = _run(mutant, _DUPLICATE_PROGRAM)
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
        'self.terminal(record, DeliveryState.AMBIGUOUS, reason="restart_in_flight")',
        'self._transition(record, DeliveryState.IN_FLIGHT, DeliveryState.READY, envelope=record.envelope)',
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
        'if current["state"] != expected.value or current["generation"] != record.generation:',
        'if False:',
    )
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        'WHERE record_tag=? AND state=? AND generation=?",',
        'WHERE record_tag=?",',
    )
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        'record.record_tag, expected.value, record.generation,',
        'record.record_tag,',
    )
    assert _run(mutant, _CAS_PROGRAM) == {"first": True, "second": True}


_FENCE_PROGRAM = _PROGRAM.replace(
    'store._connection.execute("UPDATE records SET source_tag=CASE WHEN substr(source_tag,1,1)=\'0\' THEN \'1\' || substr(source_tag,2) ELSE \'0\' || substr(source_tag,2) END WHERE record_tag=?",(record.record_tag,))\ntry:\n    value=store.get(record.record_tag)\n    tamper="accepted" if value is not None else "empty"\nexcept ContractError:\n    tamper="rejected"\nprint(json.dumps({"plaintext":b"MUTATION_MESSAGE_CANARY" in raw,"tamper":tamper,"module":module.__file__}))',
    'store.terminal(record, DeliveryState.AMBIGUOUS, reason="test"); later={**env,"source_id":"later-source","message":"later"};\ntry:\n second,created=store.reserve(later,payload_capacity=3,tombstone_capacity=3); fenced=not created\nexcept ContractError:\n fenced=True\nprint(json.dumps({"fenced":fenced}))',
)


def test_installed_removed_root_fence_mutation_bites(installed_artifact, tmp_path):
    assert _run(_copy_artifact(installed_artifact, tmp_path / "baseline"), _FENCE_PROGRAM) == {"fenced": True}
    mutant = _copy_artifact(installed_artifact, tmp_path / "mutant")
    _mutate(
        mutant,
        "restricted_runtime/mattermost_outbox.py",
        'if any(item["root_tag"] == root_tag and item["state"] != DeliveryState.DELIVERED.value for item in rows):',
        "if False:",
    )
    assert _run(mutant, _FENCE_PROGRAM) == {"fenced": False}


_AUTH_PROGRAM = _PROGRAM.replace(
    'print(json.dumps({"plaintext":b"MUTATION_MESSAGE_CANARY" in raw,"tamper":tamper,"module":module.__file__}))',
    '''
from restricted_runtime.mattermost_ingress import Ingress
class Policy:
 values={"policy_epoch":"policy","outbox_key_fingerprint":env["key_fingerprint"],"bot_user_id":"bot","bot_username":"bot"}
 digest="a"*64
 origin="https://mm.example"
 def validate(self): pass
class Rest:
 def get_me(self,*,definitive=False): return {"id":"bot","username":"bot"}
 def get_post(self, source_id,*,definitive=False): return {"id":source_id,"channel_id":"wrong-channel","user_id":"wrong-actor"}
service=Ingress(Policy(), Rest(), object(), store)
try:
 service._revalidate_envelope(env); outcome="accepted"
except ContractError:
 outcome="rejected"
print(json.dumps({"outcome":outcome}))''',
)


def test_installed_skipped_fresh_source_actor_root_authorization_bites(installed_artifact, tmp_path):
    """A current source mismatch must stop recovery before UDS or REST release."""
    assert _run(_copy_artifact(installed_artifact, tmp_path / "baseline"), _AUTH_PROGRAM) == {"outcome": "rejected"}
    mutant = _copy_artifact(installed_artifact, tmp_path / "mutant")
    _mutate(
        mutant,
        "restricted_runtime/mattermost_ingress.py",
        'source = self.rest.get_post(envelope["source_id"], definitive=True)',
        'return\n        source = self.rest.get_post(envelope["source_id"], definitive=True)',
    )
    assert _run(mutant, _AUTH_PROGRAM) == {"outcome": "accepted"}


@pytest.mark.skipif(os.name == "nt", reason="requires real POSIX AF_UNIX process witness")
def test_installed_reservation_commit_survives_post_turn_crash(installed_artifact, tmp_path):
    """A sitecustomize kill after the causal UDS reply exposes deferred commit."""
    fixed = Path("/run/restricted-inference/conversation.sock")
    if fixed.exists():
        pytest.skip("conversation socket belongs to another runtime")
    socket_path = tmp_path / "conversation.sock"
    counts = {"turns": 0}
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            request_line = self.rfile.readline().decode().split()
            headers = {}
            while (line := self.rfile.readline()) != b"\r\n":
                name, value = line.decode().split(":", 1)
                headers[name.lower()] = value.strip()
            raw_body = self.rfile.read(int(headers["content-length"]))
            if request_line[1].endswith("/turns"):
                body = json.loads(raw_body)
                counts["turns"] += 1
                value = {"schema_version":"restricted-turn-result.v1","turn_id":"turn","conversation_epoch":body["conversation_epoch"],"status":"COMMITTED","message":"response"}
            else:
                value = {"schema_version":"restricted-conversation.v1","conversation_id":request_line[1].rsplit("/",1)[-1],"conversation_epoch":"epoch-one"}
            raw = json.dumps(value).encode()
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(raw)).encode() + b"\r\n\r\n" + raw)
    server = socketserver.ThreadingUnixStreamServer(str(socket_path), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    key = tmp_path / "key"
    key.write_bytes(bytes(range(32)))
    os.chmod(key, 0o600)
    program = r'''
import os
from pathlib import Path
from restricted_runtime.mattermost_outbox import MattermostOutbox,key_fingerprint
from restricted_runtime.mattermost_ingress import ConversationUdsClient
class P: values={"uds_timeout_seconds":5,"conversation_deadline_seconds":4}
key=Path(os.environ["KEY"]); state=Path(os.environ["STATE"]); fp=key_fingerprint(bytes(range(32)))
store=MattermostOutbox.open(state,key,expected_fingerprint=fp) if state.exists() else MattermostOutbox.initialize(state,key,expected_fingerprint=fp)
e={"schema_version":"restricted-mattermost-outbox.v1","tenant_id":"t","origin":"https://x","channel_id":"c","root_id":"r","source_id":"s","actor_id":"a","message":"m","conversation_id":"conversation","conversation_epoch":None,"client_request_id":"request","policy_epoch":"p","policy_digest":"a"*64,"key_fingerprint":fp,"policy_expires_at":4000000000,"payload_expires_at":4000000000,"response":None,"pending_post_id":"pending","returned_post_id":None}
r,_=store.reserve(e,payload_capacity=3,tombstone_capacity=3); client=ConversationUdsClient(P()); created=client.create_conversation(conversation_id=e["conversation_id"]); e={**e,"conversation_epoch":created["conversation_epoch"]}; r=store.update_waiting(r,e); result=client.submit_turn(conversation_id=e["conversation_id"],conversation_epoch=e["conversation_epoch"],client_request_id=e["client_request_id"],message=e["message"]); store.mark_ready(r,{**e,"response":result["message"]})
'''
    def kill_after_turn(site, state):
        wrapper = tmp_path / ("wrapper-" + state.name)
        wrapper.mkdir(exist_ok=True)
        (wrapper / "sitecustomize.py").write_text("import os\nfrom restricted_runtime.mattermost_outbox import MattermostOutbox\ndef stop(self,*a,**k): os._exit(86)\nMattermostOutbox.mark_ready=stop\n")
        fixed.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(socket_path, fixed)
        try:
            return subprocess.run([sys.executable,"-B","-c",program], cwd=ROOT, env={**os.environ,"PYTHONPATH":os.pathsep.join((str(wrapper),str(site))),"KEY":str(key),"STATE":str(state)}, timeout=20).returncode
        finally:
            fixed.unlink(missing_ok=True)
    try:
        baseline = tmp_path / "baseline-state"
        assert kill_after_turn(_copy_artifact(installed_artifact,tmp_path/"baseline"),baseline) == 86
        check = _run(_copy_artifact(installed_artifact,tmp_path/"check"), f'''from pathlib import Path\nfrom restricted_runtime.mattermost_outbox import MattermostOutbox,key_fingerprint\nimport json\ns=MattermostOutbox.open(Path(r"{baseline}"),Path(r"{key}"),expected_fingerprint=key_fingerprint(bytes(range(32))))\nrows=s._connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]\nprint(json.dumps({{"rows":rows}}))''')
        assert check == {"rows":1}
        mutant = _copy_artifact(installed_artifact,tmp_path/"mutant")
        _mutate(mutant,"restricted_runtime/mattermost_outbox.py",'self._connection.execute("COMMIT")\n                return result, True','return result, True')
        lost = tmp_path / "lost-state"
        assert kill_after_turn(mutant,lost) == 1
        assert _run(_copy_artifact(installed_artifact,tmp_path/"lostcheck"), f'''from pathlib import Path\nfrom restricted_runtime.mattermost_outbox import MattermostOutbox,key_fingerprint\nimport json\ns=MattermostOutbox.open(Path(r"{lost}"),Path(r"{key}"),expected_fingerprint=key_fingerprint(bytes(range(32))))\nn=s._connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]\nprint(json.dumps({{"rows":n}}))''') == {"rows":0}
        assert counts["turns"] == 1
    finally:
        fixed.unlink(missing_ok=True)
        server.shutdown()
        server.server_close()
        socket_path.unlink(missing_ok=True)


@pytest.mark.skipif(
    os.name == "nt" or not os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL"),
    reason="requires isolated PostgreSQL and POSIX AF_UNIX",
)
def test_installed_recovery_cannot_regenerate_epoch_or_request_after_restart(installed_artifact, tmp_path):
    """The real PostgreSQL witness must retain the encrypted epoch/request.

    The existing witness drives the actual ``ConversationService`` and its
    PostgreSQL stores; only its provider is counting.  Running it in a child
    with a copied wheel proves import resolution targets the installed runtime.
    The directed mutant changes the recovery executor's persisted identity to
    a new epoch/request.  Its failure is the forbidden second inference or
    invalid replay, never a permitted recovery result.
    """
    target = "tests/integration/test_mattermost_outbox_postgres_recovery.py::test_real_postgres_recovery_replays_original_epoch_without_second_provider_dispatch"

    def run(site: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
                [sys.executable, "-B", "-m", "pytest", "-vv", target], cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(site), "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=90,
        )

    baseline = run(_copy_artifact(installed_artifact, tmp_path / "baseline"))
    assert baseline.returncode == 0, baseline.stdout + baseline.stderr
    mutant = _copy_artifact(installed_artifact, tmp_path / "mutant")
    _mutate(
        mutant,
        "restricted_runtime/mattermost_ingress.py",
        "envelope = record.envelope\n        if envelope is None:",
        'envelope = {**record.envelope, "conversation_epoch": None, "client_request_id": str(uuid.uuid4())}\n        if envelope is None:',
    )
    result = run(mutant)
    assert result.returncode != 0
    assert "calls" in result.stdout + result.stderr


@pytest.mark.skipif(
    os.name == "nt" or getattr(os, "geteuid", lambda: 1)() != 0,
    reason="requires isolated Linux AF_UNIX and fixed production state paths",
)
def test_installed_memory_fallback_mutation_bites_after_restart(installed_artifact, tmp_path):
    """A compound memory fallback must turn a restart into a duplicate effect.

    The control starts the actual installed production module with an invalid
    state database.  It must terminate before any Mattermost REST/WebSocket or
    conversation UDS effect.  The directed mutant removes that barrier and
    returns a process-local outbox with the same interface.  Running the same
    source event through two fresh processes then proves the forbidden effect:
    one turn and one post per restart, because the memory store forgets the
    first reservation.
    """
    # The parent test process imports only the existing peer harness.  The
    # production processes below receive a copied wheel through PYTHONPATH and
    # never inherit this checkout import path.
    source_path = str(ROOT / "src")
    sys.path.insert(0, source_path)
    harness_spec = importlib.util.spec_from_file_location(
        "mattermost_process_harness", ROOT / "tests/integration/test_mattermost_ingress_process.py"
    )
    assert harness_spec and harness_spec.loader
    harness = importlib.util.module_from_spec(harness_spec)
    try:
        harness_spec.loader.exec_module(harness)
    finally:
        sys.path.remove(source_path)
    socket_path = harness.SOCKET
    state_path = harness.OUTBOX_STATE
    if socket_path.exists():
        pytest.skip("conversation.sock already belongs to another runtime")
    if state_path.exists():
        pytest.skip("outbox state path already belongs to another runtime")

    peer_handler = harness.PeerHandler
    conversation_handler = harness.ConversationHandler
    original_get = peer_handler.do_GET

    def counted_get(self):
        if self.path != "/api/v4/websocket":
            type(self).rest_requests += 1
        return original_get(self)

    peer_handler.do_GET = counted_get
    peer_handler.mode = "success"
    conversation_handler.mode = "success"
    peer = None
    conversation = None
    try:
        peer_handler.rest_requests = 0
        peer_handler.posts = []
        peer_handler.delivered = threading.Event()
        peer_handler.websocket_connections = 0
        conversation_handler.turns = 0
        key_path, cert_path = harness._certificates(tmp_path)
        peer = harness.ThreadingHTTPServer(("127.0.0.1", 0), peer_handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        peer.socket = context.wrap_socket(peer.socket, server_side=True)
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        socket_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        conversation = socketserver.ThreadingUnixStreamServer(str(socket_path), conversation_handler)
        threading.Thread(target=conversation.serve_forever, daemon=True).start()
        policy, signature, public = harness._policy(tmp_path, peer.server_port)
        token = tmp_path / "token"
        token.write_text(harness.TOKEN, encoding="utf-8")
        outbox_key = tmp_path / "outbox.key"
        outbox_key.write_bytes(b"m" * 32)
        os.chmod(outbox_key, 0o600)
        state_path.mkdir(mode=0o700)
        database = state_path / "mattermost-outbox.sqlite3"
        database.write_bytes(b"INVALID_STATE_AFTER_RESTART")
        os.chmod(database, 0o600)
        environment = {
            **os.environ,
            "PYTHONPATH": str(ROOT / "src"),
            "RESTRICTED_MATTERMOST_POLICY_PATH": str(policy),
            "RESTRICTED_MATTERMOST_POLICY_SIGNATURE_PATH": str(signature),
            "RESTRICTED_MATTERMOST_POLICY_PUBLIC_KEY_B64": public,
            "RESTRICTED_MATTERMOST_TOKEN_PATH": str(token),
            "RESTRICTED_MATTERMOST_CA_PATH": str(cert_path),
            "RESTRICTED_MATTERMOST_OUTBOX_KEY_PATH": str(outbox_key),
            "HTTP_PROXY": "http://127.0.0.1:1",
            "HTTPS_PROXY": "http://127.0.0.1:1",
        }

        def run_process(site: Path, *, expect_success: bool) -> dict[str, int]:
            peer_handler.posts = []
            peer_handler.delivered = threading.Event()
            peer_handler.websocket_connections = 0
            peer_handler.rest_requests = 0
            conversation_handler.turns = 0
            env = {**environment, "PYTHONPATH": str(site)}
            process = subprocess.Popen(
                [sys.executable, "-B", "-m", "restricted_runtime.services.production_mattermost_ingress"],
                cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                if expect_success:
                    assert peer_handler.delivered.wait(15)
                    assert conversation_handler.turns == 1
                    assert len(peer_handler.posts) == 1
                    return {
                        "turns": conversation_handler.turns,
                        "posts": len(peer_handler.posts),
                        "websocket": peer_handler.websocket_connections,
                        "rest": peer_handler.rest_requests,
                    }
                assert process.wait(timeout=10) == 1
                return {
                    "turns": conversation_handler.turns,
                    "posts": len(peer_handler.posts),
                    "websocket": peer_handler.websocket_connections,
                    "rest": peer_handler.rest_requests,
                }
            finally:
                if process.poll() is None:
                    process.terminate()
                stdout, stderr = process.communicate(timeout=10)
                if not expect_success:
                    assert "mattermost_ingress_outcome=terminal" in stdout + stderr

        baseline_site = _copy_artifact(installed_artifact, tmp_path / "baseline")
        baseline_origin = _run(
            baseline_site,
            'import restricted_runtime.mattermost_outbox as m, json; print(json.dumps({"module":m.__file__}))',
        )
        assert str(baseline_origin["module"]).startswith(str(baseline_site))
        baseline = run_process(baseline_site, expect_success=False)
        assert baseline == {"turns": 0, "posts": 0, "websocket": 0, "rest": 0}

        mutant = _copy_artifact(installed_artifact, tmp_path / "mutant")
        memory_outbox = '''
class _MemoryOutbox:
    """Directed mutant only: a non-durable replacement for the real outbox."""
    def __init__(self):
        self.records = {}

    @staticmethod
    def _record(envelope, state, generation=0, reason=None):
        payload = envelope if state.value not in {"DELIVERED", "AMBIGUOUS", "BLOCKED", "FAILED", "EXPIRED"} else None
        return OutboxRecord(
            envelope["source_id"], envelope["source_id"], envelope["root_id"], state,
            generation, 0, 0, envelope["payload_expires_at"], envelope["policy_expires_at"], payload, reason,
        )

    def close(self):
        return None

    def reserve(self, envelope, *, payload_capacity, tombstone_capacity):
        existing = self.records.get(envelope["source_id"])
        if existing is not None:
            return existing, False
        record = self._record(envelope, DeliveryState.WAITING_COMMIT)
        self.records[record.record_tag] = record
        return record, True

    def get(self, record_tag):
        return self.records.get(record_tag)

    def candidates(self, limit):
        active = {DeliveryState.WAITING_COMMIT, DeliveryState.READY, DeliveryState.IN_FLIGHT}
        return [record for record in self.records.values() if record.state in active][:limit]

    def stale_inflight_to_ambiguous(self):
        changed = 0
        for key, record in list(self.records.items()):
            if record.state is DeliveryState.IN_FLIGHT:
                replacement = self._record(record.envelope, DeliveryState.AMBIGUOUS, record.generation + 1, "restart_in_flight")
                self.records[key] = replacement
                changed += 1
        return changed

    def update_waiting(self, record, envelope):
        replacement = self._record(envelope, DeliveryState.WAITING_COMMIT, record.generation + 1)
        self.records[record.record_tag] = replacement
        return replacement

    def mark_ready(self, record, envelope):
        replacement = self._record(envelope, DeliveryState.READY, record.generation + 1)
        self.records[record.record_tag] = replacement
        return replacement

    def claim_delivery(self, record):
        if record.state is not DeliveryState.READY:
            return None
        replacement = self._record(record.envelope, DeliveryState.IN_FLIGHT, record.generation + 1)
        self.records[record.record_tag] = replacement
        return replacement

    def terminal(self, record, state, *, reason):
        replacement = self._record(record.envelope, state, record.generation + 1, reason)
        self.records[record.record_tag] = replacement
        return replacement

    def delivered(self, record, *, returned_post_id):
        return self.terminal(record, DeliveryState.DELIVERED, reason="exact_immediate_binding")
'''
        _mutate(mutant, "restricted_runtime/mattermost_outbox.py", "class MattermostOutbox:", memory_outbox + "\n\nclass MattermostOutbox:")
        _mutate(mutant, "restricted_runtime/mattermost_outbox.py", "        _state_dir(state_dir, create=False)", "        return _MemoryOutbox()")
        mutant_origin = _run(
            mutant,
            'import restricted_runtime.mattermost_outbox as m, json; print(json.dumps({"module":m.__file__}))',
        )
        assert str(mutant_origin["module"]).startswith(str(mutant))
        first = run_process(mutant, expect_success=True)
        second = run_process(mutant, expect_success=True)
        for result in (first, second):
            assert result["turns"] == 1
            assert result["posts"] == 1
            assert result["websocket"] >= 1
            assert result["rest"] > 0
        assert first["turns"] + second["turns"] == 2
        assert first["posts"] + second["posts"] == 2
    finally:
        peer_handler.do_GET = original_get
        if conversation is not None:
            conversation.shutdown()
            conversation.server_close()
        if peer is not None:
            peer.shutdown()
            peer.server_close()
        socket_path.unlink(missing_ok=True)
        shutil.rmtree(state_path, ignore_errors=True)
