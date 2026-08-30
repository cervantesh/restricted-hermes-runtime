"""Real PostgreSQL acceptance tests: isolated schemas, constraints, races and CAS."""
import hashlib,json,os,threading,uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import psycopg,pytest
from restricted_runtime.contracts import AttemptState,ContractError,TurnState,jcs_bytes
from restricted_runtime.conversation import TurnRow
from restricted_runtime.crypto import GATEWAY_MAC_DOMAIN,LocalHmacKey,kms_mac_input
from restricted_runtime.gateway import GatewayEnvelope,Gateway
from restricted_runtime.policy import PolicyBundle,SYSTEM_INSTRUCTION
from restricted_runtime.storage import PostgresContentStore,PostgresLedger
from restricted_runtime.reconciliation import Reconciler
from restricted_runtime.reconciliation_driver import ReconciliationDriver

DATABASE_URL=os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
pytestmark=pytest.mark.skipif(not DATABASE_URL,reason="isolated PostgreSQL database unavailable: set RESTRICTED_RUNTIME_TEST_DATABASE_URL; SQLite/mocks are prohibited")
@pytest.fixture(autouse=True)
def isolated_database():
    with psycopg.connect(DATABASE_URL,autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
        conn.execute(Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8"))
        conn.execute("UPDATE inference_ledger.runtime_controls SET dispatch_enabled=true WHERE control_key=true")
    yield
def turn(*,key=None,conversation="c",epoch="e",state=TurnState.RECEIVED):
    return TurnRow("tenant",conversation,epoch,str(uuid.uuid4()),key or str(uuid.uuid4()),"caller",b"mac","service-key","1","policy",state,b"cipher",b"123456789012",None,None,b"wrapped",0)
def policy():
    values=json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"));values.update(policy_epoch="1",tenant_id="tenant",vertex_project_id="project",vertex_project_number="123",model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    return PolicyBundle(values,hashlib.sha256(jcs_bytes(values)).hexdigest())
def test_same_key_converges_and_one_attempt_dispatches():
    store=PostgresContentStore(DATABASE_URL);candidate=turn(key=str(uuid.uuid4()));barrier=threading.Barrier(2)
    def admit():barrier.wait();return store.admit(candidate)
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:admit(),range(2)))
    assert sum(created for _,created in results)==1 and {row.turn_id for row,_ in results}=={candidate.turn_id}
    with psycopg.connect(DATABASE_URL) as conn:assert conn.execute("SELECT count(*) FROM restricted_content.turns").fetchone()[0]==1
def test_different_key_active_turn_and_reset_are_serialized():
    store=PostgresContentStore(DATABASE_URL);first=turn(key=str(uuid.uuid4()));second=turn(key=str(uuid.uuid4()))
    assert store.admit(first)[1]
    with pytest.raises(ContractError,match="ACTIVE_TURN"):store.admit(second)
    with pytest.raises(ContractError,match="ACTIVE_TURN"):store.reset("tenant","c","e")
    assert store.set_state_cas("tenant",first.turn_id,0,TurnState.RECEIVED,TurnState.FAILED) and store.reset("tenant","c","e")!="e"
def test_commit_readback_conflict_replay_and_stale_lease_cas():
    store=PostgresContentStore(DATABASE_URL);row=turn(key=str(uuid.uuid4()));assert store.admit(row)[1]
    assert store.set_state_cas("tenant",row.turn_id,0,TurnState.RECEIVED,TurnState.RESPONSE_RECEIVED)
    assert store.set_state_cas("tenant",row.turn_id,0,TurnState.RESPONSE_RECEIVED,TurnState.COMMITTED,response_ciphertext=b"response",response_nonce=b"abcdefghijkl",gateway_decision_id="00000000-0000-0000-0000-000000000001",gateway_attempt_classification="SUCCEEDED")
    assert store.read_turn("tenant",row.turn_id).response_ciphertext==b"response"
    existing,created=store.admit(turn(key=row.client_request_id,conversation="other"));assert not created and existing.turn_id==row.turn_id
    lease=turn(key=str(uuid.uuid4()),conversation="lease");store.admit(lease)
    with psycopg.connect(DATABASE_URL,autocommit=True) as conn:conn.execute("UPDATE restricted_content.turns SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE turn_id=%s",(lease.turn_id,))
    assert store.claim_expired_lease("tenant",lease.turn_id,"reconciler")==1 and not store.mark_terminal_cas("tenant",lease.turn_id,0,TurnState.FAILED,"x") and store.mark_terminal_cas("tenant",lease.turn_id,1,TurnState.FAILED,"x")
def test_fence_races_and_fault_boundaries_never_redispatch():
    p=policy();key=LocalHmacKey("gateway-key","1",b"m"*32);ledger=PostgresLedger(DATABASE_URL,p,key);turn_id=str(uuid.uuid4());request_id=str(uuid.uuid4())
    envelope=GatewayEnvelope("tenant","c","e",turn_id,request_id,p.epoch,p.digest,"restricted-phi-system.v1",SYSTEM_INSTRUCTION,"PHI",[{"role":"user","text":"synthetic"}],0)
    record=key.sign(kms_mac_input(GATEWAY_MAC_DOMAIN,envelope.canonical()))
    assert ledger.reserve(envelope,"caller",record.mac,record.key_resource,record.key_version) is AttemptState.RESERVED
    assert ledger.fence("tenant",turn_id) is AttemptState.CANCELLED_NO_DISPATCH and not ledger.start_dispatch("tenant",turn_id)
    tomb_turn=str(uuid.uuid4());tomb_req=str(uuid.uuid4());assert ledger.fence("tenant",tomb_turn,client_request_id=tomb_req,policy_epoch=p.epoch,policy_digest=p.digest) is AttemptState.CANCELLED_NO_DISPATCH
    tomb=GatewayEnvelope("tenant","c","e",tomb_turn,tomb_req,p.epoch,p.digest,"restricted-phi-system.v1",SYSTEM_INSTRUCTION,"PHI",[],0)
    assert ledger.reserve(tomb,"caller",record.mac,record.key_resource,record.key_version) is AttemptState.CANCELLED_NO_DISPATCH

def test_reserve_and_not_found_fence_interleave_on_one_durable_guard():
    """The reserve/fence race converges on one tombstone, never a late dispatch."""
    p=policy();key=LocalHmacKey("gateway-key","1",b"m"*32);turn_id=str(uuid.uuid4());request_id=str(uuid.uuid4())
    envelope=GatewayEnvelope("tenant","c","e",turn_id,request_id,p.epoch,p.digest,"restricted-phi-system.v1",SYSTEM_INSTRUCTION,"PHI",[],p.values["max_canonical_input_utf8_bytes"])
    record=key.sign(kms_mac_input(GATEWAY_MAC_DOMAIN,envelope.canonical()))
    barrier=threading.Barrier(2)
    class RacingLedger(PostgresLedger):
        def reserve(self,*args):
            barrier.wait();return super().reserve(*args)
        def fence(self,*args,**kwargs):
            barrier.wait();return super().fence(*args,**kwargs)
    ledger=RacingLedger(DATABASE_URL,p,key)
    with ThreadPoolExecutor(max_workers=2) as pool:
        reserved,fenced=list(pool.map(lambda op: op(), (
            lambda: ledger.reserve(envelope,"caller",record.mac,record.key_resource,record.key_version),
            lambda: ledger.fence("tenant",turn_id,client_request_id=request_id,policy_epoch=p.epoch,policy_digest=p.digest),
        )))
    assert {reserved,fenced} <= {AttemptState.RESERVED,AttemptState.CANCELLED_NO_DISPATCH}
    assert ledger.status("tenant",turn_id,client_request_id=request_id,policy_epoch=p.epoch,policy_digest=p.digest) is AttemptState.CANCELLED_NO_DISPATCH
    assert not ledger.start_dispatch("tenant",turn_id)

def test_admission_builds_history_only_while_conversation_row_is_locked():
    """A second connection cannot update the admission row while history builds."""
    p=policy();store=PostgresContentStore(DATABASE_URL);blocked=[]
    request_id=str(uuid.uuid4());conversation="locked-conversation";epoch=store.create_conversation("tenant",conversation)
    row=turn(key=request_id,conversation=conversation,epoch=epoch)
    def build(history):
        with psycopg.connect(DATABASE_URL,autocommit=True) as conn:
            try:
                conn.execute("SELECT 1 FROM restricted_content.conversations WHERE tenant_id=%s AND conversation_id=%s FOR UPDATE NOWAIT",("tenant",conversation))
            except psycopg.errors.LockNotAvailable:
                blocked.append(True)
        return row
    admitted,created=store.admit_with_history(tenant_id="tenant",conversation_id=conversation,conversation_epoch=epoch,client_request_id=request_id,build_row=build)
    assert created and admitted.turn_id==row.turn_id and blocked==[True]

def test_db_time_lease_heartbeat_scanner_and_stale_handler_cas():
    p=policy();store=PostgresContentStore(DATABASE_URL);key=LocalHmacKey("gateway-key","1",b"m"*32);ledger=PostgresLedger(DATABASE_URL,p,key)
    candidate=turn(key=str(uuid.uuid4()),conversation="heartbeat")
    assert store.admit(candidate)[1]
    assert store.set_state_cas("tenant",candidate.turn_id,0,TurnState.RECEIVED,TurnState.INFERENCE_PENDING)
    assert store.renew_lease("tenant",candidate.turn_id,0,seconds=30)
    with psycopg.connect(DATABASE_URL,autocommit=True) as conn:
        conn.execute("UPDATE restricted_content.turns SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE tenant_id=%s AND turn_id=%s",("tenant",candidate.turn_id))
    # The scanner and claim use transaction_timestamp(), not replica wall time.
    reconciler=Reconciler(store,Gateway(p,key,ledger,object()))
    assert ReconciliationDriver(store,reconciler,"scanner","1").run_once()==1
    assert store.read_turn("tenant",candidate.turn_id).state is TurnState.FAILED
    assert not store.renew_lease("tenant",candidate.turn_id,0)
    assert not store.set_state_cas("tenant",candidate.turn_id,0,TurnState.INFERENCE_PENDING,TurnState.COMMITTED,response_ciphertext=b"x",response_nonce=b"n"*12,gateway_decision_id="00000000-0000-0000-0000-000000000002",gateway_attempt_classification="SUCCEEDED")
