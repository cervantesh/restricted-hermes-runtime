"""Real PostgreSQL composition: service -> gateway -> counted provider -> encrypted readback."""
import hashlib,json,os,uuid
from pathlib import Path
import psycopg,pytest
from restricted_runtime.contracts import ProviderResult,TurnRequest,jcs_bytes
from restricted_runtime.conversation import ConversationService
from restricted_runtime.crypto import LocalHmacKey
from restricted_runtime.gateway import Gateway
from restricted_runtime.policy import PolicyBundle
from restricted_runtime.storage import PostgresContentStore,PostgresLedger

URL=os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
pytestmark=pytest.mark.skipif(not URL,reason="requires isolated PostgreSQL")
@pytest.fixture(autouse=True)
def migrated():
    with psycopg.connect(URL,autocommit=True) as c:
        c.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
        c.execute(Path("migrations/001_restricted_runtime.sql").read_text())
def policy():
    v=json.loads(Path("policy/policy.template.json").read_text());v.update(policy_epoch="1",caller_principal="caller",tenant_id="tenant",vertex_project_id="p",vertex_project_number="123",model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    return PolicyBundle(v,hashlib.sha256(jcs_bytes(v)).hexdigest())
class Keys:
    def wrap(self,k):return k
    def unwrap(self,k):return k
class CountedProvider:
    def __init__(self):self.calls=0
    def generate_content(self,messages):self.calls+=1;return ProviderResult("SUCCEEDED",text="synthetic committed")
def req():return TurnRequest.parse({"schema_version":"restricted-turn.v1","client_request_id":str(uuid.uuid4()),"conversation_epoch":"epoch","message":"synthetic"})
def test_real_composition_admits_dispatches_commits_reads_once_and_duplicate_is_read_only():
    p=policy();mac=LocalHmacKey("gateway","1",b"g"*32);provider=CountedProvider();gateway=Gateway(p,mac,PostgresLedger(URL,p,mac),provider)
    service=ConversationService(PostgresContentStore(URL),gateway,LocalHmacKey("service","1",b"s"*32),Keys(),p,"tenant")
    turn=req(); first=service.submit(turn,principal="caller",conversation_id="conversation")
    second=service.submit(turn,principal="caller",conversation_id="conversation")
    assert first["status"]==second["status"]=="COMMITTED" and first["message"]==second["message"]=="synthetic committed" and provider.calls==1
    with psycopg.connect(URL) as c:
        assert c.execute("SELECT count(*) FROM restricted_content.turns").fetchone()[0]==1
        assert c.execute("SELECT state FROM inference_ledger.attempts").fetchone()[0]=="SUCCEEDED"
        row=c.execute("SELECT policy_epoch,policy_digest,gateway_decision_id,gateway_attempt_classification FROM restricted_content.turns").fetchone()
        assert row[0]==p.epoch and row[1]==p.digest and row[2] is not None and row[3]=="SUCCEEDED"
