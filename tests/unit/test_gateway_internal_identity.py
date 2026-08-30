import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient

from restricted_runtime.auth import SyntheticAuthenticator
from restricted_runtime.contracts import jcs_bytes
from restricted_runtime.crypto import LocalHmacKey
from restricted_runtime.gateway import Gateway
from restricted_runtime.policy import PolicyBundle
from restricted_runtime.services.gateway_api import create_app


class NoLedger: pass


def policy():
    values=json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"))
    values.update(policy_epoch="p1",tenant_id="tenant",vertex_project_id="project",vertex_project_number="123",model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    return PolicyBundle(values,hashlib.sha256(jcs_bytes(values)).hexdigest())


def test_gateway_readiness_requires_the_internal_conversation_identity():
    p=policy();app=create_app(Gateway(p,LocalHmacKey("gateway","1",b"g"*32),NoLedger(),object()),SyntheticAuthenticator("conversation"))
    url=f"/readyz?policy_epoch={p.epoch}&policy_digest={p.digest}"
    assert TestClient(app).get(url).status_code==401
    assert TestClient(app).get(url,headers={"Authorization":"Synthetic test credential"}).status_code==200
