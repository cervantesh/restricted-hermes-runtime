import hashlib
import json
from pathlib import Path

import pytest

from restricted_runtime.contracts import jcs_bytes
from restricted_runtime.policy import PolicyBundle
from restricted_runtime.policy_binding import require_policy_pair


def test_deployment_policy_pair_mismatch_fails_before_any_runtime_wiring():
    values=json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"));values.update(policy_epoch="A",tenant_id="tenant",vertex_project_id="p",vertex_project_number="1",model_resource="projects/1/locations/us/publishers/google/models/gemini-3.5-flash",generate_content_path="/v1/projects/1/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    bundle=PolicyBundle(values,hashlib.sha256(jcs_bytes(values)).hexdigest())
    with pytest.raises(RuntimeError,match="policy pair"):
        require_policy_pair(bundle,epoch="B",digest=bundle.digest)
    with pytest.raises(RuntimeError,match="policy pair"):
        require_policy_pair(bundle,epoch=bundle.epoch,digest="other")
