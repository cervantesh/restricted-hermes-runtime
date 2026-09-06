"""Real PostgreSQL proof that local sink mutations conflict before dispatch."""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

import psycopg
import pytest

from restricted_runtime.contracts import ContractError, jcs_bytes
from restricted_runtime.crypto import GATEWAY_MAC_DOMAIN, LocalHmacKey, kms_mac_input
from restricted_runtime.gateway import GatewayEnvelope
from restricted_runtime.policy import LOCAL_POLICY_SCHEMA, PolicyBundle, SYSTEM_INSTRUCTION
from restricted_runtime.storage import PostgresLedger


DATABASE_URL = os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="isolated PostgreSQL database unavailable: set RESTRICTED_RUNTIME_TEST_DATABASE_URL; SQLite/mocks are prohibited")


@pytest.fixture(autouse=True)
def isolated_database():
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
        conn.execute(Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8"))
        conn.execute("UPDATE inference_ledger.runtime_controls SET dispatch_enabled=true WHERE control_key=true")


def policy(socket_path: str = "/run/restricted-inference/broker.sock") -> PolicyBundle:
    values = {"schema_version":LOCAL_POLICY_SCHEMA,"policy_epoch":"e1","system_instruction_version":"restricted-phi-system.v1","system_instruction_sha256":"afcf847cd029409e53bbcb07e92b9d407876e3190e9cf951844829cb34599c1b","authorization_status":"operator-authorization-required","external_runner_principal":"runner","gateway_invoker_principal":"gateway","tenant_id":"tenant","classification":"PHI","provider":"local-uds","socket_path":socket_path,"method":"restrictedGenerate","model":"operator-model","model_sha256":"a"*64,"response_profile":"restricted-local-text-response.v1","streaming":False,"fallbacks":[],"max_provider_attempts":1,"allowed_modalities":["text"],"tools_allowed":False,"candidate_count":1,"max_output_tokens":4096,"max_canonical_input_utf8_bytes":131072}
    return PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest())


def test_local_sink_tuple_is_durable_and_socket_mutation_conflicts_before_dispatch():
    original = policy(); key = LocalHmacKey("gateway", "1", b"g" * 32); ledger = PostgresLedger(DATABASE_URL, original, key)
    turn, request = str(uuid.uuid4()), str(uuid.uuid4())
    envelope = GatewayEnvelope("tenant", "conversation", "epoch", turn, request, original.epoch, original.digest, "restricted-phi-system.v1", SYSTEM_INSTRUCTION, "PHI", [{"role":"user","text":"synthetic"}], 131072, authenticated_external_principal="runner")
    mac = key.sign(kms_mac_input(GATEWAY_MAC_DOMAIN, envelope.canonical()))
    assert ledger.reserve(envelope, "gateway", mac.mac, mac.key_resource, mac.key_version).value == "RESERVED"
    changed = policy("/run/restricted-inference/other.sock")
    changed_envelope = GatewayEnvelope("tenant", "conversation", "epoch", turn, request, changed.epoch, changed.digest, "restricted-phi-system.v1", SYSTEM_INSTRUCTION, "PHI", [{"role":"user","text":"synthetic"}], 131072, authenticated_external_principal="runner")
    changed_mac = key.sign(kms_mac_input(GATEWAY_MAC_DOMAIN, changed_envelope.canonical()))
    with pytest.raises(ContractError, match="conflict"):
        PostgresLedger(DATABASE_URL, changed, key).reserve(changed_envelope, "gateway", changed_mac.mac, changed_mac.key_resource, changed_mac.key_version)
