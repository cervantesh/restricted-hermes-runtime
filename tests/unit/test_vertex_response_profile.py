import json
from pathlib import Path
from restricted_runtime.vertex import parse_vertex_response

def payload(reason="STOP", text="answer"):
    return json.dumps({"candidates":[{"content":{"role":"model","parts":[{"text":text}]},"finishReason":reason,"index":0}]}).encode()

def test_only_exact_stop_single_text_is_releasable():
    assert parse_vertex_response(200, payload()).state == "SUCCEEDED"
    assert parse_vertex_response(200, payload("MAX_TOKENS")).state == "INDETERMINATE"
    assert parse_vertex_response(200, payload("SAFETY")).state == "FAILED"
    assert parse_vertex_response(200, b'{"candidates":[]}').state == "INDETERMINATE"
    assert parse_vertex_response(200, b'{"candidates":[{"content":{"role":"model","parts":[{"text":"a"},{"text":"b"}]},"finishReason":"STOP","index":0}]}').state == "INDETERMINATE"

def test_recorded_raw_synthetic_smoke_response_is_parsed_by_production_profile():
    raw=Path("tests/fixtures/vertex/synthetic_non_phi_smoke_response.json").read_bytes()
    result=parse_vertex_response(200,raw)
    assert result.state=="SUCCEEDED" and result.text=="Synthetic administrative response." and result.request_id=="synthetic-response-2026-08-30"
