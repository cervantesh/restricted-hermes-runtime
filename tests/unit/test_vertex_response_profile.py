import json
from pathlib import Path
import pytest
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
    assert result.state=="SUCCEEDED" and result.text=="Synthetic administrative response." and result.provider_request_id=="synthetic-response-2026-08-30"

def test_sanitized_exact_sink_shape_releases_text_but_discards_thought_signature():
    result=parse_vertex_response(200,Path("tests/fixtures/vertex/sanitized_exact_sink_response.json").read_bytes())
    assert result.state=="SUCCEEDED" and result.text=="HRH_RESTRICTED_RUNTIME_OK"
    assert result.provider_request_id=="sanitized-exact-sink-response" and not hasattr(result,"thought_signature")

def test_observed_response_extensions_remain_closed_to_on_demand_and_bounded_base64():
    raw=Path("tests/fixtures/vertex/sanitized_exact_sink_response.json").read_text()
    assert parse_vertex_response(200,raw.replace("ON_DEMAND","BATCH").encode()).state=="INDETERMINATE"
    assert parse_vertex_response(200,raw.replace("c2FuaXRpemVkLXRoaW5raW5nLXNpZ25hdHVyZQ==","not base64!").encode()).state=="INDETERMINATE"


AC16_FIXTURES = [
    ("stop_all_optional.json", "SUCCEEDED"),
    ("prompt_feedback_safety.json", "FAILED"),
    ("prompt_feedback_blocklist.json", "FAILED"),
    ("prompt_feedback_unknown_reason.json", "INDETERMINATE"),
    ("candidate_safety.json", "FAILED"),
    ("candidate_recitation.json", "FAILED"),
    ("max_tokens.json", "INDETERMINATE"),
    ("unknown_finish_reason.json", "INDETERMINATE"),
    ("empty_candidates.json", "INDETERMINATE"),
    ("empty_text.json", "INDETERMINATE"),
    ("malformed_truncated.json", "INDETERMINATE"),
    ("multiple_candidates.json", "INDETERMINATE"),
    ("nonzero_candidate_index.json", "INDETERMINATE"),
    ("multiple_text_parts.json", "INDETERMINATE"),
    ("thought_part.json", "INDETERMINATE"),
    ("tool_part.json", "INDETERMINATE"),
    ("media_part.json", "INDETERMINATE"),
    ("root_unknown_field.json", "INDETERMINATE"),
    ("usage_unknown_field.json", "INDETERMINATE"),
    ("usage_detail_unknown_field.json", "INDETERMINATE"),
    ("candidate_unknown_field.json", "INDETERMINATE"),
    ("rating_unknown_field.json", "INDETERMINATE"),
    ("content_unknown_field.json", "INDETERMINATE"),
    ("part_unknown_field.json", "INDETERMINATE"),
    ("prompt_feedback_unknown_field.json", "INDETERMINATE"),
    ("prompt_feedback_rating_unknown_field.json", "INDETERMINATE"),
    ("duplicate_root_key.json", "INDETERMINATE"),
    ("duplicate_nested_key.json", "INDETERMINATE"),
    ("trailing_json.json", "INDETERMINATE"),
]


@pytest.mark.parametrize(("fixture_name", "expected_state"), AC16_FIXTURES)
def test_response_profile_classifies_all_recorded_fixtures(fixture_name, expected_state):
    raw = (Path("tests/fixtures/vertex/ac16") / fixture_name).read_bytes()
    result = parse_vertex_response(200, raw)
    assert result.state == expected_state
    assert (result.text is not None) is (expected_state == "SUCCEEDED")
    if expected_state != "SUCCEEDED":
        assert result.text is None


@pytest.mark.parametrize(
    ("fixture_name", "raw", "expected_state"),
    [
        ("empty-body", b"", "INDETERMINATE"),
        ("invalid-utf8", b'{"candidates": [\xff]}', "INDETERMINATE"),
    ],
)
def test_response_profile_rejects_non_json_raw_bytes(fixture_name, raw, expected_state):
    result = parse_vertex_response(200, raw)
    assert result.state == expected_state
    assert result.text is None
