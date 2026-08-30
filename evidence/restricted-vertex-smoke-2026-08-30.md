# Synthetic Vertex response-profile fixture

This is a checked-in raw JSON response fixture for the closed response
profile. It is synthetic and non-PHI; it was not sent to Vertex and is not a
real-provider receipt.

Fixture: `tests/fixtures/vertex/synthetic_non_phi_smoke_response.json`

Expected parse: HTTP 200, one candidate at index 0, model role, one non-empty
text part, `STOP` finish reason, and `SUCCEEDED` with the recorded response
identifier.
