# Synthetic Vertex response-profile smoke receipt

This is a real synthetic non-PHI provider smoke receipt from 2026-08-30. It
does not authorize PHI processing or establish a deployed/registry image.

- sink: `projects/350094423396/locations/us/publishers/google/models/gemini-3.5-flash`
- host: `aiplatform.us.rep.googleapis.com`
- HTTP status: `200`
- dispatch count: `1`
- elapsed: `3219ms`
- state: `SUCCEEDED`
- sanitized text: `HRH_RESTRICTED_RUNTIME_OK`
- provider request ID: `8G-UasvzJOC00ekPlfiWkA0`
- observed policy digest/epoch: `faf98336bfe94b460a903662cb841e991682788ade1ad3a244348f22bb907687` / `synthetic-smoke-2026-08-30-final-r2`

The response satisfied the amended closed profile: one candidate with the
required model content and `STOP`, omitted candidate index, one non-empty text
part, `thoughtSignature` present (value omitted), and
`usageMetadata.trafficType=ON_DEMAND`. No raw `thoughtSignature` is recorded.

Six synthetic no-PHI diagnostic/smoke requests were audited in total; each
product client allowed at most one dispatch and no retry. Earlier diagnostics
needed correction because the collector used `.status` incorrectly and omitted
real response fields, including the optional candidate index. The final audit
confirmed provider success.

The checked-in fixture at
`tests/fixtures/vertex/synthetic_non_phi_smoke_response.json` remains a
sanitized parser fixture, not a substitute for this provider receipt. No
email, caller IP, account identity, authorization material, or raw signature is
included.
