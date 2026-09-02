# Restricted Mattermost ingress verification

All message data used in this verification was synthetic and explicitly non-PHI.

## Frozen frame

- Contract: `SG-MATTERMOST-001`
- Base: `2f6f116e2818189c436cb51b547cd01bd285f94e`
- Scope: standalone restricted Mattermost edge to the existing `conversation.sock` contract

## TDD witness

Before production code existed, the focused collection failed with:

```text
python -m pytest tests/unit/test_mattermost_ingress.py tests/static/test_mattermost_ingress_surface.py -q
ModuleNotFoundError: No module named 'restricted_runtime.mattermost_ingress'
```

After implementation, the Windows focused suite passed. The POSIX production-entrypoint
suite ran as root in an isolated `python:3.12-slim` container so it could own the exact
`/run/restricted-inference/conversation.sock` path. Its five cases cover the authenticated
round trip and the malformed-WebSocket, authentication-failure, REST-error-body, and UDS-timeout
diagnostic paths. Every process capture was checked for token, input, response, raw-event,
REST-error-body, and root-ID canaries.

The image was built from `Dockerfile.mattermost-ingress`. An import probe succeeded for the
restricted ingress modules and failed closed for `run_agent`, `gateway`, `tools`, `plugins`,
`psycopg`, `fastapi`, and `uvicorn`.

## Directed mutation

Temporarily deleting the allowed-user predicate from `_ordinary` made
`test_prohibited_posts_have_zero_side_effects[<lambda>0]` fail because the unlisted user reached
the conversation client. Restoring the predicate returned the focused suite to green. The
mutation itself is not retained.

## Full-suite context

The repository-wide Windows run completed with `303 passed, 20 skipped, 2 failed`. Both failures
are outside this change: the migration postflight was pointed at a passwordless TCP PostgreSQL
DSN rather than its required private-socket/password fixture, and `test_runtime_wave` expected an
unconfigured conversation root to report ready even though the current production contract
returns 503. The focused Mattermost tests and real POSIX process suite are independent of both.

## Residual boundary

The live-process single-flight proves one inference and one outbound create attempt for concurrent
duplicates and timeout-after-accept ambiguity. Crash-safe exactly-once response delivery is not
claimed. That requires a durable delivery outbox or independently verified server-side idempotency.
Real Mattermost deployment, PHI authorization, HIPAA/BAA conformance, IdP operations, retention,
audit, backups, patching, and network egress enforcement remain operator gates.
