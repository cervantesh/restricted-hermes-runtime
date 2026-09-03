# Restricted Mattermost ingress verification

All message data used in this verification was synthetic and explicitly non-PHI.

## Historical initial slice — SG-MATTERMOST-001

This section preserves the original, pre-outbox implementation evidence. Its
suite totals and residual boundary are historical, not a statement of the
current SG-MM-OUTBOX-007 delivery behavior.

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

From a clean checkout, `bash tests/deployment/test_mattermost_ingress_image.sh`
builds `Dockerfile.mattermost-ingress` and runs an import/filesystem closure
probe inside the production role image. It uses the image's Python interpreter,
not a test framework installed in that image: the four allowed Mattermost
modules must import, and every other restricted-runtime module plus normal
Hermes, `fastapi`, `uvicorn`, and `psycopg` must be absent.

The correction suite additionally uses a real-shaped Mattermost post without `file_ids`, proves
whitespace rejection and exact mention punctuation, expires a policy while the process remains
live, observes an abnormal WebSocket closure reconnect, and executes the versioned image probe
inside the built role image. `websockets` is constrained to version 15 because the explicit
`proxy=None` control is part of that API contract.

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

## SG-MM-OUTBOX-007 completion evidence

- Contract: `SG-MM-OUTBOX-007`
- Implementation base: `f9ef9f4518ef217e9382635715760177fb749789`
- Final implementation head: `5dabdacbf8eeca8788835c0fe2c136b2e1a45ff9`
- Scope: encrypted durable local delivery outbox and bounded recovery for the
  restricted Mattermost ingress. The historical SG-MATTERMOST-001 evidence
  above remains preserved as the initial slice.

### TDD and adversarial receipts

- RED cases were captured before each closure, including terminal metadata and
  nonce-registry tampering, readiness-binding bypass, expiry at every
  irreversible boundary, malformed successful REST shapes, crash windows, and
  recovery fairness.
- Process witnesses cover crash windows around durable reservation, inference
  turn, delivery claim, and posting boundaries. A post-claim restart becomes
  `AMBIGUOUS`; it is never retried.
- Installed-wheel directed mutations individually bite for payload encryption,
  durable terminal metadata, nonce reuse/history, readiness binding, source and
  root fences, CAS, stale in-flight handling, and recovery identity.
- Windows focused evidence: `107 passed, 7 skipped`.
- Linux installed-wheel/process causal evidence: `131 passed, 1 skipped`.
- Real PostgreSQL recovery witness: `1 passed`.
- Exact Mattermost `11.7.10` acceptance: `PASS`.
- Hosted CI run `33745519719`: green.

## Current residual and operating boundary

Delivery is duplicate-averse, not exactly-once. The durable outbox is now part
of this implementation; it does not turn a completed Mattermost post into an
exactly-once protocol. `AMBIGUOUS` records are never retried, and the runtime
does not catch up unseen Mattermost events while it was down.

This remains a single-replica design over one protected local state volume.
Operators own capacity sizing, whole-database retirement/reset, key custody and
rotation, and backup/restore. The keyed nonce history and row authentication
detect uncoordinated local deletion or alteration, including a rollback of
nonce history and its authenticated root/sequence to a valid prefix while a
newer outbox row remains. Only a coherent rollback of the whole state volume is
the excluded rollback class without an external monotonic anchor; operators
must not partially restore or edit state.

All verification messages were synthetic and non-PHI. This evidence makes no
claim of production PHI authorization, HIPAA/BAA or other compliance, IdP
operation, retention, audit, backups, patching, or network-egress enforcement;
those remain operator controls.
