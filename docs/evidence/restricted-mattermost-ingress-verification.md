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
- Evidence baseline head: `b5258f48d58784d3fe9537f2d4725d04a60b62bc`
- Final product-code evidence head: `330f96f964ce331fe053b9730b26e6c4ec576a86`.
  This documentation-only follow-up is deliberately distinct from that tested
  product head and changes no runtime or test code.
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
- The owner connection acquires SQLite exclusive locking before its first
  integrity read and retains it for the process lifetime. A concurrent second
  process attempting deletion during recovery readiness is rejected; the
  normal owner still completes its one turn and delivery.
- Installed-wheel directed mutations individually bite for payload encryption,
  durable terminal metadata, nonce reuse/history, readiness binding, source and
  root fences, CAS, stale in-flight handling, and recovery identity.
- Per-record authenticated transition history is append-only and bound one-for-one
  to nonce history. RED and installed-wheel mutations cover restoring an older
  authentic `READY` row after `DELIVERED`, and deleting an older terminal row
  while a newer terminal row remains.
- Earlier focused closure evidence: Windows `107 passed, 7 skipped`.
- Earlier Linux installed-wheel/process causal evidence: `131 passed, 1 skipped`.
- Prior exclusive-owner closure: Windows focused `103 passed, 4 skipped`;
  Linux installed wheel `123 passed, 1 skipped` (the skipped witness requires
  isolated PostgreSQL and POSIX AF_UNIX).
- Final product-head startup acquisition closure: a write-capable `BEGIN EXCLUSIVE` now precedes
  the first integrity, schema, nonce-history, and row-authentication read. The
  Windows race witness schedules a raw SQLite deletion at that exact first
  integrity read and observes it blocked; the installed-wheel mutation to
  `BEGIN DEFERRED` instead corrupts the row and makes startup reject it. This
  focused collection passed on Windows with `119 passed, 7 skipped` and in a
  Python 3.12 Linux installed wheel with `125 passed, 1 skipped` (the skipped
  witness requires isolated PostgreSQL and POSIX AF_UNIX).
- Real PostgreSQL recovery witness: `1 passed`.
- Exact Mattermost `11.7.10` acceptance: `PASS`.
- Historical hosted CI run `33745519719`: green.
- Hosted CI run `33755084881` on final product-code evidence head
  `330f96f964ce331fe053b9730b26e6c4ec576a86`: green.

## Current residual and operating boundary

Delivery is duplicate-averse, not exactly-once. The durable outbox is now part
of this implementation; it does not turn a completed Mattermost post into an
exactly-once protocol. `AMBIGUOUS` records are never retried, and the runtime
does not catch up unseen Mattermost events while it was down.

This remains a single-replica design over one protected local state volume;
the live owner holds SQLite exclusive locking, so a second process cannot open
or write the outbox until that owner exits.
Operators own capacity sizing, whole-database retirement/reset, key custody and
rotation, and backup/restore. The keyed nonce history, per-record transition
history, and row authentication detect uncoordinated local deletion or
alteration, including a rollback of nonce history and its authenticated
root/sequence to a valid prefix while a newer outbox row remains, restoration
of an older authenticated record state, or deletion of a terminal record.
Only a coherent rollback of the whole state volume is the excluded rollback
class without an external monotonic anchor; operators must not partially
restore or edit state.

All verification messages were synthetic and non-PHI. This evidence makes no
claim of production PHI authorization, HIPAA/BAA or other compliance, IdP
operation, retention, audit, backups, patching, or network-egress enforcement;
those remain operator controls.
