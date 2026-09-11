# Bounded candidate source ledger — 2026-09-11

The canonical JSON ledger beside this note binds the bounded source-reconciliation
claim to candidate `ae72b3a73cf8059a9fe30e6c5749ad8ca0a5ccf9` and tree
`2c8e37e59c58d960fd9219fe8f2d4459d7f977c1`.

It verifies that the candidate descends from the declared immutable-base,
lifecycle, delivery-reauthorization, source-frame, recovery, and sealed-Compose
source lines. It also retains SHA-256 bindings for the real synthetic WSL
egress and composed-E2E receipts. Those receipts name their own intermediate
runtime frames, which the verifier requires to be ancestors of the candidate;
they are not relabeled as direct execution at the ledger candidate.

Verification from this checkout:

```text
python tools/reconciled_candidate_ledger.py --verify docs/evidence/reconciled-candidate-ledger-2026-09-11.json
candidate ledger: PASS
```

The ledger intentionally says `false` for published immutable-subject
re-verification, representative-host verification, PHI authorization, and
deployment conformance. It is a source/evidence boundary for issue #35, not an
A0 aggregate, host receipt, or approval artifact.
