# Bounded candidate source ledger — 2026-09-11

The canonical JSON ledger beside this note binds the bounded source-reconciliation
claim to candidate `4b8d72481bbb7aa533b90fff0de6cf2d890c9e9e` and tree
`e449d04f84f75d94141ab06747296f77708d83e2`.

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
