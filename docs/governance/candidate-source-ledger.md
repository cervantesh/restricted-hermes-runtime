# Bounded candidate source ledger

## Closure card

This ledger is complete only when it canonically records the exact candidate
revision and tree, the required bounded source lines and trees, and the hashes
of retained real-path synthetic receipts. Verification must prove that every
named source and receipt runtime revision is an ancestor of the candidate.

It fails closed if a Git object, tree, receipt path, receipt hash, receipt
source frame, required source line, or claim differs. It must preserve these
limits: no published-subject re-verification, representative-host receipt,
PHI authorization, or deployment-conformance claim.

## Use

Generate only after all receipt files are present:

```text
python tools/reconciled_candidate_ledger.py --candidate-revision <exact-head> --output docs/evidence/reconciled-candidate-ledger-YYYY-MM-DD.json
```

Verify from a clean checkout of that candidate:

```text
python tools/reconciled_candidate_ledger.py --verify docs/evidence/reconciled-candidate-ledger-YYYY-MM-DD.json
```

The ledger is a bounded source-reconciliation artifact for issue #35. It is
not an immutable OCI-candidate manifest and does not close A0 or the
representative-host gate.
