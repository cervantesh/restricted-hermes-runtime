# Bounded candidate source ledger

## Closure card

This ledger is complete only when it canonically records the exact candidate
revision and tree, the required bounded source lines and trees, and the hashes
and closed recorded source frames of retained real-path synthetic receipts.
Verification must prove that every named control line is an ancestor of the
candidate. Receipts remain historical execution records: their bytes, schema,
and recorded source frame are closed, but they are never relabeled as an
execution of a rebased candidate.

It fails closed if a candidate Git object/tree, required source line, receipt
path/hash/schema/source frame, or claim differs. It must preserve these
limits: retained historical receipts are not candidate-execution evidence, and
there is no published-subject re-verification, representative-host receipt,
PHI authorization, or deployment-conformance claim.

## Use

Generate only after all receipt files are present:

```text
python tools/reconciled_candidate_ledger.py --candidate-revision <exact-head> --output docs/evidence/reconciled-candidate-ledger-YYYY-MM-DD.json
```

Verify from a clean retained-evidence checkout that contains the ledger and
the candidate's Git objects:

```text
python tools/reconciled_candidate_ledger.py --verify docs/evidence/reconciled-candidate-ledger-YYYY-MM-DD.json
```

The ledger is retained *after* the code subject it describes. It proves that
the named candidate's Git objects and ancestors are exact; it does not imply
that the evidence file existed in that candidate's source tree. A later
evidence-frame checkout is therefore required for verification. This prevents
a self-referential tree claim while still making the candidate relation
reproducible.

Receipt hashes are SHA-256 values over the committed Git blob bytes, not the
platform-specific working-tree bytes. This keeps the evidence invariant under
Windows CRLF checkout conversion while still rejecting a changed committed
receipt.

The ledger is a bounded source-reconciliation artifact for issue #35. It is
not an immutable OCI-candidate manifest and does not close A0 or the
representative-host gate.
