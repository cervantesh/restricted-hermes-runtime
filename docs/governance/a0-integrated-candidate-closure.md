# A0 integrated candidate — closure card

## Purpose

This cut prepares one source subject that includes the current P2 host-admission
line and the bounded candidate-ledger controls. It replaces neither a hosted
immutable-candidate run nor representative-host evaluation. In particular, it
does **not** authorize tagging or publishing an OCI candidate.

## Admission boundary

The integration starts from P2 subject
`4fb3ef85f683ede64600e3e4ba6bce904e223349`. It may selectively replay only
the pytest source-provenance control from
`cervantesh/fix-test-source-provenance`. The historical ledger implementation
is not replayed: it names receipts and source lines that do not belong to the
P2 ancestry. A fresh integrated ledger is created only after new receipts.

It must not merge the old candidate branch wholesale. A dry-run merge reports
add/add conflicts in the immutable workflow, staging composition, E2E harness,
and manifest validators; choosing either side mechanically would discard
independent hardening.

## Required outcome

1. The resulting source tree contains the P2 host-admission implementation
   unchanged except for an intentional, reviewed CI ancestry setting if the
   ledger verifier requires it.
2. The source-provenance test executes against the integrated checkout, not an
   editable sibling installation. A new ledger verifier accepts no implicit
   historical candidate or receipt.
3. A new source ledger is generated from the integrated revision in a later
   retained-evidence commit. Its receipts are read and hashed from that named
   candidate's committed Git blobs, remain historical provenance, and cannot
   be used as proof that the integrated candidate itself executed.
4. The historical `49dca06` candidate is not relabeled as the integrated
   candidate; its incompatible ledger artifacts are absent from this tree.
5. Targeted ledger, P2 admission, recovery, and E2E controls are green on the
   exact integrated SHA. Hosted CI must be green before a tag is considered.

## Negative controls

- A full branch merge must remain rejected by its recorded add/add conflicts.
- Disabling pytest's `pythonpath` while supplying a sibling checkout must make
  the source-provenance test fail.
- Changed source/tree, altered committed receipt bytes, missing ancestry, and
  mutable or unpinned OCI references must be rejected by their respective
  verifiers.

## Nonclaims

This card creates no images, host receipt, external-service qualification,
PHI authorization, HIPAA/BAA determination, or A1 pilot decision.
