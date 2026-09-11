# Integrated candidate source ledger

The integrated ledger is intentionally empty until all of its named fresh
receipts exist. It binds a candidate revision/tree to explicit source lines and
committed receipt blobs; all runtime receipt heads must be ancestors of that
candidate. The tool rejects altered blobs, source frames, schemas, ancestry,
trees, and claim escalation.

For the currently retained composed witness, a future ledger invocation will
use `docs/evidence/clinical-composed-receipt-2026-09-11-integrated.json` with
schema `restricted-runtime-composed-e2e-receipt.v1`. It must also name a fresh
independent egress witness before representing the candidate as an aggregate
evaluation input.

Example after both fresh receipts exist:

```text
python tools/integrated_candidate_ledger.py --candidate-revision <exact-head> ^
  --required-source-line composed=<receipt-producer-sha> ^
  --receipt clinical-composed=docs/evidence/<receipt>.json,restricted-runtime-composed-e2e-receipt.v1 ^
  --receipt clinical-egress=docs/evidence/<receipt>.json,<egress-schema> ^
  --output docs/evidence/integrated-candidate-ledger-YYYY-MM-DD.json
```

This is source/evidence reconciliation only. It does not attest an immutable
subject, representative host, PHI authorization, deployment conformance, or
an A1 decision.
