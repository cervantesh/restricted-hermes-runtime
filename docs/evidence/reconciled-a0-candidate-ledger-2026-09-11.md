# A0 source-candidate ledger — 2026-09-11

This retained evidence frame binds the prospective A0 code subject to
`6e1b36edbc8d78b7824dc9174170aef2d5a0da3e` and tree
`dccbe9e407308823cd56b4c0b71c1dba646351ac`.

It is deliberately stored in a later evidence commit. The JSON proves the
candidate's required source lines and retained synthetic receipt provenance.
Those historical receipts are explicitly not evidence that this candidate
executed. It does not claim that the JSON existed in the candidate tree, that OCI subjects
were published for it, or that a representative host was exercised.

Verification is run from this retained-evidence checkout:

```text
python tools/reconciled_candidate_ledger.py --verify docs/evidence/reconciled-a0-candidate-ledger-2026-09-11.json
```

Expected result:

```text
candidate ledger: PASS
```

The next eligible operation is a single immutable-candidate workflow run on a
new tag that resolves exactly to `6e1b36e`; the closure card in
`docs/governance/a0-candidate-evaluation-closure.md` defines its required
artifact and nonclaims. This file itself is not an A0 result.
