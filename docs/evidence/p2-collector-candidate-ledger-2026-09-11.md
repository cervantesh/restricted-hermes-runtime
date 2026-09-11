# P2-collector source-candidate ledger — 2026-09-11

This retained evidence frame binds the next prospective A0 and P2 code subject
to `3da46f930cc560e83328eadad44bc2127f772f53` and tree
`f501f90f2b8bfe7dc5902dbea92f0e159bd70230`.

It extends the earlier source-only ledger only to include the candidate-bound
egress collector. The JSON proves required source-line ancestry and retains
the prior synthetic receipts strictly as historical provenance. It does not
claim that those receipts executed this subject, that OCI subjects were
published for it, that a representative host was exercised, or that A0 is
complete.

Verification is run from this retained-evidence checkout:

```text
python tools/reconciled_candidate_ledger.py --verify docs/evidence/p2-collector-candidate-ledger-2026-09-11.json
```

Expected result:

```text
candidate ledger: PASS
```

The next eligible operation is an immutable-candidate workflow run on a new,
exact tag resolving to `3da46f9`. Creating that public tag or published image
subjects is intentionally outside this source-ledger cut.
