# A0 source-candidate ledger — 2026-09-11

This retained evidence frame binds the prospective A0 code subject to
`49dca06b7a2e2b8134e2c4e426112e55fa73d0c3` and tree
`5e0708c609621b8930aac03a57ac47f9f453ce0f`.

It is deliberately stored in a later evidence commit. The JSON proves the
candidate's required source lines and retained synthetic receipt ancestry; it
does not claim that the JSON existed in the candidate tree, that OCI subjects
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
new tag that resolves exactly to `49dca06`; the closure card in
`docs/governance/a0-candidate-evaluation-closure.md` defines its required
artifact and nonclaims. This file itself is not an A0 result.
