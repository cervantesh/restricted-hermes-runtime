# Candidate-ledger stack reconciliation closure

## Risk reduced

A retained receipt records the exact historical source that executed it.  Once
the active candidate is rebased to absorb a repaired upstream evidence layer,
that historical commit may no longer be a Git ancestor even though the receipt
remains valid historical evidence.  Treating it as candidate evidence would
silently overstate A0 readiness; rejecting it without distinction would erase
useful, bounded provenance.

## Scope

- Rebase the ledger on the repaired egress-v2 and composed-receipt layers.
- Separate immutable historical receipt verification from ancestry required of
  the active candidate's control lines.
- Regenerate content-safe ledgers and the A0 closure card for the exact
  post-reconciliation source subject.

## Closure predicates

1. Every retained receipt verifies only against its recorded source/tree,
   schema and committed bytes.
2. Only named control lines—not historical receipt runs—are required to be
   ancestors of the active candidate.
3. The ledger explicitly marks retained receipts historical and cannot claim
   candidate, host, PHI, deployment, or A1 success from them.
4. Tampered historical source, receipt bytes, schema, source-line ancestry,
   or elevated claim is rejected.
5. Focused tests and exact-head CI pass on the reconciled stack.

## Nonclaims

This preserves provenance across a necessary evidence-contract repair.  It
does not refresh either real run, create an immutable candidate artifact,
establish representative-host conformance, or authorize a pilot.
