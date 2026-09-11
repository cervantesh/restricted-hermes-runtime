# Egress receipt v2 stack reconciliation closure

## Risk reduced

The composed-receipt and candidate-ledger layers must not retain or validate a
superseded egress receipt after the egress witness contract changes.  A stack
that mixes the repaired v2 witness with v1 subject/schema assumptions can make
its evidence look internally coherent while referring to an obsolete control.

## Scope

- Rebase the composed-receipt layer on the exact repaired egress witness head.
- Replace every v1 egress receipt/schema expectation in downstream evidence
  consumers with the v2 receipt and its exact content-safe frame.
- Preserve the composed receipt's existing closed-schema and source-deletion
  guarantees.

## Closure predicates

1. The composed layer is a descendant of the repaired egress witness head.
2. Its retained egress receipt is the v2 file and verifier accepts it only at
   the recorded source/tree frame.
3. Unit and static tests prove that a v1 egress receipt cannot satisfy the v2
   consumer expectation.
4. The exact rebased head passes the focused receipt suite and hosted CI.

## Nonclaims

This reconciles evidence lineage only.  It does not rerun the composed E2E,
establish representative-host conformance, qualify an external service, or
authorize PHI, HIPAA/BAA, production use, or A1.
