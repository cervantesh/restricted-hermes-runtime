# Integrated ledger provenance repair closure

## Risk reduced

An integrated candidate ledger must not convert an ancestor receipt into proof
that the exact candidate executed. Its writer must also never replace an
output that appears after an existence check. Either defect can make a
content-safe evidence record overclaim or destroy a concurrent record.

## Scope

- Mark retained receipts as historical provenance rather than candidate-run
  evidence.
- Preserve ancestry checks for declared control lines only.
- Replace check-then-replace receipt output with an atomic create-if-absent
  writer.

## Closure predicates

1. The ledger refuses a claim that historical receipts prove candidate
   execution.
2. Receipt bytes, schema and closed source frame remain verified; control-line
   ancestry remains required.
3. A pre-existing or concurrently-created output is never overwritten.
4. Focused unit tests and exact-head CI pass.

## Nonclaims

This is evidence-integrity repair only. It does not run A0, create immutable
images, qualify a host, or authorize PHI, a pilot, or deployment.
