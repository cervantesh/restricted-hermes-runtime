# Composed receipt review repair closure

## Risk reduced

The public composed-E2E receipt must remain a closed and faithful projection of
the observed synthetic run. A verifier must not accept an extra source field,
coerce `int` aliases into claimed booleans, or share mutable expectation
objects with a caller.

## Scope

- Close the serialized `source` object during verification while retaining the
  broader live evidence input accepted by the builder.
- Apply type-strict comparison to the source-deletion fields.
- Copy every expectation inserted into a returned receipt.

## Closure predicates

1. Builder and verifier reject extra serialized source fields and every
   boolean/integer alias in source-deletion evidence.
2. Mutating a returned receipt cannot mutate module expectations or alter a
   later build.
3. The retained real-run receipt remains canonical and verifies against its
   recorded subjects.

## Nonclaims

This is receipt-integrity repair only. It neither reruns the composed E2E nor
claims representative-host, PHI, compliance, or production readiness.
