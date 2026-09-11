# Integrated candidate ledger reset — closure card

## Scope

The imported ledger was a verifier for the historical `49dca06` candidate. It
hard-coded historical receipts and source lines that are not ancestors of the
P2 integration line, so it cannot truthfully verify the integrated candidate.
This cut removes that incompatible evidence frame and replaces it with a
generic, explicit-input ledger contract for newly produced receipts only.

## Closure contract

1. No historical candidate ledger or test is presented as valid in the P2
   integration tree.
2. A v2 ledger records explicit required source lines and receipt descriptors;
   it verifies candidate/source ancestry, exact candidate and source trees,
   committed Git-blob receipt hashes, receipt schema, and the receipt source
   frame.
3. A receipt source's runtime revision must be an ancestor of the candidate;
   external-source identifiers are shape-validated but not falsely tested as
   commits in this repository.
4. A ledger cannot be generated until every named receipt exists in the
   retained evidence frame. It writes only a new target.
5. The current integrated composed receipt can be used as one future input,
   but no aggregate A0 ledger is emitted until the independent egress receipt
   and its controls are fresh on this source line.

## Negative controls

- Changed candidate tree, missing ancestry, altered committed receipt bytes,
  altered receipt schema/source, duplicated descriptors, and escalated claims
  are rejected.
- Historical `49dca06` paths are not accepted as an implicit default.

## Nonclaims

This is an evidence-integrity mechanism. It does not create an aggregate A0
result, an immutable subject, host conformance, PHI authorization, or an A1
pilot decision.
