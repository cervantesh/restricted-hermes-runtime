# P2 admission candidate-subject closure

## Risk reduced

The prior A0 subject included the candidate-bound egress collector but
predated the host and local-Docker admission guard. Tagging that older revision
would allow a valid-looking A0 artifact whose later P2 execution path did not
contain the guard that prevents collection from an unsupported host or remote
Docker endpoint.

## Scope

- Retain a new source ledger for revision `70217864aefc473759c739448831a8203ae81ded`
  and tree `73d10d5a90197a6e4984cc6b83e0a97f480e3869`.
- Require the ledger to prove the existing control-line ancestry and immutable
  historical-receipt bytes.
- Update the A0 closure card to name only that source subject.
- Prove each retained P2 candidate ledger derives its subject from the parent
  of the commit that introduced that particular ledger, so later stacked commits
  cannot silently rewrite its subject.

## Closure predicates

1. The new ledger verifies from the retained evidence frame.
2. Its candidate is exactly the parent source frame containing the P2 admission
   control, rather than the former collector-only source.
3. The A0 card's revision, tree, and tag suffix agree with the new ledger.
4. Tampered source-line ancestry, receipt bytes, source tree, or elevated claims
   remains rejected by the ledger verifier.
5. Focused tests and exact-head CI pass.

## Nonclaims

This only selects the next admissible source for a future immutable A0 tag. It
does not create that tag, publish images, run a representative host, produce a
P2 receipt, establish A0/A1, or make a PHI, authorization, or compliance claim.
