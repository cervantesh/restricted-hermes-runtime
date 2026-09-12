# A0 immutable-tag preflight closure

## Risk reduced

The A0 tag is the first irreversible publication action. A locally green
candidate is insufficient if the requested tag could resolve to a different
commit, reuse an existing name, or omit the immutable-candidate workflow at
the selected source. Any of those failures would make a later workflow run
ambiguous rather than an A0 evaluation of the declared subject.

## Scope

- Validate one caller-supplied candidate revision and tree from Git objects.
- Require a unique `immutable-candidate-YYYY-MM-DD-<shortsha>` tag name whose
  suffix agrees with that revision.
- Require the selected source to contain the workflow, both subject Dockerfiles,
  and the closed-subject verifier needed by the A0 card.
- Query only the named remote for an already-published tag ref.
- Emit an atomic, canonical, content-safe preflight receipt only after every
  check passes.

## Closure predicates

1. A changed revision or tree is denied before an output receipt is created.
2. A malformed/mismatched tag or an existing remote tag is denied before output.
3. A source missing an A0 workflow prerequisite is denied before output.
4. A passing receipt binds only the revision, tree, tag, remote alias, and
   closed preflight booleans; it contains no credentials, URL, command output,
   image digest, host, PHI, authorization, or compliance claim.
5. Focused real-Git tests exercise the absent-tag and existing-tag controls.

## Nonclaims

This preflight never creates, moves, deletes, or pushes a tag. It does not
publish images, invoke the immutable workflow, establish A0/P2/A1, or make a
PHI, authorization, or compliance claim.
