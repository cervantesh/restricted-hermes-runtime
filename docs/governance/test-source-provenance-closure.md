# Test source provenance — closure card

## Scope

This small test-infrastructure cut makes a local `python -m pytest` run from
any repository worktree import `restricted_runtime` from that worktree's
`src/` directory. It prevents an editable installation from a sibling checkout
from silently supplying the code under test.

## Closure contract

1. Pytest prepends the current checkout's `src/` directory before importing
   test modules.
2. A unit control resolves `restricted_runtime.__file__` and accepts it only
   when it is contained by the current checkout's `src/` directory.
3. The ordinary unit and integration commands continue to execute without a
   caller-supplied `PYTHONPATH`.

## Negative control

Before this cut, running pytest from a worktree while a sibling checkout was
installed editable could import that sibling's package. The new control would
observe an out-of-tree module path and fail. It is intentionally a provenance
check, not a claim about production packaging or deployment isolation.

## Nonclaims

This only makes local test evidence attributable to the current checkout. It
does not replace clean-environment tests, hosted CI, image tests, supply-chain
attestation, representative-host conformance, or any PHI/compliance decision.
