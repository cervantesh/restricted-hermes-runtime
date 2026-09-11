# Composed E2E retained receipt — closure card

## Scope

This cut permits the already content-scanned composed E2E to retain one
canonical, source-bound synthetic receipt below `docs/evidence/`. The default
run remains ephemeral. Retention is explicit and cannot write elsewhere in
the checkout.

## Closure contract

1. Only an explicit `--receipt-output` request can retain a receipt.
2. The output is a new regular path directly below `docs/evidence/`; an
   existing path, a path outside that directory, or a nested/unresolved path is
   rejected.
3. The retained bytes are canonical JSON plus one LF and are written through a
   new temporary file followed by replacement.
4. The receipt contains the exact runtime and HRH source frame and the same
   content-free evidence that passed the in-process canary scan.
5. No child stdout/stderr, seed, token, credential, private path, or synthetic
   clinical identifier is retained.

## Negative controls

- Default invocation leaves no receipt in the checkout.
- An outside or pre-existing target is rejected before writing bytes.
- A known secret canary in the evidence remains rejected before retention.

## Nonclaims

The receipt is a synthetic Linux-container witness. It is neither a
published-subject receipt nor representative-host proof, PHI authorization,
compliance certification, or an A1 pilot decision.
