# Optional Ollama synthetic broker verification record

This is evidence for an opt-in, synthetic-only local deployment edge. It is
not model attestation, deployment conformance, PHI authorization, or a claim
that the host is suitable for sensitive data.

## Fixed inputs

- Source base: `cba99cf5c722ebbe300a3a671019b06586d2df74`.
- Model tag: `qwen2.5:7b` from the pre-existing Windows model store.
- Raw manifest SHA-256:
  `845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e`.
- Required model blob SHA-256:
  `2bada8a7450677000f678be90653b85d364de7db25eb5ea54136ada5f3933730`.
- Pinned amd64 runtime image:
  `ollama/ollama@sha256:9e7d782e99880c70f9563c51633da875ca605518a8f8d95c2532bda70a027b7a`.

## Local checks on 2026-08-31

- A complete SHA-256 pass over the 4,683,073,952-byte required blob took
  **16.043 seconds** on the host store.
- Focused static and unit checks: **13 passed, 1 skipped**. The skipped test
  is the symlink mutation on Windows, where the test account lacks symlink
  privilege; the runtime verifier still uses `lstat`, `O_NOFOLLOW`, and
  identity rechecks.
- The real desktop-Docker Compose witness reached the pinned Ollama service,
  confirmed an NVIDIA GeForce RTX 4070 Laptop GPU, and attempted the required
  synthetic warm-up with a read-only model mount and no Docker network.

## Real-path result: not yet conformant

The real witness did **not** reach `broker.sock`. The initial Qwen load did
not produce HTTP response headers within the closed 35-second per-request
deadline, so the adapter exited fail-closed before binding the socket. The
E2E harness then removed only its uniquely named Compose resources.

This is the intended safe outcome: the contract requires a total request
deadline of at most 35 seconds and prohibits exposing the broker before the
post-warm verification. Increasing that deadline, binding early, or treating
the attempted warm-up as a successful response would be a contract violation.
Consequently the required GPU-backed three-UDS success witness, its <=40-second
post-ready request measurement, durable enable/disable proof, and unchanged
store inventory remain **unproven** on this host.

## Follow-up adjudication

The startup lifecycle now has one absolute 180-second budget, beginning before
the first bundle verification and covering `VERIFY_1`, local readiness, the
single synthetic warm-up, and `VERIFY_2`. Blob hashing checks that same budget
between blocks, and binding checks it again immediately before socket creation.
This budget is intentionally separate from the fixed one-second TCP connect
and 35-second individual Ollama request limits; it does not make a serving
request eligible for 180 seconds.

The RED result above remains historical evidence, not a passing claim. The
fresh real-path witness must still prove the broker appears within the startup
budget and that the subsequent complete three-UDS request is at most 40
seconds. If its two serving-time bundle hashes plus inference do not fit that
40-second bound, the profile remains non-conformant rather than extending or
omitting the check.

A fresh uniquely named real E2E was run after this change. It again saw the
pinned GPU-capable service but the adapter exited before verified warm-up;
cleanup removed the exact project containers and volumes. Thus AC7--AC10's
success-only witnesses remain RED/unproven. This follow-up does not relabel
the earlier result as a pass and does not change any deadline to accommodate
the host.

## Nonclaims

`model_attested=false`; `deployment_conformant=false`; `phi_authorized=false`.
