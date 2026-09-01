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

## Offline staging boundary

Before Compose exists, the harness creates exactly
`<project>_ollama_bundle_845dbda0ea48` with these exact labels:
`restricted-runtime.synthetic-only=true`,
`restricted-runtime.project=<project>`,
`restricted-runtime.manifest-sha256=845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e`,
and `restricted-runtime.managed-bundle=true`.

The pinned, networkless staging helper sees only the Windows source read-only
and this fresh destination volume read-write. It copies only the exact raw
manifest and its referenced blobs, re-verifies source and destination, and
then Compose mounts only the staged volume read-only. The Windows source is
never a runtime mount and cleanup validates the exact name and labels before
removing only the staging volume.

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
The pre-bind readiness and one warm-up request consume the remaining startup
budget while retaining a one-second TCP connect. Only requests after `READY`
use the separate 35-second serving deadline; a serving request never receives
the 180-second startup budget.

The RED result above remains historical evidence, not a passing claim. The
fresh real-path witness must still prove the broker appears within the startup
budget and that the subsequent complete three-UDS request is at most 40
seconds. If its two serving-time bundle hashes plus inference do not fit that
40-second bound, the profile remains non-conformant rather than extending or
omitting the check.

A fresh uniquely named real E2E was run after this change. The pinned
GPU-capable service started, and the pre-bind warm request consumed the
remaining absolute startup budget rather than the serving budget, but it still
did not emit headers before the 180-second startup deadline. The adapter exited
before `broker.sock`; cleanup removed the exact project containers and volumes.
Thus AC7--AC10's success-only witnesses remain RED/unproven. This follow-up
does not relabel the earlier result as a pass and does not change any deadline
to accommodate the host.

## Latest fresh witness: `olle2e6` remains RED

The later `olle2e6` run did reach the stricter preconditions that the earlier
attempts did not: the staged bundle was accepted, the adapter bound
`broker.sock` after its one synthetic warm-up, the GPU-backed Ollama service
was live, and the normal PostgreSQL/gateway/conversation services became
healthy. Its first external synthetic call through the conversation UDS then
returned `400 {"detail":"restricted turn rejected"}`. This is a failed real
three-UDS witness, not a successful inference result.

The harness preserved the bounded Compose diagnostics outside the deleted
runtime directory at `C:\\Temp\\olle2e6.ollama-failure-logs`. They show the
conversation create was accepted, `/infer` reached the gateway, and the turn
was rejected; the closed adapter intentionally does not emit a reason that
could expose request content. Consequently these facts remain **unproven**:

- a semantically successful three-UDS Qwen response within 40 seconds;
- post-ready response-path attribution (including whether the two required
  serving-time bundle verifications fit the caller's 40-second deadline);
- the requested post-success `dispatch_enabled=false` readback; and
- equality of the source-store inventory after a successful full witness.

No timeout was enlarged and no verification step was removed to convert this
RED result into a pass. The exact test project had no remaining Compose
containers or named volumes after its cleanup.

`olle2e9` then closed the remaining attribution gap without changing the
deadline: `local_gateway_failure=timeout` was emitted before the conversation
boundary recorded `turn_rejected_reason=inference_outcome_indeterminate`.
The gateway completed its `/infer` after that caller had already timed out.
The local gateway client has a closed 40-second total deadline, so this is a
real proof that the post-ready path did not fit the required request budget on
this host. The saved diagnostic is
`C:\\Temp\\olle2e9.ollama-failure-logs`; it contains only closed reason labels
and no prompt text. This profile is therefore non-conformant for the demanded
success witness. The proper disposition is to keep it RED rather than enlarge
the request deadline, omit serving-time verification, or claim a partial pass.

## Nonclaims

`model_attested=false`; `deployment_conformant=false`; `phi_authorized=false`.

## Narrowed post-ready contract

This is a declared contract correction, not an equivalent optimization. Full
cryptographic manifest/blob verification remains source-and-destination staging
and adapter `VERIFY_1 -> warm -> VERIFY_2`, all before `broker.sock` exists.
After readiness the adapter retains nofollow file descriptors and compares the
canonical allowlist plus file/directory device, inode, mode, owner, link count,
size, mtime, and ctime before and after each request. It does not continuously
hash the model bytes after READY. Namespace or retained-FD drift closes and
unlinks the broker without releasing text or continuing to serve.

This narrower guarantee trusts the host and Docker administrator and is not
continuous model-byte attestation. It is intended to preserve the 35-second
internal and 40-second three-UDS request contracts while retaining a fail-stop
identity guard over the staged read-only namespace.

## Fresh narrowed-contract witness: `olle2e10` GREEN

The fresh unique-project witness completed with no failure-log directory. Its
assertions covered the pinned GPU-backed Ollama process, adapter startup,
semantic synthetic response through all three UDS boundaries within the
closed request limits, durable dispatch disable readback, and exact project
cleanup. The Windows source store is not mounted into runtime and is outside
the product control boundary; the authoritative claim is the exact referenced
bundle copied and verified during isolated staging, not a hash of unrelated
source-store files. The probe and staging images, Compose
containers, and uniquely named volumes were absent after completion. This is
evidence only for the narrowed identity-guard contract above; the nonclaims
remain unchanged.
