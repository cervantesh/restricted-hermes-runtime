# Clinical staff next-appointment verification

## Evidence frame

- Base: `3c185717f82b4ec2fba0a635679e816ba269717c`
- Platform: Windows, Python 3.11
- Data: synthetic identifiers and appointment values only
- Scope: restricted-runtime Mattermost edge and the dedicated clinical
  UDS-to-HRH adapter implementation; no live HRH, Mattermost, PHI, or medical
  workflow was exercised.

## TDD witness

Before implementation, the new focused suite stopped at the closed policy
boundary:

```text
12 failed, 1 passed
ContractError: Mattermost ingress policy schema is closed
```

After implementation, the focused clinical, existing ingress/outbox, and
static surface gate completed:

```text
129 passed, 4 skipped
```

The defender amendment began with two additional RED witnesses: the runtime
suite failed collection because `_clinical_response_digest` did not exist, and
the adapter suite failed collection because `restricted_runtime.clinical_adapter`
did not exist. After the amendment, the runtime/adapter focused suite completed:

```text
80 passed, 6 skipped
```

The full unit and static corpus then completed:

```text
370 passed, 17 skipped, 1 warning
```

The installed-wheel directed mutation suite completed with `15 passed, 3
skipped`. A first run exposed that its ordinary-source mutation anchor now
matched the new sibling clinical revalidation first; the harness was corrected
to select the intended second occurrence, after which the behavioral mutation
again bit as designed.

The socket/deadline amendment added another explicit RED witness:

```text
3 failed, 58 passed, 1 skipped
```

The failures were the still-hidden five-second clinical UDS cap, the absent
per-connection broken-pipe isolation, and the absent executable socket-parent
initializer/verified group contract. After implementation, the focused
runtime, adapter, static, and Linux-process corpus completed on Windows with:

```text
61 passed, 4 skipped
```

The four skips are the POSIX secret-mode check and three Linux `SO_PEERCRED`
process cases, including the root-only numeric UID/GID access test. The final
unit/static corpus completed with `373 passed, 17 skipped, 1 warning`; the
installed mutation plus clinical process corpus completed with `15 passed, 6
skipped`.

The broader Windows regression command covering all unit/static tests and the
available Mattermost process integration tests completed:

```text
337 passed, 34 skipped, 1 warning
```

The skipped cases require POSIX ownership, symlinks, signals, or the real
`/run` AF_UNIX namespace. Docker Desktop was not running and the only WSL
distribution was the unavailable Docker Desktop distribution, so this evidence
does not claim Linux UDS/container execution.

Ruff passed for all changed Python files. A clean wheel was built and installed
into an isolated target, then the focused installed-package and static tests
completed with `27 passed`.

## Proven behavior

- exact command and canonical patient UUID parsing;
- malformed, confusable, reply, duplicate-mention, and extra-text namespace
  forms never reach the conversation path;
- clinical-only preflight and delivery make no conversation readiness or turn
  calls;
- exact direct-channel roster and channel/actor pair binding;
- encrypted durable association of actor, patient, operation, source/request,
  integration, response digest, and signed policy identity;
- exact frozen query/reauthorization body and response shapes, including the
  response-digest delivery binding;
- changed integration identity on recovery and mismatched/swapped response
  projections disclose nothing;
- deterministic appointment and no-upcoming text without model involvement;
- delivery-time HRH reauthorization followed by another Mattermost source and
  roster check;
- unknown response/request fields, impossible dates, mismatched timezone, and
  non-authorized delivery outcomes disclose nothing; and
- existing nonclinical private-channel behavior remains green;
- the adapter accepts only the authenticated ingress UID and two internal
  routes, maps them only to the two HRH endpoints, and has no fallback;
- HRH transport status, redirect, DNS/TLS/timeout, partial/malformed/oversized
  payload, unknown fields, and secret-permission failures are fail-closed; and
- a clean wheel contains and imports the production adapter entry point;
- clinical policy cannot arm with an ingress UDS budget below the adapter's
  ten-second maximum, and the ingress no longer truncates its remaining budget
  to five seconds;
- the adapter applies one absolute upstream timeout budget and a broken client
  response socket cannot terminate the accept loop; and
- socket parent initialization plus post-bind owner/group/mode verification is
  executable rather than an operator assumption.

## Remaining proof

Linux process witnesses for real `SO_PEERCRED` acceptance/rejection are present
but skipped on this Windows host. Closure still requires cross-repository Linux
E2E evidence using the exact wheel/images, a real protected clinical UDS peer,
the frozen HRH endpoints, pinned TLS/CA and network policy, revocation between
query and delivery, crash/retry snapshot stability, and a real Mattermost
direct channel. The Docker daemon was unavailable, so neither adapter image
build nor container composition is claimed here.
