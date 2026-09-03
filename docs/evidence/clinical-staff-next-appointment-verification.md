# Clinical staff next-appointment verification

## Evidence frame

- Base: `3c185717f82b4ec2fba0a635679e816ba269717c`
- Platform: Windows, Python 3.11
- Data: synthetic identifiers and appointment values only
- Scope: restricted-runtime Mattermost edge and the dedicated clinical
  UDS-to-HRH adapter implementation; no live HRH, Mattermost, PHI, or medical
  workflow was exercised.

The earlier Windows-only frame above is retained as the implementation
witness. The composed Linux closure run below supersedes its container/E2E
limitations without changing its compliance disclaimer.

## Composed Linux closure

Exact clean source frame used by the composed build:

- restricted runtime harness HEAD: `2fc8d706a76af0ab805f516649f04bfd503f2572`;
- restricted runtime tree: `697b26086ad6a770c8e5acdecc919259d6c8d144`;
- frozen runtime product ancestor: `8049dd7612176b33e65ef19f61f5699aef7e0a28`;
- Health-Record-Hub HEAD: `b32970ee053c4caf180d6bdadce9b8d043ab1eba`;
- Health-Record-Hub tree: `973f5c73b37dffe7171b2e0e6d57719cf54b3e5b`;
- Mattermost: `mattermost/mattermost-team-edition:11.7.10@sha256:84a041d836bf6fbf6a9a78ab699fa5ebe5437bfb6a514b5afad4121fa3800696`;
- PostgreSQL: `postgres:17.10-bookworm@sha256:9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f`;
- TLS proxy: `nginx:1.28.0-alpine@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284`.

Command:

```text
python tests/deployment/test_clinical_composed_e2e.py
```

Result: `Clinical composed E2E: PASS` from clean, ephemeral containers and
volumes. The run used migration 0083, a real Mattermost direct-message event,
the production ingress and adapter images, a CA-pinned HTTPS HRH boundary, and
synthetic staff, patient and appointment records.

The scenario matrix passed: valid minimal appointment delivery; actor, channel
and patient cross-controls; unbound and disabled bindings; each missing
permission; swapped response digest; revocation after query but before
delivery with zero post; unrelated UDS UID denial; and crash/recovery.
Denied HRH authorization is carried as an authoritative 403 through the
adapter and is terminal in the encrypted outbox rather than becoming eligible
after permissions are restored.

Post cardinality was exact after restoring authorization and allowing recovery
to drain: the valid and recovered roots each had one bot reply; actor-cross,
channel-cross, unbound, disabled, missing-patients, missing-appointments and
revoked roots each had zero. This final sweep proves terminal denials do not
revive under a later-valid policy.

Built application image IDs were:

- ingress: `sha256:b640a42066508b46721ceb08aa22bba6762f7d43ca1fbd89f52a4900004ecd45`;
- clinical adapter: `sha256:c40228bc4db224d5eb18617bbfa0bab4c5e3517f4c9e94b2e0c14c8ce4bcf01d`;
- HRH: `sha256:191a484cd0f84ff537b0cacda469450e14deba8ed6d8091704fb4e145ff20658`.

Crash/recovery produced these PHI-free invariants:

```json
{
  "response_digest_equal": true,
  "read_authorized": 1,
  "read_completed": 1,
  "delivery_reauthorized": 2
}
```

The two delivery reauthorizations are intentional: the first server-side
transaction commits after the ingress client is killed, and the recovered
record must obtain a fresh authorization immediately before posting. The PHI
read and completed-read audit each occur exactly once, and the encrypted
result digest remains unchanged.

The edge could not resolve HRH and contained no HRH credential; the adapter
could not resolve Mattermost and could resolve only the HRH-side network; an
unrelated UID could not use the socket. Container log scans found none of the
synthetic patient, appointment, staff or email canaries. The machine-readable
summary is in `clinical-composed-e2e.json`.

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

## Residual limitations

The composed run used synthetic data and an ephemeral test CA. It is technical
conformance evidence, not a HIPAA, BAA, PHI-handling or medical-production
certification. It exercised Linux containers and the pinned Mattermost ESR
image, not production infrastructure, host controls, backup/restore,
monitoring, key custody, or an independent organizational risk assessment.
