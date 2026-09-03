# Clinical staff next-appointment verification

## Evidence frame

- Base: `3c185717f82b4ec2fba0a635679e816ba269717c`
- Platform: Windows, Python 3.11
- Data: synthetic identifiers and appointment values only
- Scope: restricted-runtime Mattermost edge and the assumed dedicated clinical
  UDS adapter boundary; no live HRH, Mattermost, PHI, or medical workflow was
  exercised.

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
  and signed policy identity;
- exact frozen query/reauthorization body and response shapes;
- deterministic appointment and no-upcoming text without model involvement;
- delivery-time HRH reauthorization followed by another Mattermost source and
  roster check;
- unknown response/request fields, impossible dates, mismatched timezone, and
  non-authorized delivery outcomes disclose nothing; and
- existing nonclinical private-channel behavior remains green.

## Remaining proof

The runtime half cannot prove the HRH adapter or HRH authorization behavior in
isolation. Closure still requires cross-repository Linux E2E evidence using the
exact wheel/image, a real protected clinical UDS peer, the frozen HRH endpoints,
revocation between query and delivery, and a real Mattermost direct channel.
