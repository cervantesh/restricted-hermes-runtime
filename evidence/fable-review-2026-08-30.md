# Fable independent review record

- scope: final independent review of the adversarial delta through
  `09cca80a3dd0dda20e5484a67b1693939ef0fb5b`, including the prior reviewed
  head `a618587dd7714a8e8ec0b4657da9fa463faa3aa0`
- model/session: Fable via Claude CLI, session
  `e4a0839b-1638-47f7-810f-e13a0399784c`; completed cleanly
- record type: concise evidence register, not a literal or complete transcript
  of Fable output
- verdict: **ACCEPT**; no P0/P1 findings
- software disposition: the restricted two-service path, OCI isolation evidence,
  real ephemeral PostgreSQL run, and synthetic provider evidence are acceptable
  at the recorded head
- configured app startup is optional hardening, not a blocker

## Residual nonblockers

Fable recorded these follow-ups without treating them as release blockers:

- empty and exact-65,536-byte `thoughtSignature` boundary tests;
- inert `dist-info/RECORD` names;
- inspected-versus-manifest OCI layer count as future hardening;
- `rm -f` path drift, already caught by tests;
- slightly stricter fail-closed detail schema; and
- requiring the Docker gate in CI.

Provider smoke remains **PENDING** for user passkey reauthentication. PHI
authorization, registry push, deployment, BAA, IAM, and egress remain
**BLOCKED**. No signed policy, deployed revision, registry digest, or PHI
readiness is claimed.
