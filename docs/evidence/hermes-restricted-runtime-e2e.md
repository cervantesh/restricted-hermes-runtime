# Hermes restricted-runtime composed E2E

`tests/deployment/test_hermes_restricted_runtime_e2e.sh` is the real,
four-container witness for the closed Hermes restricted runner.  It pins the
runtime source to `4f457a55e84be6d40394f86ad45988fba50a5b07` and its Hermes
client source to `9032d66ac674ccac3b6f49d76dc454d2483c5247`.

The witness first exports the pinned runtime Git tree with
`core.autocrlf=false`, records its commit, tree and archive SHA-256, and runs
Compose from that LF blob export.  This is intentional: Docker bind mounts
shell scripts, while a Windows worktree with `core.autocrlf=true` otherwise
changes those bytes before Alpine executes them.  The original worktree is not
rewritten.

The client has no network, no host or Docker socket, a read-only conversation
socket volume, and the required UID/group separation.  The success path is
`restricted enable`, `restricted doctor`, then `restricted run --stdin`; the
script also exercises policy mismatch, missing socket, ACL denial, and altered
readiness controls.  It records only heads, commands, timings and pass/fail
labels outside the ephemeral directory; synthetic turn text is never recorded.

## Historical RED

The first witness run at `7f3f7d04e3307921c4ca684f0438e9bfdd1b4266` was
deliberately **RED**.  The
runtime's own conversation health probe receives:

```text
HTTP/1.1 200 OK
content-length: 510
content-type: application/json
```

but no `Connection: close` header.  The exact readiness client introduced by
the closed contract requires that header, so
`restricted_runtime.local_deployment_preflight ready conversation` rejects the
otherwise valid document and Compose never reaches a healthy conversation.
This is a production framing mismatch, not a harness exemption; the harness
does not continue to the Hermes turn or claim a successful composed proof until
the runtime response and its client contract agree.  Commit
`7ce40dad644521c658f2985958be6cfc745d06be` makes that header explicit; the
next fresh composed execution is recorded below rather than inferred from the
unit test.

## Second RED: cross-container peer PID

At `7ce40dad644521c658f2985958be6cfc745d06be`, the fresh `hrrte2e10`
composition passed conversation health and then proved the independent
no-network client observes the mounted socket as
`path=10006:20001:660 peer=0:10006:20001`.  Thus owner, mode, peer UID and peer
GID were exact, but the peer PID was zero across Docker PID namespaces.  Hermes
head `f04d9162a98902926f36e94034821be8f0027bff` required a positive PID and
returned `RESTRICTED_RUNTIME_UNAVAILABLE` before dispatch.

The E2E harness keeps the fourth client in a separate PID namespace.  It does
not compensate by sharing the conversation namespace, because that would
change the isolation topology being proved.  The hrrte2e10 log and failure
directory are retained outside the ephemeral project as privacy-safe evidence.
The corrected Hermes source is governed by contract SHA
`702F0BC5CD3515079E6C57A0253A9AABA8BFCA4763AE389CDCD3F8DA28AAFAE7` and
accepts this container-native PID value only when peer UID and GID remain the
exact required pair.  A new fresh run must still prove the complete composed
path rather than reuse this RED result.

## Third RED: init-time PostgreSQL health race

The fresh `hrrte2e14` run exposed a separate Compose defect before the Hermes
client was built.  PostgreSQL reported `healthy` while its official entrypoint
was still using the temporary initialization server.  The dependent
`gateway-preflight` then reached the intended Unix socket but received
`server closed the connection unexpectedly`; the entrypoint completed its init
scripts and restarted the final server immediately afterward.  The failure
log is retained at `C:\\Temp\\hrrte2e14.hermes-restricted-failure-logs`.

Commit `4f457a55e84be6d40394f86ad45988fba50a5b07` narrows no runtime policy:
it makes the existing `pg_isready` health probe conditional on PID 1 already
being the final `postgres` server.  This rejects the temporary entrypoint
server and retains the final ready state.

## Final GREEN: two fresh composed executions

`hrrte2e15` and `hrrte2e16` each ran from a new project with runtime
`4f457a55e84be6d40394f86ad45988fba50a5b07` (tree
`59fde4fb52e425ff9413f0eac4fb751f5e66934b`) and Hermes
`9032d66ac674ccac3b6f49d76dc454d2483c5247`.  Both stage the exact LF Git
archive with SHA-256
`f12d9d67e25cce2767d218b8072df0e03d52f116697277cb459619afb638bd2e`.

Each run proved the separate-PID-namespace peer tuple
`0:10006:20001`, readiness, `enable`, `doctor`, and one committed three-UDS
synthetic turn in two seconds.  Both also proved fail-closed policy mismatch,
absent socket, denied socket ACL, and altered readiness response; the normal
Hermes surface and plaintext marker were absent from `HERMES_HOME`, and all
three nonclaims remained false.  The privacy-safe durable evidence is
`C:\\Temp\\hrrte2e15.hermes-restricted-success-evidence.txt` and
`C:\\Temp\\hrrte2e16.hermes-restricted-success-evidence.txt`.

After each run, the harness verified that no project-labelled container or
volume and none of its nine exact image names remained.  It refuses a
pre-existing exact target image or volume, so cleanup never reaches resources
outside its unique project.  These results are runtime behavior evidence only:
they do not claim PHI authorization, model attestation, or deployment
conformance.

## Final GREEN with dual Git provenance

`hrrte2e17` repeated the complete witness with the same runtime commit and
Hermes commit, but now staged **both** sources before Docker received a build
context. Its durable evidence records the runtime tree/archive above and the
Hermes tree `abe8263661a9d55a732494deade6e8937dd6232e` with archive SHA-256
`3cc3b226bc97a6171e6bb9b0eea66aeea6b40e9b0f51c1ed3348e18607bc5636`.
The staged Hermes archive—not its live worktree—was the client build context;
the client Dockerfile itself came from the staged runtime archive. Thus
staged, unstaged, and untracked worktree files cannot enter this witness.

`hrrte2e17` again completed the three-UDS turn in three seconds, passed all
four fail-closed controls, and completed exact cleanup. Its privacy-safe
record is `C:\\Temp\\hrrte2e17.hermes-restricted-success-evidence.txt`.
The earlier `hrrte2e15` and `hrrte2e16` GREEN results remain valid runtime
lineage, but this final record is the provenance-complete witness.

## Restacked Hermes GREEN

`hrrte2e18` repeated the provenance-complete witness with Hermes restack head
`fe13b904d0c99c18991e3f281e91edf7ca1d84e3` on validated ancestor base
`95d42656021a22f20201c618a67da07a618d16f3`. The exact Hermes tree was
`5f60fa31086d35dd218296ab81ef6139f4470a55`; its staged archive SHA-256 was
`bc612ee334e9665d906539c3a69833e8598dd603424fb48363dc47bddb830b33`.
The runtime remained production head
`4f457a55e84be6d40394f86ad45988fba50a5b07`, tree
`59fde4fb52e425ff9413f0eac4fb751f5e66934b`, with staged archive SHA-256
`f12d9d67e25cce2767d218b8072df0e03d52f116697277cb459619afb638bd2e`.

The three-UDS turn reached `COMMITTED` in two seconds. Policy mismatch,
missing socket, denied ACL, and altered readiness all failed closed; the
normal Hermes surface and plaintext marker remained absent, all nonclaims
remained false, and exact cleanup completed. The privacy-safe source record is
`C:\\Temp\\hrrte2e18.hermes-restricted-success-evidence.txt`.
Range-diff equivalence was verified externally and is not a claim made by the
harness or this runtime witness.
