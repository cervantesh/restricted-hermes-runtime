# Hermes restricted-runtime composed E2E

`tests/deployment/test_hermes_restricted_runtime_e2e.sh` is the real,
four-container witness for the closed Hermes restricted runner.  It pins the
runtime source to `7ce40dad644521c658f2985958be6cfc745d06be` and its Hermes
client source to `f04d9162a98902926f36e94034821be8f0027bff`.

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
The next run is pending the separately adjudicated Hermes peer-credential
contract correction; it must again prove the full composed path rather than
reuse this RED result.
