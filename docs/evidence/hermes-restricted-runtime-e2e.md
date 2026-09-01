# Hermes restricted-runtime composed E2E

`tests/deployment/test_hermes_restricted_runtime_e2e.sh` is the real,
four-container witness for the closed Hermes restricted runner.  It pins the
runtime source to `7f3f7d04e3307921c4ca684f0438e9bfdd1b4266` and its Hermes
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

## Current result

The witness is deliberately **RED** at the pinned runtime revision.  The
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
the runtime response and its client contract agree.
