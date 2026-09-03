# Mattermost 11.7.10 exact-digest staging conformance

**Scope:** synthetic, explicitly non-PHI staging only

**Repository base:** `676bb074008ee721d741c4dd18fbbbeab8cd8150`

**Evidence revision:** the commit containing this receipt

**Host engine:** Docker Desktop 29.4.3, Linux/amd64 containers

This receipt records one clean execution of
`python tests/deployment/test_mattermost_esr_staging.py`. The harness created a
unique Compose project from empty volumes and removed that project's containers,
networks, volumes, generated policy, credentials, keys, and synthetic posts at
the end of the run.

## Supply-chain frame

- Mattermost Team Edition `11.7.10`:
  `sha256:84a041d836bf6fbf6a9a78ab699fa5ebe5437bfb6a514b5afad4121fa3800696`
- PostgreSQL `17.10-bookworm`:
  `sha256:9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f`
- Both runtime images were inspected as Linux/amd64 and each running container's
  image ID was compared with the inspected pinned image ID before scenarios ran.

The compatibility claim is limited to those exact digests.

## Observed contract

- Two bootstrap invocations converged to the same topology and exactly one usable
  bot token.
- Wrong CA, a trusted certificate with the wrong SAN, an alternate hostname, and
  a plaintext origin all failed before an authenticated ingress became ready.
- The production ingress emitted its content-free authenticated-ready marker only
  after the real Mattermost WebSocket authentication reply returned `status=OK`.
- A wrong token terminated the ingress without producing a turn or reply.
- An allowed root plus continuation produced two turns and two replies in one
  restricted conversation. After recreating only the Mattermost container, a
  continuation preserved the same root and conversation, resulting in three turns
  and three replies.
- Denied user, denied private channel, public channel, DM, GM, uploaded file,
  edited/root-without-mention, and removed bot membership produced no additional
  effects in the unmodified ingress.
- Real root, continuation, uploaded-file, and create-response shapes were checked.
  The outbound request carried a deterministic `pending_post_id`; the server
  preserved channel and root but did not preserve that client field.
- The ingress-equivalent network namespace reached only the exact TLS Mattermost
  peer and `conversation.sock`; PostgreSQL, the alternate TLS name, plaintext,
  external DNS, external IPv4, and external IPv6 probes failed.
- Removing the allowed-user authorization check in a disposable mutated image
  made the denied-user scenario produce one turn and one reply. This directed
  mutation proves that the real authorization assertion can fail.
- The retained, sanitized evidence was scanned against generated passwords,
  tokens, private keys, synthetic message/response canaries, file canary, and raw
  Mattermost identifiers before exact-project cleanup.

Mattermost 11.7.10 does not allow a bot's D/GM memberships to be removed through
the channel-member API. The harness therefore records only salted one-run channel
digests and removes those memberships with the disposable Mattermost/PostgreSQL
volumes. Temporary public membership is removed immediately.

## Real-server correction

The pre-change production client sent the WebSocket authentication JSON as a
binary frame. The pinned Mattermost server closed that connection before an
authentication reply, so the readiness marker was never reached. The corrected
client sends a UTF-8 WebSocket text frame. The process-level peer now asserts text
opcode `0x1`, and the exact server reaches authenticated-ready.

The exact server also omitted the client-supplied `pending_post_id` from its
stored/create response. The pre-change client therefore classified an otherwise
successful, correctly threaded post as rejected. The corrected response contract
binds the returned channel and root while the focused transport test independently
proves the deterministic outbound `pending_post_id`; it does not claim server-side
idempotency.

## Test disposition

- Exact Mattermost staging harness: **PASS**
- Focused Mattermost unit/static tests: **42 passed, 1 Windows symlink skip**
- Full Windows suite: **316 passed, 21 platform skips, 2 unrelated failures**
- The same two failures reproduce on the untouched sibling checkout: a migration
  test inherits a passwordless external PostgreSQL URL, and a runtime-wave fixture
  expects `ready` while its own comment describes a required `503` fail-closed
  result. Neither path is touched by this change.

## Remaining operator gates

This does not authorize PHI and does not provide a medical-portal deployment.
Retention, backup/restore, IdP and membership governance, audit configuration,
patching, production firewalling, BAA/HIPAA obligations, and an explicit PHI
authorization remain outside this synthetic staging proof.
