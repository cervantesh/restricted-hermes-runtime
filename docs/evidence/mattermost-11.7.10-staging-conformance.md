# Mattermost 11.7.10 exact-digest staging conformance

**Scope:** synthetic, explicitly non-PHI staging only

**Repository base:** `676bb074008ee721d741c4dd18fbbbeab8cd8150`

**Evidence revision:** the commit containing this receipt

**Host engine:** Docker Desktop 29.4.3, Linux/amd64 containers

This receipt records one clean execution of
`python tests/deployment/test_mattermost_esr_staging.py`. The harness created a
unique Compose project from empty volumes and kept its temporary state outside
the repository. It removed that project's containers, networks, volumes, test
images, generated policy, credentials, keys, synthetic posts, and temporary
directory at the end of the run.

## Supply-chain frame

- Mattermost Team Edition `11.7.10`:
  `sha256:84a041d836bf6fbf6a9a78ab699fa5ebe5437bfb6a514b5afad4121fa3800696`
- PostgreSQL `17.10-bookworm`:
  `sha256:9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f`
- Both runtime images were inspected as Linux/amd64 and each running container's
  image ID was compared with the inspected pinned image ID before any Mattermost
  user, bot, team, channel, membership, token, or post was created.

The compatibility claim is limited to those exact digests.

## Observed contract

- Two bootstrap invocations converged to the same topology and exactly one usable
  bot token.
- Wrong CA, a trusted certificate with the wrong SAN, an alternate hostname, and
  a plaintext origin all failed before an authenticated ingress became ready.
- The production ingress emitted its content-free authenticated-ready marker only
  after the real Mattermost WebSocket authentication reply returned `status=OK`.
- A direct real-server WebSocket challenge and the production ingress both
  rejected a wrong token without changing processing or reply counters.
- An allowed root plus continuation produced two turns and two replies in one
  restricted conversation. After recreating only the Mattermost container, a
  continuation preserved the same root and conversation, resulting in three turns
  and three replies.
- Denied user, denied private channel, public channel, DM, GM, uploaded file,
  edited/root-without-mention, and removed bot membership produced no additional
  effects in the unmodified ingress. During the denied-private-channel scenario,
  the bot was a real channel member, so Mattermost delivered the event and the
  ingress allowlist—not server fan-out—denied it.
- Real root, continuation, uploaded-file, immediate create-response, and later
  stored read-back shapes were checked separately. The immediate response
  preserved channel, root, and deterministic `pending_post_id`; later read-back
  preserved channel and root but omitted the client field.
- The ingress-equivalent network namespace reached only the exact TLS Mattermost
  peer and `conversation.sock`; PostgreSQL, the alternate TLS name, plaintext,
  external DNS, external IPv4, and external IPv6 probes failed.
- Removing both channel-allowlist enforcement points in a disposable mutated
  image made the denied-channel scenario produce one turn and one reply. This
  directed mutation proves that the real allowlist assertion can fail.
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

The harness separately captured the immediate create response and a later stored
read-back for a deterministic probe post. The exact server echoed the supplied
`pending_post_id` immediately and omitted it from later read-back. Production
consumes the immediate response, so its original exact channel/root/pending binding
is retained. The stored omission means this evidence does not claim durable
server-side idempotency.

## Test disposition

- Exact Mattermost staging harness: **PASS**
- Focused Mattermost unit/static tests: **46 passed, 1 Windows symlink skip**
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
