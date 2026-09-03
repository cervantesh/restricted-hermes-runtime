# Restricted Mattermost ingress

This is a **synthetic/non-PHI** implementation. It is not a HIPAA, BAA, PHI
authorization, or production-deployment claim.

## Closed path

`private Mattermost thread -> restricted Mattermost edge -> conversation.sock`

The signed ingress policy fixes one HTTPS origin, team, bot identity, private
channel and user allowlists, validity window, downstream inference policy pair,
text limit, and finite timeout ordering. The bot token is a separate read-only
mounted file. The process must preflight the exact conversation readiness pair,
bot account, and every channel before WebSocket authentication. Events are
ignored until authentication succeeds. Every accepted event freshly fetches
the channel and root. Replies always carry both the source channel and root;
there is no flat-post fallback.

Deterministic conversation and request identities preserve thread continuity
and conversation-ledger idempotency. Before a turn is submitted, the edge
commits one encrypted SQLite outbox record on its local persistent volume,
keyed by the Mattermost source post. A restart reuses that record's original
conversation epoch and client request identity. A committed turn which has
not entered `create_post` can therefore be recovered without another provider
dispatch. The record enters `IN_FLIGHT` before any Mattermost POST bytes are
sent; after that point a restart, timeout, or response-binding failure becomes
terminal `AMBIGUOUS`, never an automatic resend. This is deliberately
duplicate-averse, at-most-one POST-attempt behavior -- it does not claim
does not claim exactly-once posting or guaranteed eventual delivery.

## Operator gates

Before any real use, operators remain responsible for Mattermost retention,
audit configuration and review, backup and restore testing, patching cadence,
identity provider and membership lifecycle, private-channel governance, TLS
trust, DNS and IPv4/IPv6 network egress enforcement, secret mounting, firewall
rules, monitoring, and deployment conformance. The application disables proxy
discovery and redirects by construction, but application code is not the
network enforcement boundary.

`conversation_deadline_seconds` is enforced as one absolute monotonic budget
for each signed `POST /turns` submission. Before every UDS connect, send, and
receive, the edge recomputes the remaining time and applies the lesser of that
time and the signed UDS cap. It rechecks after response decoding and
validation. Recovery can issue a fresh bounded submission only while the
recorded policy and encrypted-payload-retention windows remain valid. If one
submission budget is exhausted, that submission produces no retry, fallback,
partial response, or Mattermost reply.

That budget deliberately does not include preflight/readiness, WebSocket
authentication, Mattermost REST validation, or reply delivery. Those phases
retain their own signed limits and are not a conversation-deadline SLA.

Required mounts and settings:

- signed ingress JSON/signature and its Ed25519 public key;
- a regular, non-symlink, size-bounded bot-token file;
- a separate regular, non-symlink, exactly 32-byte outbox key file whose
  SHA-256 fingerprint is bound by the signed ingress policy;
- an explicitly initialized, non-root-owned mode-`0700` state directory at
  `/var/lib/restricted-mattermost-outbox` on one local persistent volume;
- a CA bundle for the exact self-hosted Mattermost origin;
- `conversation.sock` reachable through GID 20001;
- a bot restricted to the allowlisted private channels, with read-channel,
  read-post and create-post permissions; and
- WebSocket support enabled, federation/DM/files outside this integration, and
  no webhook, slash-command, OCR, vision, attachment, plugin, or tool route.

Runtime startup does not initialize a missing state directory or silently
replace a mismatched key. Operators must run the dedicated initialization step
before first ingress start. Removing or restoring the whole outbox volume is
an explicit operator reset that forfeits historical source deduplication and
root fences; it is not a safe replay/recovery procedure.

Rollback stops the edge process and revokes the bot token. It does not alter
the restricted conversation, gateway, broker, database, or provider roles.

## Exact ESR staging conformance

`tests/deployment/test_mattermost_esr_staging.sh` is a synthetic, non-PHI
staging conformance harness for exactly Mattermost Team Edition 11.7.10 on
Linux/amd64 at its pinned image digest.  It is not a deployment recipe or a
general Mattermost compatibility claim.  Its isolated TLS topology is only a
test witness; real operators still own retention, backups and restore, IdP and
membership governance, audit configuration, patching, production firewalling,
BAA/HIPAA obligations, and PHI authorization.

The harness stores all generated state outside the repository and removes its
exact Compose resources, test images, and temporary directory on completion.

The latest exact-digest execution receipt is recorded in
`docs/evidence/mattermost-11.7.10-staging-conformance.md`.
