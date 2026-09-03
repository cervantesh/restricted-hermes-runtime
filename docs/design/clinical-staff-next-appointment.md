# Clinical staff next-appointment slice

## Decision

The first clinical capability is a deterministic, read-only staff command in
an exact two-party Mattermost direct channel:

```text
@restricted-bot next-appointment <canonical-lowercase-patient-uuid>
```

It is deliberately not a model tool. The command never enters the restricted
conversation service, provider, prompt history, plugins, tools, or memory. It
proves the human-identity, patient-selection, authorization, durability, and
disclosure boundaries before any model-mediated clinical capability is
admitted.

## Signed configuration

Clinical mode is enabled only when the signed Mattermost policy contains the
complete clinical extension:

- `clinical_bindings`: canonical channel/actor pairs (one actor per channel);
- `clinical_integration_id`: the HRH integration binding;
- `clinical_policy_id`: exactly `clinical-read-v1`;
- `clinical_query_socket_path`: exactly
  `/run/restricted-clinical/query.sock`; and
- `clinical_timezone`: the exact IANA-style timezone expected from HRH.

Partial extensions, duplicate channel bindings, Cartesian channel/user
allowlists, another socket path, and a mismatched timezone fail closed.

## Runtime flow

1. The edge removes the one exact bot mention and accepts only the exact ASCII
   root command. Case variants, Unicode-dash lookalikes, invalid or uppercase
   UUIDs, extra text, and replies reserve the namespace but are not sent to the
   model.
2. The source must be a Mattermost `D` channel whose complete first-three
   membership result is exactly `{signed actor, signed bot}`. The signed policy
   must contain that exact channel/actor pair.
3. Before any clinical query, the encrypted durable outbox commits actor,
   patient, operation, source/request identity, integration identity, policy
   identity, and expiry. Recovery rejects a changed integration binding.
4. A dedicated UDS client calls only the clinical query service. Its outgoing
   body is exactly:

   ```json
   {"mattermostActorId":"...","patientId":"...","requestId":"...","integrationId":"...","clinicalPolicyId":"clinical-read-v1","policyEpoch":"...","policyDigest":"..."}
   ```

5. The only accepted query result is
   `{"clinicTimezone":"...","appointment":null,"responseDigest":"..."}`
   or that same object with one exact appointment DTO containing only `id`,
   `date`, `time`, `duration`, and `status`. `responseDigest` is the HRH
   SHA-256 commitment to the exact closed projection. The edge recomputes it
   before durably storing the DTO and deterministic response text.
6. Immediately before disclosure, the edge revalidates the source and exact DM
   roster, calls the HRH-backed delivery reauthorization with the same closed
   tuple plus the stored `responseDigest`, and then revalidates the source and
   roster once more. Denial,
   unavailability, indeterminate or malformed results cause no PHI post.

## Recovery and delivery semantics

The clinical record uses the existing encrypted, authenticated, single-writer
Mattermost outbox. Its source and root fences, nonce history, expiry, compare-
and-set transitions, and ambiguous-post handling remain unchanged. A crash
before a confirmed Mattermost response is duplicate-averse, not exactly-once;
an `IN_FLIGHT` record is terminal `AMBIGUOUS` on recovery and is never retried.
HRH treats `requestId` plus the frozen integration, actor, patient, policy
epoch and digest as the durable authorization correlation. It atomically
records the first response digest. A retry may return the same projection; a
changed projection under the same request is denied. The runtime therefore
keeps the first accepted DTO and digest in its encrypted outbox and never
reconstructs a response from later mutable state.

## Dedicated HRH adapter

`restricted_runtime.services.production_clinical_adapter` owns
`/run/restricted-clinical/query.sock` as UID 10008 and authenticates the
connecting ingress as UID 10007 using Linux `SO_PEERCRED`. It maps only the two
internal routes to the two closed HRH endpoints with an API key scoped exactly to
`restricted-hermes:clinical-read`:

- `POST /api/restricted-hermes/clinical/next-appointment`
- `POST /api/restricted-hermes/clinical/reauthorize-delivery`

The adapter is built separately by `Dockerfile.clinical-adapter`; it has no
Hermes agent, conversation, provider, Mattermost credential, or general HRH
proxy. It reads the HRH key from an owned regular secret file with mode 0400 or
0600, trusts only the configured CA, connects directly to one configured HTTPS
origin using `http.client` (no proxy discovery and no redirect following), and
accepts bounded HTTP/JSON frames only. Errors return a content-free failure and
there is no fallback route. Its socket group is the local principal boundary;
the edge receives only that group and never receives the HRH credential or HRH
network access.

Before either service starts, `deploy/mattermost/clinical-socket-init.sh` must
run as root over the shared socket volume. It creates the parent as
`10008:20006` with mode `0770`. After binding, the adapter explicitly assigns
the socket to GID 20006, sets mode `0660`, reads the metadata back, and exits
closed unless owner, group, type, and mode are exact. Thus parent-directory
ownership is a deployment precondition and socket ownership is a runtime-
verified postcondition.

Clinical signed policies require an ingress UDS budget of at least 10 seconds;
the adapter configuration permits at most 10 seconds and applies that as one
absolute upstream request budget. The ingress uses its remaining signed UDS
budget for connect, send, and receive instead of imposing a hidden five-second
socket cap. A peer disconnect during the final response is isolated to that
connection and does not terminate the adapter loop.

The example configuration is
`deploy/mattermost/clinical-adapter.example.json`. Production orchestration
must mount the clinical socket volume into both services, mount the API key and
CA only into the adapter, and enforce network policy with these asymmetric
edges: ingress -> Mattermost + clinical UDS; adapter -> pinned HRH HTTPS only.
This repository does not invent a production HRH hostname or secret mount and
therefore does not ship a misleading standalone Compose deployment.

## Staged capability rationale

This slice is technical hardening evidence, not a PHI, HIPAA, BAA, or medical-
production authorization. It intentionally admits one read-only operation and
one minimal DTO. Later Hermes capabilities require their own explicit policy,
negative cross-user/cross-patient tests, retention decision, and evidence that
they do not widen this boundary implicitly.
