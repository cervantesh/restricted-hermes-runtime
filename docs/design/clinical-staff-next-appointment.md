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
   patient, operation, source/request identity, policy identity, and expiry.
4. A dedicated UDS client calls only the clinical query service. Its outgoing
   body is exactly:

   ```json
   {"mattermostActorId":"...","patientId":"...","requestId":"...","integrationId":"...","clinicalPolicyId":"clinical-read-v1","policyEpoch":"...","policyDigest":"..."}
   ```

5. The only accepted query result is
   `{"clinicTimezone":"...","appointment":null}` or that same object with
   one exact appointment DTO containing only `id`, `date`, `time`, `duration`,
   and `status`. The response text is formatted deterministically.
6. Immediately before disclosure, the edge revalidates the source and exact DM
   roster, calls the HRH-backed delivery reauthorization with the same closed
   tuple, and then revalidates the source and roster once more. Denial,
   unavailability, indeterminate or malformed results cause no PHI post.

## Recovery and delivery semantics

The clinical record uses the existing encrypted, authenticated, single-writer
Mattermost outbox. Its source and root fences, nonce history, expiry, compare-
and-set transitions, and ambiguous-post handling remain unchanged. A crash
before a confirmed Mattermost response is duplicate-averse, not exactly-once;
an `IN_FLIGHT` record is terminal `AMBIGUOUS` on recovery and is never retried.
HRH must treat `requestId` plus the frozen integration, actor, patient, policy
epoch and digest as the durable authorization correlation.

## External adapter assumption

This repository implements only the restricted-runtime half. The owner of
`/run/restricted-clinical/query.sock` must be a separately deployed,
least-privileged adapter that authenticates the UDS peer and invokes the two
closed HRH endpoints with an API key scoped exactly to
`restricted-hermes:clinical-read`:

- `POST /api/restricted-hermes/clinical/next-appointment`
- `POST /api/restricted-hermes/clinical/reauthorize-delivery`

The adapter must not expose a general HRH proxy. Its socket ownership/group is
the clinical service principal boundary; the Mattermost image receives only
the dedicated clinical-query group in addition to its existing groups.

## Staged capability rationale

This slice is technical hardening evidence, not a PHI, HIPAA, BAA, or medical-
production authorization. It intentionally admits one read-only operation and
one minimal DTO. Later Hermes capabilities require their own explicit policy,
negative cross-user/cross-patient tests, retention decision, and evidence that
they do not widen this boundary implicitly.
