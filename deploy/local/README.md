# Local Linux restricted runtime deployment

This directory is an operationally repeatable Docker Compose reference for the
existing `local-uds` runtime. It is **not HIPAA compliance**, **not PHI
authorization**, not model attestation, and not byte-reproducible
infrastructure. The default profile does not contain a broker and never creates
operator authority or key material.

## Fixed topology

`external role -> conversation.sock -> gateway.sock -> broker.sock`

Conversation and gateway have no Docker network and publish no ports.
PostgreSQL also has no network listener; both runtimes use its separate Unix
socket. Kernel peer identity maps UID 10006 to
`restricted_local_conversation` and UID 10005 to
`restricted_local_gateway`. The LOGIN roles inherit only their respective
content or ledger group role.

`/readyz` remains a component endpoint. It is not whole-stack health. The
deployment is usable only after the operator separately proves the policy,
authorization, database, gateway, and broker paths.

## Operator preparation

1. Decide and attest the broker/model, retention, logging, training, host,
   firewall, backup, access-control, audit, incident-response and contractual
   posture. This repository does not do so.
2. Keep the Ed25519 policy private key outside this repository and build
   context. Prepare the public image-bound policy:

   ```text
   python tools/prepare_local_policy.py \
     --private-key-b64-file /operator/offline/policy-private.b64 \
     --epoch 2026-09-01.1 --tenant-id tenant-a \
     --runner-principal local-runner --gateway-principal local-gateway \
     --model-display-name operator-approved-model \
     --model-sha256 <64-lowercase-hex>
   ```

3. Create six uniquely named external Docker volumes: inference sockets,
   conversation authorization, gateway authorization, conversation keys,
   gateway keys and PostgreSQL admin secret. Attach the inference volume to the
   operator-controlled broker before starting this stack. Populate the two
   authorization volumes with identical signed `authorization.json` and
   `authorization.sig`, but ownership 10006 and 10005 respectively, mode 0600.
   Populate each key volume only with that role's 0600 key and retired-key
   manifest. Put the database admin password in a 0600 file named `password`
   owned by UID 999. No private signing key belongs in these volumes.
4. Copy `.env.example` outside the repository, replace public placeholders and
   exact volume names, then validate before acting:

   ```text
   docker compose --env-file /operator/config/restricted-local.env \
     -f deploy/local/compose.yaml config
   docker compose --env-file /operator/config/restricted-local.env \
     -f deploy/local/compose.yaml build
   ```

5. Start the broker on `broker.sock` first. Then start the stack. Gateway
   preflight verifies protected artifacts, digests, peer-authenticated
   PostgreSQL and broker reachability before the runtime starts. Conversation
   waits for exact gateway policy-pair readiness.

   ```text
   docker compose --project-name <unique-project> \
     --env-file /operator/config/restricted-local.env \
     -f deploy/local/compose.yaml up -d
   ```

Durable dispatch begins disabled in PostgreSQL. Enabling it is a separate
operator decision made through the PostgreSQL administrator boundary; changing
`RESTRICTED_ADMISSION_ENABLED` alone is insufficient.

## Lifecycle and cleanup

Recreating conversation/gateway leaves the external keys, authorization,
inference volume and PostgreSQL data unchanged. Never rotate or regenerate
those artifacts during a restart. Before cleanup, list only the selected
Compose project resources. Ordinary cleanup omits `--volumes`; persistent data
is removed only by an explicit destructive decision. Never use a global prune.

The opt-in conformance harness is `tests/deployment/test_local_compose_e2e.sh`.
It creates uniquely named disposable artifacts and a deterministic broker
containing only `SYNTHETIC_NON_PHI_ONLY` text. Its receipt/nonclaim contract is
always `model_attested=false`, `deployment_conformant=false`, and
`phi_authorized=false`. It is not a template for production authority.
