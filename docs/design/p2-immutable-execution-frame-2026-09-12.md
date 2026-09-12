# P2 immutable execution frame — 2026-09-12

## Purpose

This is the operator input card for a future **synthetic, non-production**
representative-host run against the immutable runtime candidate
`immutable-candidate-2026-09-12-7021786`.  It corrects the source-frame
ambiguity in the earlier collector closure card without changing the immutable
candidate itself.

It is deliberately not a P2 receipt, an A0/A1 decision, PHI authorization,
HIPAA/BAA evidence, production approval, or a clinical-readiness claim.

## Frozen subject frame

| Subject | Exact value |
| --- | --- |
| Runtime tag | `immutable-candidate-2026-09-12-7021786` |
| Runtime commit | `70217864aefc473759c739448831a8203ae81ded` |
| Runtime tree | `73d10d5a90197a6e4984cc6b83e0a97f480e3869` |
| Required HRH commit | `ad13735e9881a48580a9e138daac137f8c865dea` |
| Required HRH tree | `f217b0b1cf7f438422528dfe178d81b78212c68b` |
| Mattermost ingress OCI subject | `sha256:5dbc4a7e17910f62fdcba1162328eefc7e185c2cffe8c81eeb31eefae1e98fd1` |
| Clinical adapter OCI subject | `sha256:50ade779752dfcefd135b75ee7058afb1d2051c95643423652cdbe7a7754163c` |
| Subject publication run | [34703552764](https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/34703552764) |

The OCI digests above are the published subjects from the tag-triggered
workflow. They are not substitutes for a host-side subject-admission check.

## Admissible host and inputs

Before any execution, the operator must provide all of the following:

1. One administrator-provisioned, dedicated Ubuntu 24.04 LTS x86_64 host,
   reserved for this synthetic run and containing no production or PHI data.
2. A native host shell: neither WSL nor a container running with a mounted
   Docker socket is admissible.
3. Local Docker through the default `unix:///var/run/docker.sock` endpoint;
   `DOCKER_HOST` and `DOCKER_CONTEXT` must be unset.
4. Clean detached checkouts at the runtime tag above and the exact required
   HRH commit above. The harness independently rejects dirty or substituted
   source frames.
5. An empty, operator-owned destination directory for the canonical receipt.
   It must not be a log, home, evidence, or secret directory.

Do not put hostnames, account identifiers, environment files, raw logs,
credentials, certificates, endpoint addresses, or payloads in a receipt or
in a public follow-up.

## Exact current executable slice

On an admissible host, the currently implemented harness is invoked from the
detached runtime checkout:

```bash
bash tests/deployment/test_representative_clinical_egress.sh \
  /absolute/path/to/clean-exact-hrh \
  /absolute/path/to/new/p2-egress-receipt.json
```

The command first rejects an unsupported host class and non-local Docker
endpoint. It then creates synthetic staging state, proves a deliberate
RED dual-stack route to an ephemeral controlled sink for each restricted
service, removes that route, proves the GREEN denied state, removes only
owned resources, and verifies a canonical content-safe receipt. The harness
does not take secrets or endpoints as command-line inputs.

Expected terminal states are limited to:

- `PASS receipt_sha256=<digest>` for the executable egress slice;
- `DENIED` for policy, source, host, or collection failure; and
- `SKIP` only where the declared host capability needed for the synthetic
  witness is unavailable.

`SKIP` is not GREEN and must not yield a P2 conformance assertion.

## Strict boundary: what this does not yet prove

The executable egress harness is useful preparation, but it is **not** the
whole contract in [#31](https://github.com/cervantesh/restricted-hermes-runtime/issues/31).
The following still need a unified P2 conformance verifier and real-host
RED/GREEN witnesses before that issue can close:

| #31 control | Current status |
| --- | --- |
| Dedicated-host/operator admission | Host-class gate exists; dedicated ownership is an external operator attestation. |
| Exact published OCI subject admission | Digests are frozen above, but the egress harness builds and binds staging images rather than admitting those published OCI subjects. |
| Secret absence, stale/malformed material, and rotation | Staging generates synthetic secrets; the full negative/rotation P2 matrix is not yet collected. |
| Trust, audit, retention | Not collected by this egress harness. |
| Recovery controls | Existing synthetic recovery evidence remains separate; no representative-host P2 recovery witness exists. |
| Full host-effective egress matrix | The harness covers controlled dual-stack, DNS, metadata and proxy-related service probes; the complete #31 host-level matrix remains uncollected. |
| Independent replay | Not started. |

Therefore this card must be used to preserve the exact execution frame and to
avoid a misleading witness. It must not be cited as proof of representative
host conformance.

## Minimum unblocker

The immediate external blocker is a dedicated administrator-provisioned host
that satisfies the input requirements above. Once it exists, the egress slice
can run without new source mutation. Completing P2 still additionally requires
the bounded unified verifier and the remaining controls listed above; creating
or using an arbitrary shared VM would not substitute for either requirement.
