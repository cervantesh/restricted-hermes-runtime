# Source-free HRH candidate consumption

## Status and boundary

This is the consumer contract for restricted-runtime issue #23. It adds an
explicit `published` mode to the existing composed clinical witness. In that
mode, only the Health-Record-Hub web and migration services are source-free.
The restricted runtime and the test controller are still built from this
repository. The existing `source-build` mode remains the default.

This contract uses synthetic data only. It is not PHI authorization, HIPAA
certification, deployment conformance, or approval for medical production.

## Independent selection

The operator selects four files outside the repository:

1. a closed trust declaration;
2. the producer's candidate receipt;
3. the approved KMS public key; and
4. a private Docker configuration directory containing only `config.json`.

The receipt and public key cannot select themselves. The trust declaration
independently fixes:

```json
{
  "schema_version": "restricted-runtime-hrh-trust.v1",
  "clinical_contract_revision": "<40 lowercase hex C>",
  "build_source_revision": "<40 lowercase hex H>",
  "platform": {"os": "linux", "architecture": "amd64"},
  "publisher_identity": "<approved publisher identity>",
  "kms_key_version": "projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n>",
  "kms_public_key_sha256": "<64 lowercase hex>",
  "subjects": {
    "web": "<registry>/web@sha256:<64 lowercase hex>",
    "migrate": "<registry>/migrate@sha256:<64 lowercase hex>"
  }
}
```

The Docker config contract is intentionally narrower than a general Docker
configuration: exactly one `config.json`, an `auths` object containing exactly
the registries selected by the two subjects, and one base64
`username:credential` `auth` entry per registry. On POSIX, the directory and
file must be owned by the caller and grant no group or other access. Credential
helpers, identity tokens, proxy settings, and unrelated registry credentials
are rejected.

## Ordering and fail-closed behavior

`tools/verify_hrh_published_candidate.py` first checks the trust declaration,
receipt, key fingerprint, roles, exact digest subjects, platform, publisher,
exact KMS version, retention evidence, material evidence, and non-authorization
claims. It then runs a digest-pinned Cosign container four times to verify SBOM
and provenance for each role. Provenance must bind the same `C`, `H`, role,
platform, publisher, KMS version, key fingerprint, workflow run, runtime
identity, materials, retention evidence, and source dependency.

Only after all four checks pass does the harness pull the two approved digest
references. Registry credentials reach Cosign through a read-only Docker config
mount and reach host pulls through `DOCKER_CONFIG`; they do not enter command
arguments, Compose environment files, receipts, or public evidence. Compose
starts published services with `--pull never`, and the published overlay has no
HRH build context, source mount, tag, or fallback.

The migration container must complete successfully before the web service can
start. The harness compares the stopped migration container and running web
container with the approved references, local image IDs, repository digests,
and `linux/amd64` platform before recording evidence.

## Running the two modes

Source-build mode is unchanged and remains the default:

```text
CLINICAL_E2E_HRH_ROOT=/clean/frozen/Health-Record-Hub \
python tests/deployment/test_clinical_composed_e2e.py
```

Published mode must run without `CLINICAL_E2E_HRH_ROOT` in the environment:

```text
CLINICAL_E2E_HRH_MODE=published \
CLINICAL_E2E_HRH_TRUST_DECLARATION=/private/input/trust.json \
CLINICAL_E2E_HRH_RECEIPT=/private/input/candidate-receipt.json \
CLINICAL_E2E_HRH_PUBLIC_KEY=/private/input/kms-public.pem \
CLINICAL_E2E_HRH_DOCKER_CONFIG=/private/docker \
python tests/deployment/test_clinical_composed_e2e.py
```

The consumer verifies signed publication claims but deliberately does not
recompute `C` ancestry of `H`; that requires the HRH repository and remains a
producer-side assertion. A real published-mode closure receipt also requires
actual retained subjects and their producer evidence. The in-repository tests
use synthetic fixtures and command doubles, and therefore validate the bounded
consumer and no-fallback orchestration without claiming a real publication.
