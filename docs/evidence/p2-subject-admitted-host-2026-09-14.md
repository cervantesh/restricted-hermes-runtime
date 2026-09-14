# P2 subject-admitted host witness — 2026-09-14

This is a bounded, synthetic non-PHI conformance witness.  It is not a
production deployment, authorization, HIPAA/BAA assertion, or PHI claim.

## Immutable frame

- runtime: `6a402732b039c1be21074931007e515e4c662747`
- runtime tree: `a7d2fffbeed5946b7ab39247067b2b0f26cf8f6a`
- immutable tag: `immutable-candidate-2026-09-14-6a40273`
- candidate workflow: https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/34804863747
- Health Record Hub source frame: `ad13735e9881a48580a9e138daac137f8c865dea`

The host was Ubuntu 24.04 x86_64 with a local Docker socket. Before service
creation it independently reverified the exact candidate's provenance and
SBOM attestations with `gh attestation`, using separate source and evidence
roots so the runtime checkout remained clean.

## Real-host result

`tests/deployment/test_representative_clinical_egress.sh` passed against the
exact source frames and published subject digests. Its canonical receipt SHA-256
is `f878241c20e3a20f3d10b7b7fac14e4ef434099abcc4aca82532c077035d9594`.

The receipt records RED detection for both restricted services on a controlled
external network, GREEN denial after removal, fixed public-DNS and metadata
controls, exact executed RepoDigests, restricted service controls, and cleanup.
It was independently verified again with
`tools/representative_clinical_egress.py --verify` on the host.

## Negative host control

A copy of the candidate manifest with only `source_revision` changed to forty
zeroes was rejected as `subject admission source revision differs from runtime`.
The rejection occurred before staging state, containers, or networks were
created. The temporary negative material and the complete composed run were
removed after evidence extraction.
