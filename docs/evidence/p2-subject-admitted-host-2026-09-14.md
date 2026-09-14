# P2 subject-admitted host witness — 2026-09-14

This is a bounded, synthetic non-PHI conformance witness.  It is not a
production deployment, authorization, HIPAA/BAA assertion, or PHI claim.

## Subject-admission immutable frame

- runtime: `8babe4e65640ceaa34aecce9adb4784db4c06bfe`
- runtime tree: `c41e4b6395e4b239aff48f376d30f4b17905ad23`
- immutable tag: `immutable-candidate-2026-09-14-8babe4e`
- candidate workflow: https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/34864036542
- Health Record Hub source frame: `ad13735e9881a48580a9e138daac137f8c865dea`

The host was Ubuntu 24.04 x86_64 with a local Docker socket. Before service
creation it independently reverified the exact candidate's provenance and
SBOM attestations with `gh attestation`, using separate source and evidence
roots so the runtime checkout remained clean.

The admission path now performs that live attestation check itself after
structural candidate validation and before staging can create state or invoke
Docker. A real-boundary negative control shadowed `gh` with a failing command:
the otherwise valid candidate was denied, and no staging state, containers, or
networks were created.

## Real-host result

`tests/deployment/test_representative_clinical_egress.sh` passed against the
exact source frames and published subject digests. Its canonical receipt SHA-256
is `de9cba120eb341a00381a9fb9993cb1c7da6a2e72a2ffaff4e25842f238ba805`.

The receipt records RED detection for both restricted services on a controlled
external network, GREEN denial after removal, fixed public-DNS and metadata
controls, exact executed RepoDigests, restricted service controls, and cleanup.
It was independently verified again with
`tools/representative_clinical_egress.py --verify` on the host.

## Negative host control

A copy of the candidate manifest with only `source_revision` changed to forty
zeroes was rejected as `subject admission source revision differs from runtime`.
The rejection occurred before staging state, containers, or networks were
created. The live-attestation-negative control above supplied the complementary
authentication failure. Temporary negative material and staging resources were
removed after evidence extraction.

## Earlier composed control

The prior immutable frame, `6a402732b039c1be21074931007e515e4c662747`, also
ran the separate full composed secret/recovery control. Its receipt SHA-256 is
`9a980d0f9f841b86e6a5a1bd2ef4938103bac5ab5c0ce2760ecd0ed8e906c02c`.
That control is retained as evidence for its unchanged exact-source,
secret-boundary, revocation, and recovery paths; it is not substituted for the
new subject-admission witness above. The later `8babe4e` change is confined to
live attestation authentication of subject admission.
