# Historical A0 candidate evaluation — execution closure card

## Exact subject and purpose

This card records the former `49dca06` source-only candidate evaluation frame.
It is historical evidence, not a current execution authorization: that source
cannot be relabeled as the integrated candidate because it diverged from the
current P2 host-admission line.  The current integration boundary is defined
by `a0-integrated-candidate-closure.md` and requires fresh exact-SHA receipts
before any future candidate-tag consideration.

The only admissible source subject is revision
`49dca06b7a2e2b8134e2c4e426112e55fa73d0c3`, tree
`5e0708c609621b8930aac03a57ac47f9f453ce0f`, as named by
`docs/evidence/reconciled-a0-candidate-ledger-2026-09-11.json`. The ledger is
retained in a later evidence frame; it verifies the source subject's Git
objects and ancestry but does not claim to be part of that source tree.

## Closure contract

The execution is complete only if all conditions below hold:

1. A new, unique `immutable-candidate-<date>-49dca06` tag resolves exactly to
   the subject revision. A previous tag or a moved tag is inadmissible.
2. `Immutable clinical-edge candidate` completes successfully for that tag and
   produces digest-pinned `restricted-mattermost-ingress` and
   `restricted-clinical-adapter` subjects.
3. Its retained artifact contains the two subject records, provenance and
   SPDX-SBOM verification receipts bound to this source revision, platform and
   source-label inspections, candidate manifest, and command outcomes.
4. The manifest is accepted by
   `tools/verify_immutable_candidate.py --closed-subjects-only`.
5. The workflow's role-closure, clinical-adapter protocol, and Mattermost ESR
   staging checks consume the published digest-pinned subjects, not rebuilt
   source images.

The retained A0 record must name the tag, source revision/tree, workflow URL,
artifact hashes, both immutable image references, and every command outcome.

## Negative controls and stop conditions

The admission record must reject a changed source revision/tree, missing or
mutable/wrong subject digest, missing/mismatched attestation predicate, a
source-built substitute for a published image, and every attempt to elevate
the result to representative-host verification, deployment conformance, PHI
authorization, HIPAA/BAA status, or a pilot decision.

Stop if the tag is not exact, a workflow artifact omits a required receipt,
either image is not digest-pinned, an attestation is not bound to the source,
or a published-image test is skipped. A failed workflow is a failed A0
attempt; do not synthesize a success receipt.

## Sequence and nonclaims

1. From this retained-evidence checkout, verify the A0 source ledger.
2. Create the unique tag on the exact source revision.
3. Run the immutable workflow and retain its artifact.
4. Verify the artifact manifest from a clean checkout and record the result.

This is hosted, synthetic, non-PHI evidence only. It does not replace the
representative-host gate, external service qualification, operational review,
independent assessment, or an authorized A1 decision. The next gate after a
successful artifact is representative-host evaluation against those same image
digests, not a pilot launch.
