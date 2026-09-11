# A0 candidate evaluation — execution closure card

## Exact subject and purpose

This card defines the smallest reproducible A0 execution that advances the
reconciled runtime candidate from source-only evidence to a digest-pinned,
hosted synthetic evaluation. It is not an authorization record and does not
permit PHI, a controlled pilot, or deployment on a representative host.

The only admissible source subject is revision
`70217864aefc473759c739448831a8203ae81ded`, tree
`73d10d5a90197a6e4984cc6b83e0a97f480e3869`, as named by
`docs/evidence/p2-admission-candidate-ledger-2026-09-11.json`. The ledger is
retained in a later evidence frame; it verifies the source subject's Git
objects and ancestry but does not claim to be part of that source tree. This
subject includes the candidate-bound P2 collector and its pre-collection host
and local-Docker admission control; it does not itself claim a P2 host receipt.

## Closure contract

The execution is complete only if all conditions below hold:

1. A new, unique `immutable-candidate-<date>-7021786` tag resolves exactly to
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
Historical synthetic receipts listed by the source ledger remain bounded
provenance only; they are not execution evidence for this rebased subject.

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
2. Run `tools/a0_tag_preflight.py` against the declared source revision/tree
   and the proposed unique tag. Retain its canonical, content-safe receipt in
   the later evidence frame. A denial, including an existing remote tag, stops
   before any tag is created.
3. Create the unique tag on the exact source revision only after that receipt
   passes. Push only the new tag ref; a remote rejection or any mismatch stops
   the attempt rather than retrying with a moved/reforced tag.
4. Run the immutable workflow and retain its artifact.
5. Verify the artifact manifest from a clean checkout and record the result.

This is hosted, synthetic, non-PHI evidence only. It does not replace the
representative-host gate, external service qualification, operational review,
independent assessment, or an authorized A1 decision. The next gate after a
successful artifact is representative-host evaluation against those same image
digests, not a pilot launch.
