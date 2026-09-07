# SG-PHI-GOV-001 usage note

This folder contains the governance handoff for tracker [#6](https://github.com/cervantesh/restricted-hermes-runtime/issues/6).
It is separate from runtime code and technical test receipts.

## Use

1. Copy `pilot-readiness-decision-record.template.md` to a candidate-specific
   record. Keep the template itself unresolved.
2. Freeze one candidate first: record exact source SHAs, contract/policy
   digests, OCI image digests, Mattermost and Health-Record-Hub revisions,
   provider/model/region, dependency locks, base images, and deployment SHA.
3. Fill only the bounded clinical flow. A broader workflow requires its own
   reviewed contract; do not widen this record silently.
4. Attach product-controlled receipts, then obtain an independent review of the
   same immutable candidate. Green CI or a historical review is not enough.
5. Obtain named decisions from the technical operator, security/risk owner,
   privacy/legal owner, clinical/product owner, and pilot approver.
6. Attach attributable evidence for IAM, egress, provider terms, secrets,
   backups, audit, incident response, workforce controls, recovery, and
   rollback. Record references, digests, dates, and owners; never commit PHI,
   credentials, or secret material.
7. Record residual risks and preserve the nonclaims. Every unresolved field is
   a failed gate.
8. Select `NO-GO`, `GO WITH CONDITIONS`, or `GO`. Section 9 is authoritative:
   missing mandatory evidence or sign-off means `NO-GO` for PHI. Conditions must
   state the limited non-PHI activity allowed while they remain open.

## Evidence boundary

The runtime can demonstrate bounded technical properties for a specified
artifact, such as closed routes, fail-closed handling, isolation, idempotency,
and recovery. It cannot establish legal approval, HIPAA compliance, a BAA,
provider terms, workforce authorization, host/network controls, or production
readiness. Those facts belong to accountable external parties.

This record is a governance checkpoint, not a deployment recipe. Completing it
or passing tests never authorizes real PHI by itself.
