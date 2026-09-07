# SG-PHI-GOV-001 usage note

This folder contains the governance handoff for tracker [#6](https://github.com/cervantesh/restricted-hermes-runtime/issues/6).
It is separate from runtime code and technical test receipts.

## Use

1. Copy `pilot-readiness-decision-record.template.md` to a candidate-specific
   record. Keep the template itself unresolved.
2. Freeze one candidate first: record exact source SHAs, contract/policy
   digests, OCI image digests, Mattermost and Health-Record-Hub revisions,
   provider/model/region, dependency locks, base images, and deployment SHA.
   Compute the final record and evidence-manifest digests before collecting
   signatures; changing either invalidates every signature.
3. Fill only the bounded clinical flow. A broader workflow requires its own
   reviewed contract; do not widen this record silently.
   Before the pilot gate closes, all identifiers, patients, users, channels,
   fixtures, and test records must be synthetic and unrelated to real people or
   production records.
4. Attach product-controlled receipts, then obtain an independent review of the
   same immutable candidate. Green CI or a historical review is not enough.
   The reviewer must be independent of the author, operator, and approver.
5. Obtain named, verifiably delegated decisions from the technical operator,
   security/risk owner, privacy/legal owner, clinical/product owner, and pilot
   approver.
6. Attach attributable evidence for IAM, egress, provider terms, secrets,
   backups, audit, incident response, workforce controls, recovery, and
   rollback. Include applicable contractual evidence or an attributable
   privacy/legal determination that no such contract is required; the record
   itself does not decide that question. Record references, digests, dates, and
   owners; never commit PHI, credentials, or secret material.
7. Record residual risks and preserve the nonclaims. Every unresolved field is
   a failed gate.
8. Select `NO-GO`, `GO WITH CONDITIONS`, or `GO`. Section 9 is authoritative:
   any absence, rejection, `NO-GO`, or pending condition forces `NO-GO` for PHI.
   `ACCEPT WITH CONDITIONS` cannot close a blocker or coexist with `GO` while a
   condition is open. A recorded `GO` only registers compatible external
   decisions with matching scope; this record never grants authority.

## Evidence boundary

The runtime can demonstrate bounded technical properties for a specified
artifact, such as closed routes, fail-closed handling, isolation, idempotency,
and recovery. It cannot establish legal approval, HIPAA compliance, a BAA,
provider terms, workforce authorization, host/network controls, or production
readiness. Those facts belong to accountable external parties.

This record is a governance checkpoint, not a deployment recipe. Completing it
or passing tests never authorizes real PHI by itself.
