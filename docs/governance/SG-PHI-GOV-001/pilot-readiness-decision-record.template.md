# SG-PHI-GOV-001 — Pilot-readiness decision record

**Tracker:** [#6](https://github.com/cervantesh/restricted-hermes-runtime/issues/6)  
**Template status:** `UNRESOLVED — NO-GO BY DEFAULT`  
**Record version:** `0.1`  
**Decision scope:** one exact candidate and one bounded pilot

> This is a governance record, not a certification, legal opinion, provider
> attestation, security warranty, or authorization to process PHI. Every blank,
> `TBD`, `UNRESOLVED`, stale, or unbound value is a failed gate. Until all
> mandatory evidence and sign-offs are present, use synthetic/non-PHI data only.

## 1. Decision frame

| Field | Required value |
|---|---|
| Record ID | `SG-PHI-GOV-001-<candidate-id>` |
| Decision date / timezone | `UNRESOLVED` |
| Pilot name and environment | `UNRESOLVED` |
| Data permitted while unresolved | `SYNTHETIC_NON_PHI_ONLY` |
| Requested decision | `NO-GO` / `GO WITH CONDITIONS` / `GO` |
| Effective decision | `NO-GO` |
| Decision owner | `UNRESOLVED` |

`GO WITH CONDITIONS` cannot authorize PHI while any mandatory technical,
independent, operator, privacy/legal, or clinical/product item remains open. It
may authorize only a separately described non-PHI staging step.

## 2. Exact candidate and external subjects

Moving branches, package ranges, and `latest` are not evidence. Every subject
that can affect the decision must be pinned and the evidence must be collected
from the same candidate.

| Subject | Exact identity (SHA, digest, or version) | Evidence reference / date | Status |
|---|---|---|---|
| Restricted runtime source | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Runtime contract and policy schema | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Gateway / edge image | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Conversation / runtime image | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Clinical adapter image | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Mattermost server image | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Health-Record-Hub source/API/migrations | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Provider, model, endpoint, region, revision | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Policy epoch/digest and authorization artifact | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Dependency locks and base-image digests | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Deployment/IaC and host/OS/runtime | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |

## 3. Allowed flow and disabled surfaces

### Allowed clinical-personnel flow

This is the bounded flow proposed for this decision; it is not an external
authorization claim:

1. An authenticated, approved clinical staff member uses an allowlisted private
   two-party Mattermost direct channel.
2. The member sends the exact signed command and canonical patient identifier.
3. The edge validates actor/channel membership, command grammar, policy identity,
   expiry, and request identity, then commits the encrypted durable record.
4. A dedicated adapter reaches only the exact allowlisted HRH clinical-read
   endpoint over the approved private boundary.
5. Only the closed response projection is accepted; before disclosure, source,
   membership, and delivery authorization are checked again.
6. The response is posted only to the original approved source/root under the
   documented ambiguity, retention, and recovery rules.

### Disabled unless separately reviewed

Normal Hermes agent prompting; tools, plugins, MCP, skills, shell, browser,
memory, compression, fallback, retries, streaming, attachments, OCR, vision,
arbitrary model selection; public/group channels, federation, webhooks, email,
SMS, unmanaged clients, arbitrary Mattermost membership; arbitrary HRH routes,
bulk/export operations, unrestricted database access, cross-tenant access; and
provider/network paths outside the signed allowlist are all disabled. No PHI is
permitted before an effective `GO`.

## 4. Named decision roles

Names and authority must be supplied; they cannot be inferred from repository
ownership, code authorship, GitHub identity, or a contract with another party.

| Role | Person / organization | Authority / scope | Signature or record | Status |
|---|---|---|---|---|
| Technical deployment operator | `UNRESOLVED` | Runs and maintains exact deployment | `UNRESOLVED` | `UNRESOLVED` |
| Security / risk owner | `UNRESOLVED` | Accepts residual operational/security risk | `UNRESOLVED` | `UNRESOLVED` |
| Privacy / legal decision owner | `UNRESOLVED` | Decides privacy, contractual, and legal prerequisites | `UNRESOLVED` | `UNRESOLVED` |
| Clinical / product decision owner | `UNRESOLVED` | Approves purpose, users, and clinical boundary | `UNRESOLVED` | `UNRESOLVED` |
| Independent technical reviewer | `UNRESOLVED` | Reviews exact candidate independently | `UNRESOLVED` | `UNRESOLVED` |
| Pilot approver | `UNRESOLVED` | Signs final bounded pilot decision | `UNRESOLVED` | `UNRESOLVED` |

## 5. Evidence register

Technical hardening, independent evaluation, and external/operator acceptance
are separate evidence classes. One cannot substitute for another.

### 5.1 Product-controlled technical evidence

| Control | Exact test/receipt bound to candidate | Status |
|---|---|---|
| Closed imports, image separation, and artifact provenance | `UNRESOLVED` | `UNRESOLVED` |
| Mattermost actor/channel/root and disclosure fences | `UNRESOLVED` | `UNRESOLVED` |
| HRH adapter route and credential separation | `UNRESOLVED` | `UNRESOLVED` |
| Fail-closed malformed, timeout, partial, and provider error behavior | `UNRESOLVED` | `UNRESOLVED` |
| Durable idempotency, crash, ambiguity, and recovery | `UNRESOLVED` | `UNRESOLVED` |
| Negative cross-user, cross-channel, cross-patient, and cross-tenant tests | `UNRESOLVED` | `UNRESOLVED` |
| Logging/privacy-sink behavior | `UNRESOLVED` | `UNRESOLVED` |

### 5.2 Independent evaluation

| Required item | Evidence | Status |
|---|---|---|
| Reviewer identity, independence, and conflict statement | `UNRESOLVED` | `UNRESOLVED` |
| Review against every exact subject in section 2 | SHA/digest comparison | `UNRESOLVED` |
| Real reachable paths exercised, not helper-only fixtures | commands/report | `UNRESOLVED` |
| Findings, objections, residual risks, and unverified claims recorded | report | `UNRESOLVED` |
| Reviewer disposition | `ACCEPT` / `ACCEPT WITH CONDITIONS` / `REQUEST CHANGES` | `UNRESOLVED` |

A review of an older SHA is historical context and cannot close this gate.

### 5.3 External/operator acceptance

| External evidence | Artifact, owner, exact revision/date | Status |
|---|---|---|
| IAM principals, least privilege, and denial tests | `UNRESOLVED` | `UNRESOLVED` |
| IPv4/IPv6/DNS/proxy/literal/metadata/media egress enforcement | `UNRESOLVED` | `UNRESOLVED` |
| Provider/model region, retention, logging, and training posture | `UNRESOLVED` | `UNRESOLVED` |
| Contract/BAA or equivalent organizational decision | `UNRESOLVED` | `UNRESOLVED` |
| Secret creation, custody, rotation, revocation, backup, destruction | `UNRESOLVED` | `UNRESOLVED` |
| Mattermost and HRH backup/restore evidence | `UNRESOLVED` | `UNRESOLVED` |
| Audit collection, review, retention, and deletion | `UNRESOLVED` | `UNRESOLVED` |
| Incident response, escalation, and contact path | `UNRESOLVED` | `UNRESOLVED` |
| Exact-host recovery and rollback test | `UNRESOLVED` | `UNRESOLVED` |
| Workforce identity/access review and clinical roster | `UNRESOLVED` | `UNRESOLVED` |

These facts are external and must not be manufactured by this repository.

## 6. Residual risks and nonclaims

| Residual risk | Owner | Treatment / acceptance record | Status |
|---|---|---|---|
| `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |

At minimum consider host compromise, socket namespace control, trusted time,
backup integrity, broker honesty, Mattermost availability, HRH correctness,
ambiguous delivery, and retention/deletion failures.

This record does not claim HIPAA compliance, PHI readiness, legal approval, BAA
coverage, provider approval, model attestation, host/network/physical/workforce
controls, incident readiness, or production authorization. Green CI, an SBOM,
a signature, or a synthetic test is not such proof.

## 7. Pilot limits and rollback

| Control | Required value |
|---|---|
| Maximum named users / roster | `UNRESOLVED` |
| Allowed Mattermost team/channel/DM set | `UNRESOLVED` |
| Allowed operation and patient projection | `UNRESOLVED` |
| PHI fields allowed | `UNRESOLVED` — none until effective `GO` |
| Pilot dates and review checkpoints | `UNRESOLVED` |
| Monitoring and alert owner | `UNRESOLVED` |
| Stop triggers | `UNRESOLVED` |
| Tested rollback revision/procedure | `UNRESOLVED` |
| Credential revocation | `UNRESOLVED` |
| Data deletion/retention action | `UNRESOLVED` |

Rollback must stop the edge, revoke/disable credentials, preserve required
audit records, and define treatment of in-flight or ambiguous requests. An
untested rollback is not evidence of recovery.

## 8. Independent decision

**Reviewer:** `UNRESOLVED`  
**Organization / conflict statement:** `UNRESOLVED`  
**Exact candidate reviewed:** `UNRESOLVED`  
**Report:** `UNRESOLVED`  
**Reviewer disposition:** `UNRESOLVED`

**Conditions:** `UNRESOLVED`  
**Decision rationale:** `UNRESOLVED`

## 9. Fail-closed gate

| Gate | Required condition | Result |
|---|---|---|
| Candidate binding | All subjects and evidence match section 2 exactly | `UNRESOLVED` |
| Technical hardening | Mandatory reachable-path controls pass | `UNRESOLVED` |
| Independent review | Named reviewer closes or explicitly accepts blockers | `UNRESOLVED` |
| Ownership and sign-off | All roles in section 4 are named and signed | `UNRESOLVED` |
| External controls | All section 5.3 evidence is attributable and current | `UNRESOLVED` |
| Pilot containment | Scope, monitoring, stop, rollback, and retention are tested | `UNRESOLVED` |
| Nonclaims | No unsupported authorization or compliance claim appears | `UNRESOLVED` |

If any mandatory row is `UNRESOLVED`, `MISSING`, `FAILED`, or bound to another
candidate, the effective decision is `NO-GO` for PHI. `GO WITH CONDITIONS` cannot
waive a mandatory row. `GO` requires every row to be `PASS`, all signatures, and
a compatible independent-review disposition.

## 10. Final sign-off

| Signatory | Name / organization | Decision | Signature / record | Date |
|---|---|---|---|---|
| Technical deployment operator | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Security / risk owner | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Privacy / legal decision owner | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Clinical / product decision owner | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Independent reviewer | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |
| Pilot approver | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` | `UNRESOLVED` |

**Effective decision:** `NO-GO`  
**Reason:** mandatory evidence and sign-offs are unresolved.  
**Next review trigger:** `UNRESOLVED`
