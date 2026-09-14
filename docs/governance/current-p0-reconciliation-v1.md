# Current P0 reconciliation closure card v1

Status: `active`  
Issue: #35  
Base candidate: `0ab0afd833c768b8e3ce58d346f4271f83d5ee37`  
Base tag: `immutable-candidate-2026-09-14-p2-conformance-v2`  
Historical integration input: #21 at `c3f012d7fae7ed8af27daadbfc2dd9db90d7e171`  
Common ancestor: `2f6f116e2818189c436cb51b547cd01bd285f94e`

## Strict scope

Produce one draft candidate on the current admitted-subject line that preserves
the bounded #35 behaviors: serialized lifecycle, TLS enforcement, immutable
subject admission, secret-safe bootstrap, duplicate-averse delivery,
authorization revalidation, effective egress, and cold recovery. Historical
receipts remain historical unless replayed on the resulting exact head.

This card does not create a representative-host receipt, A0/A1 decision,
PHI authorization, production deployment, HIPAA/BAA claim, or external
application publication claim.

## Source audit

| Boundary | Current source finding | Historical #21 finding | Disposition |
| --- | --- | --- | --- |
| Delivery and reauthorization | `src/restricted_runtime/mattermost_ingress.py` has identical content in both heads | Same implementation | Reuse; prove in the composed candidate. |
| TLS, immutable subjects, source ledger, and P2 admission | Present on the current ancestry | Earlier form exists in #21 | Preserve current source; do not overwrite with historical receipts. |
| Effective egress | Current collector/witness is candidate-derived | #21 carries an older source-bound witness | Re-derive and replay against the final candidate. |
| Cold backup/restore | `clinical_backup_bundle.py`, `clinical_operator_lock.py`, and cold-recovery E2E are absent | Present, but coupled to older lifecycle semantics | Required semantic integration; no blind transfer. |
| Shared lifecycle/harness | `clinical_staging.py` differs materially: current source is 1,403 lines; historical source is 1,771 lines | Contains recovery paths absent from current source | Required semantic integration; current admission and sealed-subject invariants remain authoritative. |

The trial merge reported 19 add/add conflicts in shared staging, composition,
candidate, and test contracts plus the two new cold-recovery modules. It was
aborted without a commit. Therefore this work is not mechanical and #21 cannot
be merged or relabeled as validation of this candidate.

## Observable closure predicates

1. The final source has one serialized lifecycle authority. Concurrent
   backup/restore/finalization attempts are rejected or serialized through the
   same durable operator boundary.
2. A cold backup contains only the declared, owned state; malformed, linked,
   foreign, or substituted archive material fails before restoration.
3. A restart during delivery preserves the existing terminal-state distinction:
   known reauthorization rejection becomes `BLOCKED`; an unknown result becomes
   content-erased `AMBIGUOUS`; neither posts after the prohibited boundary.
4. The current source/HRH/OCI-subject vector remains admitted before lifecycle
   mutation. A historical or substituted vector fails closed.
5. All egress and recovery evidence is replayed on the exact final candidate,
   with cleanup of owned synthetic resources and no raw secrets in receipts.

## Required evidence

- focused RED/GREEN tests for every transferred cold-recovery boundary;
- composed synthetic E2E on the final exact head;
- immutable publication and live-attestation verification for that exact head;
- a candidate ledger naming inherited inputs without relabeling old runs;
- an independent review of the final composition.

## Implementation order

1. Add the cold-recovery codec and operator lock as isolated, tested
   dependencies without changing the current lifecycle behavior.
2. Integrate lifecycle entry points and cold backup/restore transitions while
   retaining current subject admission and sealed environment checks.
3. Compose the existing delivery, egress, TLS, and subject controls with the
   new recovery path; add a final candidate-bound evidence ledger.
4. Freeze, publish, and replay the composed candidate. Only after that may
   #31 re-derive its real-host collector/runbook.

## Falsifiers

- A transfer that weakens current subject admission, sealed environment, or
  public-output controls is rejected even if cold recovery passes.
- A cold-recovery test that only calls helpers, rather than exercising the
  staging lifecycle and a restart boundary, is insufficient.
- A receipt naming another source, tree, immutable subject, or retained
  historical run cannot satisfy this card.
