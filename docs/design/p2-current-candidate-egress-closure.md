# P2 current-candidate egress collector closure card

## Risk reduced

The reconciled composed candidate has a content-safe egress receipt validator,
but no representative-host collector bound to its current source frame.  A
collector inherited from an earlier line names a different frozen HRH subject;
using it unchanged could make a valid-looking P2 receipt describe the wrong
candidate.

## Exact scope

Derive the representative egress collector and its tests from the prior
implementation only after rebinding every candidate assertion to the composed
candidate at `67a89b8662e3f37775306f6078ca470373b62062` and its already
enforced HRH frame:

- HRH head: `ad13735e9881a48580a9e138daac137f8c865dea`;
- HRH tree: `f217b0b1cf7f438422528dfe178d81b78212c68b`.

The collector may emit only canonical, content-safe proof digests and bounded
outcomes. It must not serialize probe endpoints, command output, environment
values, logs, credentials, or payloads.

## Closure criteria

1. A marker produced by the current `clinical_staging.py` source frame is
   accepted by the collector.
2. The prior historical HRH frame is rejected even when runtime head and tree
   match.
3. The existing RED/GREEN network, container-control, image-binding and cleanup
   receipt checks remain covered by focused tests.
4. A real representative Linux host run is explicitly *not* claimed by this
   slice. The runbook may remain draft until the candidate and host are both
   admissible under #31.

## Non-goals

This does not designate an A0 candidate, change the composed recovery
contract, create cloud infrastructure, run a representative-host witness,
authorize PHI, or make an A1 decision.
