# Integrated A0 preflight — 2026-09-11

**Evidence frame:** `eaf69e401b7f15bb3f051c5fd87644a36756ef5a`
**Hosted verification:** [CI run #145](https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/34630158194) — success
**Data class:** synthetic, non-PHI only

## What passed

1. The composed Mattermost → restricted runtime → HRH harness completed on
   runtime subject `e1d92dae8de161b189415cf94ab163802bbc10f6`, producing
   [the retained receipt](clinical-composed-receipt-2026-09-11-integrated.json).
   It exercised boundary isolation, restricted identities, authorization and
   revocation, source deletion, crash ambiguity/recovery, final denial sweep,
   and content-safe output scanning.
2. The hosted run above passed Python 3.11 contracts, Python 3.12 contracts,
   and the synthetic Linux/container E2E on this evidence frame.
3. Local focused validation passed: 727 tests with 11 documented POSIX-only
   skips; the egress collector unit suite passed 85 tests with one Linux-only
   skip; cold-recovery lifecycle/static controls passed 60 tests with two
   documented POSIX-only skips.
4. The integrated ledger was reset to explicit fresh inputs. It has no
   historical candidate/receipt default and has 14 focused green controls for
   source provenance, receipt retention, and mutation rejection.

## Deliberate limits

- The composed witness ran Linux containers from Docker Desktop. It is useful
  synthetic runtime evidence, but it is not P2 representative-host evidence.
- P2 host admission denied the current Windows host before collection. The
  egress and cold-recovery real collectors remain unrun here because they
  require a non-WSL Linux host by contract.
- No aggregate A0 ledger exists yet: the independent fresh egress receipt is
  still missing. No immutable tag, OCI publication, deployment, PHI,
  compliance, or pilot claim follows from this preflight.

## Next minimum dependency

Run `tests/deployment/test_representative_clinical_egress.sh` and the
cold-recovery E2E from a clean, non-WSL Ubuntu 24.04 x86_64 host with Docker
Engine/Compose. The run must use only synthetic inputs and a clean checkout;
its resulting receipts become explicit inputs to the integrated ledger rather
than being inferred from this preflight.
