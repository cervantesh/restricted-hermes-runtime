# A0 Windows clean-replay closure card

**Frame:** `A0-WINDOWS-REPLAY v1`
**Candidate:** `6bc01cbccb5f701e18ef8632eb1f0747e6451f26`
**Immutable tag:** `immutable-candidate-2026-09-11-6bc01cb`
**Published workflow:** [run 34650455783](https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/34650455783)

## Strict scope

The A0 artifact verifier must consume GitHub CLI JSON deterministically on
Windows. `gh` emits UTF-8 JSON, while Python's default `text=True` decoding can
use the active Windows code page. A valid UTF-8 byte sequence containing a byte
undefined by that code page caused the verifier to terminate before it could
return a validation result.

The verifier now requests UTF-8 explicitly and treats decoding failure as an
unavailable external attestation check. This is fail-closed: the command exits
non-zero and does not expose provider output.

## Closure evidence

| Requirement | Evidence |
| --- | --- |
| UTF-8 is explicit at all `gh` JSON boundaries in the verifier | `tests/static/test_immutable_candidate_supply_chain.py::test_live_attestation_verifier_binds_exact_subject_workflow_source_and_predicate` |
| A decode failure does not crash or pass | `tests/static/test_immutable_candidate_supply_chain.py::test_live_attestation_verifier_fails_closed_when_cli_utf8_decode_fails` |
| The published A0 evidence replays from a clean detached checkout on Windows | `python tools/verify_immutable_candidate.py candidate-subjects/candidate.manifest.json --repo-root <clean-candidate-checkout> --closed-subjects-only` — `PASS` |

## Non-goals and limits

- This does not alter the immutable candidate, published image subjects, or
  source tag.
- It does not claim PHI authorization, HIPAA compliance, BAA coverage, or
  production deployment conformance.
- Live GitHub attestation verification remains an external dependency; a
  timeout, unavailable CLI, malformed response, or decode error is a failure,
  never an acceptance signal.
