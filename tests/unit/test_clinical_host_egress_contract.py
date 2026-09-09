"""Byte-only EL01/EL14-EL17 preparation, not a host or enforcement witness.

EL10 and full EL13 remain MISSING: no row-result schema, effect/host attribution
or loader/symlink custody is invented. EL02-EL09/EL11-EL12 deployment effects
and every H observation remain MISSING/BLOCKED. EL12 linkage alone is tested.
Network order is network_id ascending, adjudicated from contract 3810cc1c.
"""

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
BEFORE = "platform/generation.before.json"
AFTER = "platform/generation.after.json"
RESULT = "platform/result.json"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


@pytest.fixture
def parser():
    path = ROOT / "tools/clinical_host_egress_contract.py"
    spec = importlib.util.spec_from_file_location("egress_contract_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def packet():
    generation = {
        "schema": "restricted-clinical-platform-generation.v1", "mode": "published",
        "candidate_id": "sha256:" + "1" * 64, "policy": {"epoch": "Synthetic/Epoch-1", "digest": "2" * 64},
        "compose_sha256": "3" * 64, "resolver_sha": "4" * 40, "project": "clinical_test",
        "state_id": "state_1", "host_baseline_sha256": "5" * 64, "enforcement_sha256": "6" * 64,
        "workloads": [{"service": "operator-proxy", "container_id": "7" * 64,
            "image_id": "sha256:" + "8" * 64, "image_digest": "sha256:" + "9" * 64,
            "started_at": "2026-09-07T12:00:00.123456789Z",
            "networks": [{"network_id": "a" * 64, "name_sha256": "b" * 64, "internal": False}]}],
    }
    files = {BEFORE: canonical(generation), AFTER: canonical(generation),
        RESULT: b'{"synthetic":"parser-fixture-only-not-an-effect-proof"}\n'}
    producer = {"id": "synthetic-runner", "run_id": "synthetic-run-1", "engine": "Py", "toolchain_sha256": "c" * 64}
    witness = {
        "schema": "restricted-clinical-egress-witness.v1", "scope": "SYNTHETIC_NON_PHI_ONLY",
        "contract_sha256": "d" * 64, "candidate_manifest_sha256": "e" * 64,
        "mode": "published", "producer": producer, "host_baseline_sha256": "5" * 64,
        "generation": {"operation": "observe", "before_sha256": "", "after_sha256": "", "parent_sha256": None},
        "observations": [{"id": f"EL{index:02}", "outcome": "NOT_VERIFIED",
            "diagnostic": "host-not-observed", "proof_sha256s": []} for index in range(1, 18)],
        "witness_files": [],
    }
    expected = {"expected_before": files[BEFORE], "expected_after": files[AFTER],
        "expected_contract_sha256": witness["contract_sha256"],
        "expected_candidate_manifest_sha256": witness["candidate_manifest_sha256"],
        "expected_producer": deepcopy(producer), "expected_operation": "observe", "restarted_services": ()}
    return witness, files, expected


def refresh(packet):
    witness, files, _ = packet
    witness["generation"].update(before_sha256=digest(files[BEFORE]), after_sha256=digest(files[AFTER]))
    witness["witness_files"] = [{"path": path, "sha256": digest(data), "size": len(data),
        "media_type": "application/json"} for path, data in sorted(files.items())]


def validate(parser, packet, *, refresh_manifest=True):
    if refresh_manifest:
        refresh(packet)
    witness, files, expected = packet
    return parser.validate_witness(canonical(witness), files, **expected)


def change_generation(packet, change, *, both=True, expected=False):
    _, files, frame = packet
    for name in (BEFORE, AFTER) if both else (AFTER,):
        value = json.loads(files[name])
        change(value)
        files[name] = canonical(value)
        if expected:
            frame["expected_before" if name == BEFORE else "expected_after"] = files[name]


def claim(packet, row="EL15", outcome="PASS", diagnostic="none"):
    witness, files, _ = packet
    entry = next(item for item in witness["observations"] if item["id"] == row)
    entry.update(outcome=outcome, diagnostic=diagnostic, proof_sha256s=[digest(files[RESULT])])
    return entry


def test_parser_acceptance_does_not_promote_unverified_effects(parser, packet):
    before = deepcopy(packet)
    assert validate(parser, packet) is None
    assert all(row["outcome"] == "NOT_VERIFIED" for row in packet[0]["observations"])
    assert packet[2] == before[2]


def test_public_generation_validator_binds_independent_frame(parser, packet):
    raw = packet[1][BEFORE]
    assert parser.validate_generation_bytes(
        raw,
        expected_mode="published",
        expected_candidate_id="sha256:" + "1" * 64,
        expected_services=("operator-proxy",),
    ) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("expected_mode", "source-build"),
        ("expected_candidate_id", "sha256:" + "0" * 64),
        ("expected_services", ("other-service",)),
    ],
)
def test_public_generation_validator_rejects_frame_substitution(
    parser, packet, field, value
):
    expected = {
        "expected_mode": "published",
        "expected_candidate_id": "sha256:" + "1" * 64,
        "expected_services": ("operator-proxy",),
    }
    expected[field] = value
    with pytest.raises(parser.ContractError):
        parser.validate_generation_bytes(packet[1][BEFORE], **expected)


@pytest.mark.parametrize("field", ["candidate_id", "mode", "policy", "compose_sha256", "resolver_sha", "project", "state_id", "host_baseline_sha256", "enforcement_sha256", "workloads"])
def test_identity_or_mode_substitution_rejected(parser, packet, field):
    replacements = {"candidate_id": "sha256:" + "0" * 64, "mode": "source-build",
        "policy": {"epoch": "different", "digest": "0" * 64}, "resolver_sha": "0" * 40,
        "project": "other", "state_id": "other", "workloads": []}
    change_generation(packet, lambda value: value.update({field: replacements.get(field, "0" * 64)}))
    with pytest.raises(parser.ContractError):
        validate(parser, packet)


@pytest.mark.parametrize("field", ["contract_sha256", "candidate_manifest_sha256", "mode", "host_baseline_sha256", "producer"])
def test_root_identity_substitution_rejected(parser, packet, field):
    packet[0][field] = "source-build" if field == "mode" else ({**packet[0]["producer"], "run_id": "mixed-run"} if field == "producer" else "0" * 64)
    with pytest.raises(parser.ContractError):
        validate(parser, packet)


@pytest.mark.parametrize("mode", ["source", "Published", "SOURCE-BUILD", "", "unknown"])
def test_mode_enum_has_no_aliases(parser, packet, mode):
    packet[0]["mode"] = mode
    change_generation(packet, lambda value: value.update(mode=mode), expected=True)
    with pytest.raises(parser.ContractError):
        validate(parser, packet)


def test_source_build_nullable_digest_is_not_published_authority(parser, packet):
    packet[0]["mode"] = "source-build"
    def source(value):
        value["mode"] = "source-build"
        value["workloads"][0]["image_digest"] = None
    change_generation(packet, source, expected=True)
    assert validate(parser, packet) is None
    packet[0]["mode"] = "published"
    change_generation(packet, lambda value: value.update(mode="published"), expected=True)
    with pytest.raises(parser.ContractError):
        validate(parser, packet)


@pytest.mark.parametrize("mutation", ["missing", "bom", "spaces", "no-lf", "extra-lf", "duplicate-key", "float", "nan", "unknown-field", "stale-hash"])
def test_generation_files_are_retained_canonical_and_recomputed(parser, packet, mutation):
    refresh(packet)
    files = packet[1]
    if mutation == "missing":
        del files[BEFORE]
    elif mutation == "bom":
        files[BEFORE] = b"\xef\xbb\xbf" + files[BEFORE]
    elif mutation == "spaces":
        files[BEFORE] = json.dumps(json.loads(files[BEFORE]), indent=2).encode() + b"\n"
    elif mutation == "no-lf":
        files[BEFORE] = files[BEFORE][:-1]
    elif mutation == "extra-lf":
        files[BEFORE] += b"\n"
    elif mutation == "duplicate-key":
        files[BEFORE] = files[BEFORE].replace(b'{"candidate_id":', b'{"mode":"published","candidate_id":', 1)
    elif mutation in {"float", "nan"}:
        files[BEFORE] = files[BEFORE].replace(b'"internal":false', b'"internal":' + (b"1.0" if mutation == "float" else b"NaN"))
    elif mutation == "unknown-field":
        change_generation(packet, lambda value: value.update(extra=True))
    else:
        packet[0]["generation"]["before_sha256"] = "0" * 64
    with pytest.raises(parser.ContractError):
        validate(parser, packet, refresh_manifest=False)


@pytest.mark.parametrize("mutation", ["observe-changed", "observe-parent", "restart-parent", "restart-unchanged", "restart-profile", "restart-workload-unclaimed"])
def test_observe_equality_and_restart_parent_binding(parser, packet, mutation):
    witness, files, expected = packet
    if mutation.startswith("restart"):
        witness["generation"]["operation"] = expected["expected_operation"] = "restart"
        expected["restarted_services"] = ("operator-proxy",)
        witness["generation"]["parent_sha256"] = digest(files[BEFORE])
    if mutation not in {"observe-parent", "restart-unchanged"}:
        change_generation(packet, lambda value: value["workloads"][0].update(started_at="2026-09-07T12:01:00.123456789Z"), both=False, expected=True)
    if mutation in {"observe-parent", "restart-parent"}:
        witness["generation"]["parent_sha256"] = "0" * 64
    if mutation == "restart-profile":
        change_generation(packet, lambda value: value.update(enforcement_sha256="f" * 64), both=False, expected=True)
    if mutation == "restart-workload-unclaimed":
        expected["restarted_services"] = ()
    claim(packet, row="EL12")
    with pytest.raises(parser.ContractError):
        validate(parser, packet)


@pytest.mark.parametrize("success", [False, True])
def test_restart_linkage_accepts_failed_same_generation_or_changed_success(parser, packet, success):
    witness, files, expected = packet
    witness["generation"].update(operation="restart", parent_sha256=digest(files[BEFORE]))
    expected.update(expected_operation="restart", restarted_services=("operator-proxy",))
    claim(packet, "EL12", "PASS" if success else "FAIL", "none" if success else "enforcement-incomplete")
    if success:
        change_generation(packet, lambda value: value["workloads"][0].update(started_at="2026-09-07T12:01:00.123456789Z"), both=False, expected=True)
    assert validate(parser, packet) is None  # Structural claim only; effect remains unverified.


@pytest.mark.parametrize("mutation", ["empty-pass", "empty-fail", "unresolved", "duplicate", "unsorted", "too-many", "generation-only", "invented-not-verified", "not-applicable", "missing-diagnostic", "pass-ambiguous"])
def test_observation_proofs_resolve_with_status_cardinality(parser, packet, mutation):
    row = claim(packet)
    if mutation.startswith("empty"):
        row["proof_sha256s"] = []
        if mutation == "empty-fail":
            row.update(outcome="FAIL", diagnostic="identity-mismatch")
    elif mutation == "unresolved":
        row["proof_sha256s"] = ["0" * 64]
    elif mutation == "duplicate":
        row["proof_sha256s"] *= 2
    elif mutation == "unsorted":
        row["proof_sha256s"] = sorted([digest(packet[1][BEFORE]), digest(packet[1][RESULT])], reverse=True)
    elif mutation == "too-many":
        row["proof_sha256s"] = [f"{index:064x}" for index in range(65)]
    elif mutation == "generation-only":
        row["proof_sha256s"] = [digest(packet[1][BEFORE])]
    elif mutation == "invented-not-verified":
        row.update(outcome="NOT_VERIFIED", diagnostic="host-not-observed")
    elif mutation == "not-applicable":
        row["outcome"] = "NOT_APPLICABLE"
    elif mutation == "missing-diagnostic":
        row.update(outcome="NOT_VERIFIED", diagnostic="none", proof_sha256s=[])
    else:
        row["diagnostic"] = "ambiguous-denial"
    with pytest.raises(parser.ContractError):
        validate(parser, packet)


@pytest.mark.parametrize("mutation", ["traversal", "absolute", "backslash", "empty-part", "duplicate", "undeclared", "bad-size", "bool-size", "wrong-hash", "unknown-field", "root-as-member"])
def test_witness_file_manifest_is_closed(parser, packet, mutation):
    refresh(packet)
    witness, files, _ = packet
    entries = witness["witness_files"]
    if mutation in {"traversal", "absolute", "backslash", "empty-part", "root-as-member"}:
        name = {"traversal": "../proof", "absolute": "/proof", "backslash": "platform\\proof", "empty-part": "platform//proof", "root-as-member": "platform/egress-witness.v1.json"}[mutation]
        files[name] = files.pop(RESULT)
        refresh(packet)
    elif mutation == "duplicate":
        entries.append(deepcopy(entries[0]))
    elif mutation == "undeclared":
        files["platform/extra.json"] = b"{}\n"
    elif mutation == "bad-size":
        entries[0]["size"] = 0
    elif mutation == "bool-size":
        entries[0]["size"] = True
    elif mutation == "wrong-hash":
        entries[0]["sha256"] = "0" * 64
    else:
        entries[0]["extra"] = True
    with pytest.raises(parser.ContractError):
        validate(parser, packet, refresh_manifest=False)


@pytest.mark.parametrize("target", ["root", "producer", "generation", "observation", "policy", "workload", "network"])
def test_unknown_or_extra_fields_fail_closed(parser, packet, target):
    if target in {"root", "producer", "generation", "observation"}:
        objects = {"root": packet[0], "producer": packet[0]["producer"], "generation": packet[0]["generation"], "observation": packet[0]["observations"][0]}
        objects[target]["unexpected"] = True
    else:
        def mutate(value):
            objects = {"policy": value["policy"], "workload": value["workloads"][0], "network": value["workloads"][0]["networks"][0]}
            objects[target]["unexpected"] = True
        change_generation(packet, mutate, expected=True)
    with pytest.raises(parser.ContractError):
        validate(parser, packet)


@pytest.mark.parametrize("mutation", ["bad-date", "missing-nanos", "numeric-boolean", "duplicate-workload", "duplicate-network"])
def test_generation_scalar_and_inventory_validation(parser, packet, mutation):
    def mutate(value):
        workload = value["workloads"][0]
        if mutation == "bad-date":
            workload["started_at"] = "2026-02-30T12:00:00.000000000Z"
        elif mutation == "missing-nanos":
            workload["started_at"] = "2026-09-07T12:00:00Z"
        elif mutation == "numeric-boolean":
            workload["networks"][0]["internal"] = 0
        elif mutation == "duplicate-workload":
            value["workloads"].append(deepcopy(workload))
        else:
            workload["networks"].append(deepcopy(workload["networks"][0]))
    change_generation(packet, mutate, expected=True)
    with pytest.raises(parser.ContractError):
        validate(parser, packet)


def test_error_messages_do_not_echo_untrusted_content(parser, packet):
    packet[0]["mode"] = "synthetic-credential-sentinel"
    with pytest.raises(parser.ContractError) as error:
        validate(parser, packet)
    assert "synthetic-credential-sentinel" not in str(error.value)


def test_network_order_uses_network_id_not_hashed_name(parser, packet):
    def add_network(value):
        value["workloads"][0]["networks"].append({"network_id": "c" * 64, "name_sha256": "b" * 64, "internal": True})
    change_generation(packet, add_network, expected=True)
    assert validate(parser, packet) is None
    change_generation(packet, lambda value: value["workloads"][0]["networks"].reverse(), expected=True)
    with pytest.raises(parser.ContractError, match="network-order"):
        validate(parser, packet)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unsorted", "unknown"])
def test_observation_inventory_cannot_omit_missing_work(parser, packet, mutation):
    rows = packet[0]["observations"]
    if mutation == "missing":
        rows.pop()
    elif mutation == "duplicate":
        rows[-1] = deepcopy(rows[0])
    elif mutation == "unsorted":
        rows.reverse()
    else:
        rows[-1]["id"] = "H05"
    with pytest.raises(parser.ContractError):
        validate(parser, packet)


def test_retained_paths_or_asserted_hashes_cannot_substitute_file_bytes(parser, packet):
    refresh(packet)
    for substitute in (Path("unread-source"), digest(packet[1][RESULT]), {"sha256": digest(packet[1][RESULT])}):
        packet[1][RESULT] = substitute
        with pytest.raises(parser.ContractError, match="witness-file-bytes"):
            validate(parser, packet, refresh_manifest=False)


def test_row_proof_can_reference_retained_bytes_without_becoming_host_pass(parser, packet):
    original = digest(packet[1][RESULT])
    link = canonical({"retained_sha256": original, "synthetic_only": True})
    packet[1]["platform/link.json"] = link
    claim(packet)["proof_sha256s"] = [digest(link)]
    assert validate(parser, packet) is None
    assert packet[0]["observations"][9]["outcome"] == "NOT_VERIFIED"  # EL10 stays missing.


@pytest.mark.parametrize("value", [None, "synthetic-sensitive-value", []])
def test_expected_producer_must_be_explicit_mapping(parser, packet, value):
    packet[2]["expected_producer"] = value
    with pytest.raises(parser.ContractError) as error:
        validate(parser, packet)
    assert "synthetic-sensitive-value" not in str(error.value)


def test_json_canonicalization_requires_ascii_escapes_and_preserves_epoch(parser, packet):
    change_generation(packet, lambda value: value["policy"].update(epoch="Synthetïc/Epoch-1"), expected=True)
    assert validate(parser, packet) is None
    packet[1][BEFORE] = packet[1][BEFORE].replace(b"\\u00ef", "ï".encode())
    with pytest.raises(parser.ContractError, match="json-canonical"):
        validate(parser, packet)
