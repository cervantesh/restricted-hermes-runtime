"""RED oracle for a pure clinical platform-generation constructor.

Contracts: clinical-host-egress-contract.v1.md and
clinical-supervision-contract.v1.md at 3810cc1c. Their checked-out SHA-256
values are pinned below. Fixtures are synthetic and supply independent inputs;
the future constructor must not inspect Docker or derive authority from a
witness. No host, enforcement, PHI, production, or compliance claim is made.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "tools" / "build_clinical_platform_generation.py"
EGRESS_PARSER = ROOT / "tools" / "clinical_host_egress_contract.py"
SUPERVISION_PARSER = ROOT / "tools" / "clinical_supervision_contract.py"
BEFORE = "platform/generation.before.json"
AFTER = "platform/generation.after.json"
EGRESS_CONTRACT_SHA256 = "2e407f94925f3f6af1ebd1388de66ca28fab595d1327adf4c71441973a3651a0"
SUPERVISION_CONTRACT_SHA256 = "0fbd857f0802bcc1593174ac622264d30ba23d9cbf9611a3af0cd538aca60cb7"
CANDIDATE = "sha256:" + "1" * 64
WEB_SUBJECT = "registry.example/clinical/web@sha256:" + "2" * 64
INGRESS_SUBJECT = "registry.example/clinical/ingress@sha256:" + "3" * 64


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def builder():
    assert BUILDER.is_file(), "RED: pure platform-generation constructor is not implemented"
    return load(BUILDER, "clinical_platform_generation_test")


def workload(
    service: str,
    *,
    container: str,
    image_id: str,
    image_digest: str | None,
    started_at: str = "2026-09-07T12:00:00.123456789Z",
    networks: list[dict[str, object]] | None = None,
):
    return {
        "service": service,
        "container_id": container,
        "image_id": image_id,
        "image_digest": image_digest,
        "started_at": started_at,
        "networks": networks
        if networks is not None
        else [
            {
                "network_id": "4" * 64,
                "name": "synthetic_internal",
                "internal": True,
            }
        ],
    }


def inputs(mode: str = "published"):
    web_digest = WEB_SUBJECT.split("@", 1)[1] if mode == "published" else None
    return {
        "mode": mode,
        "candidate_id": CANDIDATE,
        "policy": {"epoch": "Synthetic-Epoch-1", "digest": "5" * 64},
        "compose_bytes": b"services:\n  synthetic: {}\n",
        "resolver_sha": "6" * 40,
        "project": "clinical_test",
        "state_id": "state_1",
        "host_baseline_bytes": b'{"schema":"synthetic-host-baseline.v1"}\n',
        "enforcement_bytes": b'{"schema":"synthetic-enforcement.v1"}\n',
        "approved_subjects": {
            "hrh": WEB_SUBJECT,
            "ingress": INGRESS_SUBJECT,
        }
        if mode == "published"
        else {},
        "workloads": [
            workload(
                "ingress",
                container="7" * 64,
                image_id="sha256:" + "8" * 64,
                image_digest=INGRESS_SUBJECT.split("@", 1)[1]
                if mode == "published"
                else None,
                networks=[
                    {
                        "network_id": "9" * 64,
                        "name": "synthetic_operator_access",
                        "internal": False,
                    },
                    {
                        "network_id": "4" * 64,
                        "name": "synthetic_internal",
                        "internal": True,
                    },
                ],
            ),
            workload(
                "hrh",
                container="a" * 64,
                image_id="sha256:" + "b" * 64,
                image_digest=web_digest,
            ),
        ],
    }


def build(builder, before=None, after=None):
    before = deepcopy(before if before is not None else inputs())
    after = deepcopy(after if after is not None else before)
    return builder.build_generation_pair(before=before, after=after)


def decoded(pair, path):
    return json.loads(pair[path].decode("utf-8"))


def assert_canonical_pair(pair):
    assert set(pair) == {BEFORE, AFTER}
    for raw in pair.values():
        value = json.loads(raw.decode("utf-8"))
        assert raw == canonical(value)
        assert set(value) == {
            "schema",
            "mode",
            "candidate_id",
            "policy",
            "compose_sha256",
            "resolver_sha",
            "project",
            "state_id",
            "host_baseline_sha256",
            "enforcement_sha256",
            "workloads",
        }


def test_generation_pair_is_canonical_and_derived_from_independent_bytes(builder):
    source = inputs()
    pair = build(builder, source, source)
    assert_canonical_pair(pair)
    value = decoded(pair, BEFORE)
    assert pair[BEFORE] == pair[AFTER]
    assert value["compose_sha256"] == digest(source["compose_bytes"])
    assert value["host_baseline_sha256"] == digest(source["host_baseline_bytes"])
    assert value["enforcement_sha256"] == digest(source["enforcement_bytes"])

    byte_bindings = {
        "compose_bytes": "compose_sha256",
        "host_baseline_bytes": "host_baseline_sha256",
        "enforcement_bytes": "enforcement_sha256",
    }
    for source_field, result_field in byte_bindings.items():
        changed = deepcopy(source)
        changed[source_field] += f"# changed {source_field}\n".encode()
        changed_pair = build(builder, changed, changed)
        changed_value = decoded(changed_pair, BEFORE)
        assert changed_pair[BEFORE] == changed_pair[AFTER]
        assert changed_pair[BEFORE] != pair[BEFORE]
        assert changed_value[result_field] == digest(changed[source_field])
        for independent_source, independent_result in byte_bindings.items():
            if independent_source != source_field:
                assert changed_value[independent_result] == value[independent_result]

    renamed = deepcopy(source)
    network = renamed["workloads"][0]["networks"][0]
    network["name"] += "_renamed"
    renamed_pair = build(builder, renamed, renamed)
    renamed_value = decoded(renamed_pair, BEFORE)
    retained = next(
        row for row in renamed_value["workloads"] if row["service"] == renamed["workloads"][0]["service"]
    )
    renamed_network = next(row for row in retained["networks"] if row["network_id"] == network["network_id"])
    assert renamed_network["name_sha256"] == digest(network["name"].encode())
    assert renamed_pair[BEFORE] == renamed_pair[AFTER]
    assert renamed_pair[BEFORE] != pair[BEFORE]


def test_source_build_and_published_are_exact_distinct_modes(builder):
    published = build(builder, inputs("published"), inputs("published"))
    source = build(builder, inputs("source-build"), inputs("source-build"))
    assert decoded(published, BEFORE)["mode"] == "published"
    assert decoded(source, BEFORE)["mode"] == "source-build"
    assert next(row for row in decoded(source, BEFORE)["workloads"] if row["service"] == "hrh")["image_digest"] is None

    error = getattr(builder, "GenerationError", ValueError)
    for alias in ("source", "Published", "SOURCE-BUILD", "", "unknown"):
        changed = inputs()
        changed["mode"] = alias
        with pytest.raises(error):
            build(builder, changed, changed)


def test_source_build_accepts_mixed_local_and_pinned_observed_digests(builder):
    source = inputs("source-build")
    pinned = "sha256:" + "d" * 64
    source["workloads"][0]["image_digest"] = pinned

    pair = build(builder, source, source)
    value = decoded(pair, BEFORE)
    retained = {row["service"]: row for row in value["workloads"]}
    assert retained["ingress"]["image_digest"] == pinned
    assert retained["hrh"]["image_digest"] is None
    assert source["approved_subjects"] == {}

    error = getattr(builder, "GenerationError", ValueError)
    for invalid in (
        "registry.example/clinical/ingress:latest",
        "sha256:" + "D" * 64,
        "sha256:" + "d" * 63,
        "sha512:" + "d" * 64,
        "",
        7,
    ):
        changed = deepcopy(source)
        changed["workloads"][0]["image_digest"] = invalid
        with pytest.raises(error):
            build(builder, changed, changed)

    asserted = deepcopy(source)
    asserted["approved_subjects"] = {"ingress": INGRESS_SUBJECT}
    with pytest.raises(error):
        build(builder, asserted, asserted)


def test_workloads_and_networks_are_uniquely_and_stably_sorted(builder):
    forward = inputs()
    reverse = deepcopy(forward)
    reverse["workloads"].reverse()
    for row in reverse["workloads"]:
        row["networks"].reverse()
    first = build(builder, forward, forward)
    second = build(builder, reverse, reverse)
    assert first == second
    value = decoded(first, BEFORE)
    assert [row["service"] for row in value["workloads"]] == ["hrh", "ingress"]
    ingress = next(row for row in value["workloads"] if row["service"] == "ingress")
    assert [row["network_id"] for row in ingress["networks"]] == sorted(
        row["network_id"] for row in ingress["networks"]
    )
    assert all(set(row) == {"network_id", "name_sha256", "internal"} for row in ingress["networks"])
    assert all("synthetic_" not in json.dumps(row) for row in ingress["networks"])


def test_mutable_or_crossed_image_identity_is_rejected(builder):
    error = getattr(builder, "GenerationError", ValueError)
    valid = inputs()
    assert_canonical_pair(build(builder, valid, valid))
    mutations = []
    mutable = deepcopy(valid)
    mutable["workloads"][1]["image_digest"] = "registry.example/clinical/web:latest"
    mutations.append(mutable)
    crossed = deepcopy(valid)
    crossed["workloads"][1]["image_digest"] = INGRESS_SUBJECT.split("@", 1)[1]
    mutations.append(crossed)
    asserted_subject = deepcopy(valid)
    asserted_subject["approved_subjects"]["hrh"] = "registry.example/clinical/web:latest"
    mutations.append(asserted_subject)
    missing_published_digest = deepcopy(valid)
    missing_published_digest["workloads"][1]["image_digest"] = None
    mutations.append(missing_published_digest)
    for changed in mutations:
        with pytest.raises(error):
            build(builder, changed, changed)


def test_duplicate_network_or_cross_generation_identity_is_rejected(builder):
    error = getattr(builder, "GenerationError", ValueError)
    duplicate_network = inputs()
    duplicate_network["workloads"][0]["networks"].append(
        deepcopy(duplicate_network["workloads"][0]["networks"][0])
    )
    duplicate_workload = inputs()
    duplicate_workload["workloads"].append(deepcopy(duplicate_workload["workloads"][0]))
    duplicate_service = inputs()
    second = deepcopy(duplicate_service["workloads"][0])
    second["container_id"] = digest(canonical({"duplicate_service": second["service"]}))
    second["started_at"] = "2026-09-07T12:00:02.123456789Z"
    duplicate_service["workloads"].append(second)
    for duplicate in (duplicate_network, duplicate_workload, duplicate_service):
        with pytest.raises(error):
            build(builder, duplicate, duplicate)

    before, after = inputs(), inputs()
    after["candidate_id"] = "sha256:" + "f" * 64
    with pytest.raises(error):
        build(builder, before, after)
    after = inputs()
    after["mode"] = "source-build"
    after["approved_subjects"] = {}
    for row in after["workloads"]:
        row["image_digest"] = None
    with pytest.raises(error):
        build(builder, before, after)

    drift_cases = []
    policy = inputs()
    policy["policy"]["epoch"] += "-changed"
    drift_cases.append(policy)
    compose = inputs()
    compose["compose_bytes"] += b"# cross-generation drift\n"
    drift_cases.append(compose)
    resolver = inputs()
    resolver["resolver_sha"] = digest(resolver["resolver_sha"].encode())[:40]
    drift_cases.append(resolver)
    host_baseline = inputs()
    host_baseline["host_baseline_bytes"] += b"# cross-generation drift\n"
    drift_cases.append(host_baseline)
    enforcement = inputs()
    enforcement["enforcement_bytes"] += b"# cross-generation drift\n"
    drift_cases.append(enforcement)
    for drifted_after in drift_cases:
        with pytest.raises(error):
            build(builder, inputs(), drifted_after)

    dynamic_before, dynamic_after = inputs(), inputs()
    for row in dynamic_after["workloads"]:
        row["container_id"] = digest(canonical({"service": row["service"], "generation": "after"}))
        row["started_at"] = "2026-09-07T12:00:03.123456789Z"
    dynamic_pair = build(builder, dynamic_before, dynamic_after)
    assert dynamic_pair[BEFORE] != dynamic_pair[AFTER]
    before_value, after_value = decoded(dynamic_pair, BEFORE), decoded(dynamic_pair, AFTER)
    for before_row, after_row in zip(before_value["workloads"], after_value["workloads"], strict=True):
        assert before_row["service"] == after_row["service"]
        for field in ("container_id", "started_at"):
            before_row.pop(field)
            after_row.pop(field)
        assert before_row == after_row


def test_unknown_fields_noncanonical_time_and_personal_identifiers_are_rejected(builder):
    error = getattr(builder, "GenerationError", ValueError)
    valid = inputs()
    assert_canonical_pair(build(builder, valid, valid))
    mutations = []
    extra_root = deepcopy(valid)
    extra_root["asserted_compose_sha256"] = "0" * 64
    mutations.append(extra_root)
    extra_workload = deepcopy(valid)
    extra_workload["workloads"][0]["patient"] = "synthetic"
    mutations.append(extra_workload)
    extra_network = deepcopy(valid)
    extra_network["workloads"][0]["networks"][0]["hostname"] = "sensitive.example"
    mutations.append(extra_network)
    bad_time = deepcopy(valid)
    bad_time["workloads"][0]["started_at"] = "2026-09-07T12:00:00Z"
    mutations.append(bad_time)
    personal_project = deepcopy(valid)
    personal_project["project"] = "patient@example.com"
    mutations.append(personal_project)
    personal_state = deepcopy(valid)
    personal_state["state_id"] = "room/clinical/patient"
    mutations.append(personal_state)
    for changed in mutations:
        with pytest.raises(error):
            build(builder, changed, changed)


def test_builder_does_not_copy_a_fixed_expected_fixture(builder):
    original = inputs()
    first = build(builder, original, original)
    changed = deepcopy(original)
    changed["workloads"][0]["container_id"] = "0" * 64
    changed["workloads"][0]["started_at"] = "2026-09-07T12:00:01.123456789Z"
    second = build(builder, changed, changed)
    assert first != second
    assert decoded(second, BEFORE)["workloads"] != decoded(first, BEFORE)["workloads"]
    assert build(builder, changed, changed) == second


def test_same_generation_bytes_are_accepted_by_both_platform_parsers_at_join(builder):
    if not EGRESS_PARSER.is_file() or not SUPERVISION_PARSER.is_file():
        pytest.skip("join gate: both byte-only platform parsers are not integrated")
    pair = build(builder)
    egress = load(EGRESS_PARSER, "clinical_egress_generation_join")
    supervision = load(SUPERVISION_PARSER, "clinical_supervision_generation_join")
    expected = {
        "expected_mode": "published",
        "expected_candidate_id": CANDIDATE,
        "expected_services": ("hrh", "ingress"),
    }
    assert egress.validate_generation_bytes(pair[BEFORE], **expected) is None
    assert supervision.validate_generation_bytes(pair[BEFORE], **expected) is None
    assert egress.validate_generation_bytes(pair[AFTER], **expected) is None
    assert supervision.validate_generation_bytes(pair[AFTER], **expected) is None
