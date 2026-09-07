from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "tests" / "deployment" / "clinical-composed-e2e"


def test_clinical_composed_e2e_is_a_pinned_real_boundary_harness():
    compose = (HARNESS / "compose.yaml").read_text(encoding="utf-8")
    runner = (ROOT / "tests" / "deployment" / "test_clinical_composed_e2e.py").read_text(encoding="utf-8")
    control = (HARNESS / "control.py").read_text(encoding="utf-8")

    assert "mattermost/mattermost-team-edition:11.7.10@sha256:" in compose
    assert compose.count("postgres:17.10-bookworm@sha256:") == 2
    assert "Dockerfile.clinical-adapter" in compose
    assert "Dockerfile.mattermost-ingress" in compose
    assert "Dockerfile.web" in compose
    assert "Dockerfile.migrate" in compose
    assert "clinical-socket-init.sh" in compose
    assert "internal: true" in compose
    assert "responseDigest" in control
    assert "zero model/conversation/provider calls" in runner
    assert "unrelated UID" in control


def test_clinical_e2e_keeps_hrh_credentials_out_of_the_edge():
    compose = (HARNESS / "compose.yaml").read_text(encoding="utf-8")
    ingress = re.search(r"(?ms)^  ingress:\n(.*?)(?=^  \S|\Z)", compose).group(1)
    adapter = re.search(r"(?ms)^  clinical-adapter:\n(.*?)(?=^  \S|\Z)", compose).group(1)

    assert "hrh_api_key" not in ingress
    assert "hrh_secret" in adapter


def test_clinical_e2e_proves_clean_descendant_sources_and_exact_post_cardinality():
    runner = (ROOT / "tests" / "deployment" / "test_clinical_composed_e2e.py").read_text(encoding="utf-8")
    control = (HARNESS / "control.py").read_text(encoding="utf-8")

    assert "merge-base" in runner and "--is-ancestor" in runner
    assert "status" in runner and "--porcelain=v1" in runner
    assert "HRH E2E checkout must be clean before build" in runner
    assert "HRH E2E checkout tree does not match the frozen source" in runner
    assert "runtime_head" in runner and "runtime_tree" in runner
    assert "hrh_head" in runner and "hrh_tree" in runner
    assert "built_images" in runner
    assert "len(responses) != 1" in control
    assert "final-denial-sweep" in runner
    assert "post_count" in control


def test_clinical_e2e_uses_current_hrh_build_provenance_and_atomic_policy_refresh():
    compose = (HARNESS / "compose.yaml").read_text(encoding="utf-8")
    runner = (ROOT / "tests" / "deployment" / "test_clinical_composed_e2e.py").read_text(encoding="utf-8")
    control = (HARNESS / "control.py").read_text(encoding="utf-8")

    assert "BUILD_SHA: ${CLINICAL_HRH_BUILD_SHA:?required}" in compose
    assert 'HRH_SHA = "ad13735e9881a48580a9e138daac137f8c865dea"' in runner
    assert 'HRH_TREE = "f217b0b1cf7f438422528dfe178d81b78212c68b"' in runner
    assert 'C:\\dev\\Health-Record-Hub-wt-restricted-hermes-clinical-current' in runner
    assert '"CLINICAL_HRH_BUILD_SHA": HRH_SHA' in runner
    assert "os.replace" in control
    assert 'command == "policy-digest"' in control
