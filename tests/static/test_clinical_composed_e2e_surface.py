from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "tests" / "deployment" / "clinical-composed-e2e"


def test_clinical_composed_e2e_wrapper_selects_a_portable_python_interpreter():
    wrapper = (
        ROOT / "tests" / "deployment" / "test_clinical_composed_e2e.sh"
    ).read_text(encoding="utf-8")

    assert "command -v python3" in wrapper
    assert "elif command -v python" in wrapper
    assert wrapper.index("command -v python3") < wrapper.index("elif command -v python")
    assert 'exec "$python_bin"' in wrapper
    assert 'exec python "$root/tests/deployment/test_clinical_composed_e2e.py"' not in wrapper
    assert "clinical-composed-e2e: DENIED python-unavailable" in wrapper


def test_clinical_composed_e2e_is_a_pinned_real_boundary_harness():
    compose = (HARNESS / "compose.yaml").read_text(encoding="utf-8")
    source_build = (HARNESS / "compose.source-build.yaml").read_text(encoding="utf-8")
    runner = (ROOT / "tests" / "deployment" / "test_clinical_composed_e2e.py").read_text(encoding="utf-8")
    control = (HARNESS / "control.py").read_text(encoding="utf-8")

    assert "mattermost/mattermost-team-edition:11.7.10@sha256:" in compose
    assert compose.count("postgres:17.10-bookworm@sha256:") == 2
    assert "Dockerfile.clinical-adapter" in compose
    assert "Dockerfile.mattermost-ingress" in compose
    assert "Dockerfile.web.clinical-candidate" in source_build
    assert "Dockerfile.migrate.clinical-candidate" in source_build
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


def test_restricted_clinical_services_have_explicit_runtime_confinement():
    compose = yaml.safe_load((HARNESS / "compose.yaml").read_text(encoding="utf-8"))
    runner = (ROOT / "tests" / "deployment" / "test_clinical_composed_e2e.py").read_text(encoding="utf-8")
    expected = {
        "clinical-adapter": "/tmp:rw,noexec,nosuid,size=16m,mode=0700,uid=10008,gid=20007",
        "ingress": "/tmp:rw,noexec,nosuid,size=16m,mode=0700,uid=10007,gid=20005",
    }

    for service, tmpfs in expected.items():
        config = compose["services"][service]
        assert config["read_only"] is True
        assert config["cap_drop"] == ["ALL"]
        assert config["security_opt"] == ["no-new-privileges:true"]
        assert config["tmpfs"] == [tmpfs]
    assert "restricted_container_control_evidence" in runner
    assert "verify_restricted_container_controls" in runner
    assert "os.getuid()" in runner and "os.getgroups()" in runner


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
    compose = (HARNESS / "compose.source-build.yaml").read_text(encoding="utf-8")
    runner = (ROOT / "tests" / "deployment" / "test_clinical_composed_e2e.py").read_text(encoding="utf-8")
    control = (HARNESS / "control.py").read_text(encoding="utf-8")

    assert "BUILD_SHA: ${CLINICAL_HRH_BUILD_SHA:?required}" in compose
    assert 'HRH_SHA = "e30a4f968de6727519f49c08369f561fdf269ec5"' in runner
    assert 'HRH_TREE = "7fb2543a2ceb1649f05c467b38708d1404106659"' in runner
    assert 'CLINICAL_E2E_HRH_ROOT' in runner
    assert 'CLINICAL_E2E_HRH_ROOT must name a clean HRH checkout' in runner
    assert r'C:\dev' not in runner
    assert "CLINICAL_HRH_BUILD_SHA=HRH_SHA" in runner
    assert "sealed_compose_environment" in runner
    assert "SAFE_COMPOSE_PROCESS_ENV" in runner
    assert "env=sealed_compose_environment()" in runner
    assert "no published HRH registry digest, SBOM, provenance attestation, or no-rebuild verification" in runner
    assert "os.replace" in control
    assert 'command == "policy-digest"' in control


def test_published_hrh_overlay_has_no_source_build_or_fallback_surface():
    published_path = HARNESS / "compose.published-hrh.yaml"
    published_text = published_path.read_text(encoding="utf-8")
    published = yaml.safe_load(published_text)

    assert set(published["services"]) == {"hrh", "hrh-migrate"}
    assert "CLINICAL_HRH_ROOT" not in published_text
    for service, variable in (("hrh", "CLINICAL_HRH_WEB_IMAGE"), ("hrh-migrate", "CLINICAL_HRH_MIGRATE_IMAGE")):
        config = published["services"][service]
        assert config["image"] == "${" + variable + ":?required}"
        assert config["pull_policy"] == "never"
        assert "build" not in config
        assert "volumes" not in config
    assert "context:" not in published_text
    assert "dockerfile:" not in published_text.lower()


def test_published_hrh_runner_verifies_before_pull_and_disables_compose_pull():
    runner = (ROOT / "tests" / "deployment" / "test_clinical_composed_e2e.py").read_text(encoding="utf-8")

    assert runner.index("verify_hrh_published_candidate.py") < runner.index("def pull_published_hrh_subjects")
    assert 'compose_args[1:1] = ["--pull", "never"]' in runner
    assert '"docker", "pull", str(subjects[role])' in runner
    assert 'published_hrh_container_evidence("hrh-migrate", "migrate", completed=True)' in runner
    assert 'published_hrh_container_evidence("hrh", "web")' in runner
    assert '"CLINICAL_E2E_HRH_ROOT" in os.environ' in runner
    assert 'published HRH mode forbids CLINICAL_E2E_HRH_ROOT' in runner
    assert '"DOCKER_CONFIG"' not in runner.split("SAFE_COMPOSE_PROCESS_ENV =", 1)[1].split(")", 1)[0]
