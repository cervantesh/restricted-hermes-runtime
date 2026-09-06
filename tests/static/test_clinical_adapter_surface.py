from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_adapter_image_is_a_separate_principal_with_no_general_runtime():
    source = (ROOT / "Dockerfile.clinical-adapter").read_text(encoding="utf-8")
    assert "10008" in source and "restricted-clinical-adapter" in source
    assert "production_clinical_adapter" in source
    assert "network_mode: host" not in source
    assert "run_agent.py" not in source and "mattermost_ingress.py" not in source
    assert "! -name 'upstream_deadline.py'" in source


def test_adapter_image_closure_command_imports_every_retained_module():
    command = ROOT / "tests/deployment/test_clinical_adapter_image.sh"
    source = command.read_text(encoding="utf-8")
    assert source.startswith("#!/usr/bin/env bash\n")
    assert 'docker build -f Dockerfile.clinical-adapter' in source
    assert 'docker run --rm --network none --entrypoint python' in source
    for module in (
        "restricted_runtime.contracts", "restricted_runtime.upstream_deadline",
        "restricted_runtime.clinical_adapter", "restricted_runtime.services.production_clinical_adapter",
    ):
        assert module in source


def test_edge_image_and_process_never_receive_the_hrh_credential():
    image = (ROOT / "Dockerfile.mattermost-ingress").read_text(encoding="utf-8")
    ingress = (ROOT / "src/restricted_runtime/services/production_mattermost_ingress.py").read_text(encoding="utf-8")
    for forbidden in ("HRH_API_KEY", "hrh-clinical-api-key", "Authorization: Bearer"):
        assert forbidden not in image
        assert forbidden not in ingress


def test_adapter_has_only_two_external_hrh_routes_and_one_uds_path():
    source = (ROOT / "src/restricted_runtime/clinical_adapter.py").read_text(encoding="utf-8")
    assert source.count('"/api/restricted-hermes/clinical/') == 2
    assert '"/run/restricted-clinical/query.sock"' in source
    assert "HTTP_PROXY" not in source and "urlopen" not in source


def test_socket_group_contract_and_parent_initializer_are_executable():
    source = (ROOT / "src/restricted_runtime/clinical_adapter.py").read_text(encoding="utf-8")
    initializer = (ROOT / "deploy/mattermost/clinical-socket-init.sh").read_text(encoding="utf-8")
    assert "CLINICAL_SOCKET_GID = 20006" in source
    assert "os.chown" in source and "st_gid" in source and "0o660" in source
    assert "10008:20006" in initializer and "-m 0770" in initializer
