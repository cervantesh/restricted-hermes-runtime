from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_exact_esr_harness_pins_native_tls_and_internal_networks():
    compose = (ROOT / "tests/deployment/mattermost-esr-staging/compose.yaml").read_text(encoding="utf-8")
    runner = (ROOT / "tests/deployment/test_mattermost_esr_staging.py").read_text(encoding="utf-8")
    assert "mattermost/mattermost-team-edition:11.7.10@sha256:84a041d836bf6fbf6a9a78ab699fa5ebe5437bfb6a514b5afad4121fa3800696" in compose
    assert "postgres:17.10-bookworm@sha256:9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f" in compose
    assert 'command: ["/mattermost/bin/mattermost", "server"]' in compose
    assert "MM_SERVICESETTINGS_CONNECTIONSECURITY: TLS" in compose
    assert "internal: true" in compose
    assert "ports:" not in compose
    assert "mattermost_ingress_outcome=authenticated_ready" in runner
    assert 'compose("down", "--volumes", "--remove-orphans"' in runner
    assert 'tempfile.mkdtemp(prefix="mattermost-esr-")' in runner
    assert 'dir=ROOT' not in runner
    assert 'wait_mattermost_local()' in runner
    assert 'exec_controller("websocket-wrong-token")' in runner
    assert 'EVIDENCE / "allowed-delivery.log"' in runner
    assert 'if "mattermost_delivery_outcome=rejected_binding" in root_logs' in runner
    assert 'if "mattermost_delivery_outcome=rejected_binding" in continuation_logs' in runner
    assert "def compose_ps(" in runner
    assert "pytest" not in runner.lower()
