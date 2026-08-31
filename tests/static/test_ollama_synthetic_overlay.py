"""Static guardrails for the optional real-model synthetic overlay."""
from pathlib import Path
import yaml


ROOT = Path(__file__).resolve().parents[2]


def test_default_compose_does_not_gain_ollama_services():
    source = (ROOT / "deploy/local/compose.yaml").read_text(encoding="utf-8").lower()
    assert "ollama" not in source


def test_overlay_is_opt_in_pinned_networkless_and_read_only_model_store():
    value = yaml.safe_load((ROOT / "deploy/local/compose.ollama-synthetic-non-phi-only.yaml").read_text(encoding="utf-8"))
    services = value["services"]
    assert set(services) == {"ollama-synthetic-non-phi-only", "ollama-synthetic-non-phi-only-adapter"}
    ollama, adapter = services.values()
    assert "@sha256:9e7d782e99880c70f9563c51633da875ca605518a8f8d95c2532bda70a027b7a" in ollama["image"]
    assert ollama["network_mode"] == "none" and adapter["network_mode"] == "service:ollama-synthetic-non-phi-only"
    assert ollama["gpus"] == "all" and ollama["read_only"] is True and adapter["read_only"] is True
    assert ollama["environment"]["OLLAMA_NO_CLOUD"] == "true"
    assert adapter["user"] == "10003:20003" and adapter["group_add"] == ["20000"]
    for service in (ollama, adapter):
        assert service["profiles"] == ["ollama-synthetic-non-phi-only"]
        assert all(mount.get("read_only") is True for mount in service["volumes"] if isinstance(mount, dict) and mount.get("target") == "/models")
        assert "ports" not in service and "docker.sock" not in str(service)
