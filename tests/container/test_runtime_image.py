import shutil
import subprocess
import pytest

try:
    DOCKER_READY = shutil.which("docker") is not None and subprocess.run(["docker", "info"], capture_output=True, timeout=2).returncode == 0
except (OSError, subprocess.TimeoutExpired):
    DOCKER_READY = False

def test_image_recipe_has_no_dynamic_capabilities():
    # Recipe scanning is executable even when a local Docker daemon is absent.
    conversation=open("Dockerfile.conversation",encoding="utf-8").read()
    gateway=open("Dockerfile.gateway",encoding="utf-8").read()
    for recipe in (conversation,gateway):
        assert ".env" not in recipe and "hermes" not in recipe.lower() and "USER " in recipe

@pytest.mark.skipif(not DOCKER_READY, reason="Docker daemon unavailable")
def test_runtime_images_build_when_docker_is_available():
    for recipe, tag in (("Dockerfile.conversation", "restricted-runtime-conversation-test"), ("Dockerfile.gateway", "restricted-runtime-gateway-test")):
        result=subprocess.run(["docker","build","-f",recipe,"-t",tag,"."],capture_output=True,text=True,timeout=180)
        assert result.returncode==0, result.stdout[-2000:]+result.stderr[-2000:]
