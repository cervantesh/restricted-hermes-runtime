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

@pytest.mark.skipif(not DOCKER_READY, reason="Docker daemon unavailable")
def test_built_images_have_no_hermes_or_alternate_inference_surface():
    for recipe, tag, allowed in (("Dockerfile.conversation","restricted-runtime-conversation-proof",set()),("Dockerfile.gateway","restricted-runtime-gateway-proof",{"vertex.py"})):
        built=subprocess.run(["docker","build","-f",recipe,"-t",tag,"."],capture_output=True,text=True,timeout=180)
        assert built.returncode==0,built.stdout[-2000:]+built.stderr[-2000:]
        proof=(
            "import os,pathlib; root=pathlib.Path('/app'); files=[p for p in root.rglob('*') if p.is_file()]; "
            "bad=[str(p) for p in files if p.name=='.env' or p.name.endswith('.json') and 'service' in p.name.lower() or any(x in str(p).lower() for x in ('hermes_home','/plugins/','/skills/','mcp'))]; "
            "assert not bad,bad; src={p.name:p.read_text(errors='ignore') for p in files if p.suffix=='.py'}; "
            "assert not any(x in '\\n'.join(src.values()) for x in ('run_agent','AIAgent','subprocess.run','shell_tool','openai','anthropic','ollama')); "
            f"assert {{p for p in src if p=='vertex.py'}}=={allowed!r}"
        )
        checked=subprocess.run(["docker","run","--rm","--entrypoint","python",tag,"-c",proof],capture_output=True,text=True,timeout=30)
        assert checked.returncode==0,checked.stdout+checked.stderr
        metadata=subprocess.run(["docker","image","inspect",tag,"--format","{{json .Config.Env}}"],capture_output=True,text=True,timeout=10)
        assert metadata.returncode==0 and "HERMES_HOME" not in metadata.stdout and "GOOGLE_APPLICATION_CREDENTIALS" not in metadata.stdout
