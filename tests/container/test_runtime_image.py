"""Image closure proof against the package Python imports, not just build status."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


ROOT=Path(__file__).resolve().parents[2]

def _wsl_cwd() -> str:
    path=ROOT.resolve()
    return "/mnt/"+path.drive[0].lower()+path.as_posix()[2:]

def _docker_prefix() -> list[str] | None:
    try:
        if shutil.which("docker") and subprocess.run(["docker","info"],capture_output=True,timeout=3).returncode==0:
            return ["docker"]
    except (OSError,subprocess.TimeoutExpired):
        pass
    try:
        if shutil.which("wsl") and subprocess.run(["wsl","-d","Ubuntu-24.04","--","docker","info"],capture_output=True,timeout=20).returncode==0:
            return ["wsl","-d","Ubuntu-24.04","--cd",_wsl_cwd(),"--","docker"]
    except (OSError,subprocess.TimeoutExpired):
        pass
    return None

DOCKER=_docker_prefix()

def run_docker(*args: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    assert DOCKER is not None
    return subprocess.run([*DOCKER,*args],capture_output=True,text=True,timeout=timeout,cwd=None if DOCKER[0]=="wsl" else ROOT)

def test_image_recipe_has_no_dynamic_capabilities():
    for recipe in (ROOT/"Dockerfile.conversation",ROOT/"Dockerfile.gateway"):
        source=recipe.read_text(encoding="utf-8")
        assert ".env" not in source and "hermes" not in source.lower() and "USER " in source
        assert "rm -rf /app/src /app/build" in source

@pytest.mark.skipif(DOCKER is None, reason="Docker daemon unavailable locally and through Ubuntu-24.04 WSL")
@pytest.mark.parametrize(("recipe","tag","entry","absent"),[
    ("Dockerfile.conversation","restricted-runtime-conversation-proof","restricted_runtime.services.production_conversation",{"vertex.py","services/production_gateway.py","services/gateway_api.py"}),
    ("Dockerfile.gateway","restricted-runtime-gateway-proof","restricted_runtime.services.production_gateway",{"gateway_client.py","reconciliation.py","reconciliation_driver.py","services/production_conversation.py","services/restricted_api.py"}),
])
def test_built_role_image_is_import_closed_and_has_only_its_role_surface(recipe,tag,entry,absent):
    built=run_docker("build","-f",recipe,"-t",tag,".")
    assert built.returncode==0,built.stdout[-2000:]+built.stderr[-2000:]
    proof=f"""
import importlib
import pathlib
import restricted_runtime
root=pathlib.Path(restricted_runtime.__file__).parent
assert not pathlib.Path('/app/src').exists() and not pathlib.Path('/app/build').exists()
assert not list(root.rglob('__pycache__'))
files={{str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}}
absent={absent!r}
assert not(files & absent),(files & absent)
bad=[str(p) for base in (pathlib.Path('/app'),root) if base.exists() for p in base.rglob('*') if p.is_file() and (p.name=='.env' or ('service' in p.name.lower() and p.suffix=='.json') or p.suffix=='.pyc')]
assert not bad,bad
src='\\n'.join(p.read_text(errors='ignore') for p in root.rglob('*.py'))
assert not any(x in src for x in ('run_agent','AIAgent','shell_tool','openai','anthropic','ollama','mcp'))
importlib.import_module('{entry}')
"""
    checked=run_docker("run","--rm","--entrypoint","python",tag,"-c",proof,timeout=30)
    # A production root must reach its own closed config gate. Missing internal
    # role-local modules are image-construction failures, never a passing probe.
    assert checked.returncode != 0
    assert "required restricted runtime configuration missing" in checked.stderr
    assert "ModuleNotFoundError" not in checked.stderr and "ImportError" not in checked.stderr
    metadata=run_docker("image","inspect",tag,"--format","{{json .Config.Env}}",timeout=20)
    assert metadata.returncode==0
    assert "HERMES_HOME" not in metadata.stdout and "GOOGLE_APPLICATION_CREDENTIALS" not in metadata.stdout
