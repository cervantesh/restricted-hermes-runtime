"""Image closure proof against the package Python imports, not just build status."""
from __future__ import annotations

from pathlib import Path
import io
import shutil
import subprocess
import tarfile
import tempfile
import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.generate_synthetic_policy import generate


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
    return subprocess.run([*DOCKER,*args],capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=timeout,cwd=None if DOCKER[0]=="wsl" else ROOT)

def docker_path(path: Path) -> str:
    value=path.resolve()
    return _wsl_cwd_for(value) if DOCKER and DOCKER[0]=="wsl" else str(value)

def _wsl_cwd_for(path: Path) -> str:
    return "/mnt/"+path.drive[0].lower()+path.as_posix()[2:]

def layer_members(archive: Path) -> tuple[set[str],int]:
    """Read every tar-readable layer from legacy or OCI docker-save layouts."""
    found:set[str]=set()
    inspected=0
    with tarfile.open(archive) as saved:
        for member in saved:
            if not member.isfile():
                continue
            stream=saved.extractfile(member)
            if stream is None:
                continue
            try:
                with tarfile.open(fileobj=stream,mode="r|*") as layer:
                    found.update(item.name.lstrip("./") for item in layer)
                    inspected+=1
            except tarfile.ReadError:
                pass
    return found,inspected

def forbidden_layer_paths(names:set[str],absent:set[str])->set[str]:
    suffixes={"restricted_runtime/"+path for path in absent}
    return {name for name in names if any(name.rstrip("/").endswith(suffix) for suffix in suffixes)}

def assert_layer_proof(names:set[str],inspected:int,absent:set[str])->None:
    assert inspected>0,"docker-save archive contained no tar-readable OCI or legacy layer"
    forbidden=forbidden_layer_paths(names,absent)
    assert not forbidden,sorted(forbidden)

def _tar_bytes(paths:list[str])->bytes:
    data=io.BytesIO()
    with tarfile.open(fileobj=data,mode="w") as layer:
        for path in paths:
            info=tarfile.TarInfo(path);info.size=0;layer.addfile(info)
    return data.getvalue()

def test_layer_proof_catches_site_packages_prefix_and_rejects_zero_readable_layers(tmp_path):
    archive=tmp_path/"oci-save.tar";payload=_tar_bytes(["usr/local/lib/python3.11/site-packages/restricted_runtime/vertex.py"])
    with tarfile.open(archive,"w") as saved:
        info=tarfile.TarInfo("blobs/sha256/layer");info.size=len(payload);saved.addfile(info,io.BytesIO(payload))
    names,inspected=layer_members(archive)
    assert inspected==1
    with pytest.raises(AssertionError):assert_layer_proof(names,inspected,{"vertex.py"})
    empty=tmp_path/"empty-save.tar"
    with tarfile.open(empty,"w") as saved:
        data=b"{}";info=tarfile.TarInfo("manifest.json");info.size=len(data);saved.addfile(info,io.BytesIO(data))
    names,inspected=layer_members(empty)
    with pytest.raises(AssertionError):assert_layer_proof(names,inspected,{"vertex.py"})

def test_image_recipe_has_no_dynamic_capabilities():
    for recipe in (ROOT/"Dockerfile.conversation",ROOT/"Dockerfile.gateway",ROOT/"Dockerfile.local-gateway"):
        source=recipe.read_text(encoding="utf-8")
        assert ".env" not in source and "hermes" not in source.lower() and "USER " in source
        assert "AS builder" in source and "COPY --from=builder /usr/local/lib/python3.11/site-packages" in source
        assert "COPY policy ./policy" not in source
        assert "COPY policy/generated/policy.json policy/generated/policy.sig" in source
    for recipe, user, uid, primary_gid, supplementary in (
        (ROOT / "Dockerfile.local-conversation", "restricted-local-conversation", 10006, 20001, (20000, 20002)),
        (ROOT / "Dockerfile.local-gateway", "restricted-local-gateway", 10005, 20002, (20000, 20003)),
    ):
        source = recipe.read_text(encoding="utf-8")
        assert f"useradd --system --uid {uid} --gid {primary_gid} --groups {','.join(map(str, supplementary))} {user}" in source
        assert f"USER {user}" in source
        assert "chown root:20000 /run/restricted-inference" in source
        assert "chmod 1770 /run/restricted-inference" in source


@pytest.mark.skipif(DOCKER is None, reason="Docker daemon unavailable locally and through Ubuntu-24.04 WSL")
def test_built_runner_image_imports_google_request_transport_without_runtime_surface():
    tag = "restricted-runtime-runner-proof"
    built = run_docker("build", "-f", "Dockerfile.runner", "-t", tag, ".")
    assert built.returncode == 0, built.stdout[-2000:] + built.stderr[-2000:]
    proof = """
import importlib.util
import os
from pathlib import Path

from google.auth.transport.requests import Request

assert Request is not None
assert os.getuid() == 10004
script = Path('/app/synthetic_runner.py')
assert script.is_file()
compile(script.read_text(encoding='utf-8'), str(script), 'exec')
assert importlib.util.find_spec('restricted_runtime') is None
assert 'HRH_RESTRICTED_RUNTIME_OK' in script.read_text(encoding='utf-8')
"""
    checked = run_docker("run", "--rm", "--entrypoint", "python", tag, "-c", proof, timeout=30)
    assert checked.returncode == 0, checked.stdout[-2000:] + checked.stderr[-2000:]


@pytest.fixture
def generated_public_policy(tmp_path):
    """Supply only build-safe artifacts; the temporary private key is external."""
    private=Ed25519PrivateKey.generate()
    key=tmp_path/"external-policy-private-key.b64"
    key.write_text(base64.b64encode(private.private_bytes_raw()).decode("ascii"),encoding="ascii")
    output=ROOT/"policy"/"generated"
    output.mkdir(exist_ok=True)
    try:
        generate(template=ROOT/"policy"/"policy.template.json",output_dir=output,private_key_b64_file=key,project_id="project",project_number="123",epoch="image-proof",tenant_id="tenant",runner_principal="caller",conversation_principal="conversation")
        yield
    finally:
        for name in ("policy.json","policy.sig"):
            (output/name).unlink(missing_ok=True)
        try:output.rmdir()
        except OSError:pass

@pytest.mark.skipif(DOCKER is None, reason="Docker daemon unavailable locally and through Ubuntu-24.04 WSL")
@pytest.mark.parametrize(("recipe","tag","entry","uid","absent"),[
    ("Dockerfile.conversation","restricted-runtime-conversation-proof","restricted_runtime.services.production_conversation","10001",{"vertex.py","services/production_gateway.py","services/gateway_api.py"}),
    ("Dockerfile.gateway","restricted-runtime-gateway-proof","restricted_runtime.services.production_gateway","10002",{"gateway_client.py","reconciliation.py","reconciliation_driver.py","services/production_conversation.py","services/restricted_api.py"}),
    ("Dockerfile.local-gateway","restricted-runtime-local-gateway-proof","restricted_runtime.services.production_local_gateway","10005",{"vertex.py","gateway_client.py","reconciliation.py","reconciliation_driver.py","services/production_gateway.py","services/production_conversation.py","services/restricted_api.py"}),
    ("Dockerfile.local-conversation","restricted-runtime-local-conversation-proof","restricted_runtime.services.production_local_conversation","10006",{"vertex.py","google_kms.py","gateway_client.py","gateway.py","local_uds.py","storage.py","services/production_gateway.py","services/production_conversation.py"}),
])
def test_built_role_image_is_import_closed_and_has_only_its_role_surface(generated_public_policy,recipe,tag,entry,uid,absent):
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
    metadata=run_docker("image","inspect",tag,"--format","{{json .Config}}",timeout=20)
    assert metadata.returncode==0
    assert "HERMES_HOME" not in metadata.stdout and "GOOGLE_APPLICATION_CREDENTIALS" not in metadata.stdout
    role_identities = {
        "Dockerfile.local-conversation": ("restricted-local-conversation", 10006, 20001, {20000, 20001, 20002}),
        "Dockerfile.local-gateway": ("restricted-local-gateway", 10005, 20002, {20000, 20002, 20003}),
    }
    expected_config_user = role_identities.get(recipe, (uid,))[0]
    assert f'"User":"{expected_config_user}"' in metadata.stdout
    if recipe in role_identities:
        user, expected_uid, expected_gid, expected_groups = role_identities[recipe]
        assert f'"User":"{user}"' in metadata.stdout
        identity = run_docker(
            "run", "--rm", "--entrypoint", "python", tag, "-c",
            "import os; assert os.getuid() == %d; assert os.getgid() == %d; assert set(os.getgroups()) == %r"
            % (expected_uid, expected_gid, expected_groups),
            timeout=20,
        )
        assert identity.returncode == 0, identity.stdout[-2000:] + identity.stderr[-2000:]
    with tempfile.TemporaryDirectory() as directory:
        archive=Path(directory)/"image.tar"
        saved=run_docker("save","-o",docker_path(archive),tag,timeout=60)
        assert saved.returncode==0,saved.stderr
        names,inspected=layer_members(archive)
    assert_layer_proof(names,inspected,absent)
