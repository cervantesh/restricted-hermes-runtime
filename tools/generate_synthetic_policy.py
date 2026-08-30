"""Generate a signed synthetic-only policy bundle; private key input is external."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from restricted_runtime.contracts import jcs_bytes
from restricted_runtime.policy import PolicyBundle


REPOSITORY_ROOT=Path(__file__).resolve().parents[1]


def require_external_private_key(path: Path) -> Path:
    resolved=path.resolve(strict=True)
    try:
        resolved.relative_to(REPOSITORY_ROOT)
    except ValueError:
        return resolved
    raise ValueError("policy private key must remain outside the repository and Docker build context")


def generate(*, template: Path, output_dir: Path, private_key_b64_file: Path, project_id: str, project_number: str, epoch: str, tenant_id: str, runner_principal: str, conversation_principal: str) -> tuple[Path, Path, str]:
    values=json.loads(template.read_text(encoding="utf-8"))
    values.update({
        "policy_epoch":epoch, "tenant_id":tenant_id, "vertex_project_id":project_id,
        "vertex_project_number":project_number, "external_runner_principal":runner_principal,
        "gateway_invoker_principal":conversation_principal,
        "model_resource":f"projects/{project_number}/locations/us/publishers/google/models/gemini-3.5-flash",
        "generate_content_path":f"/v1/projects/{project_number}/locations/us/publishers/google/models/gemini-3.5-flash:generateContent",
    })
    bundle=PolicyBundle(values,"");bundle.validate()
    external_key=require_external_private_key(private_key_b64_file)
    private=Ed25519PrivateKey.from_private_bytes(base64.b64decode(external_key.read_text(encoding="ascii"),validate=True))
    output_dir.mkdir(parents=True,exist_ok=True)
    policy_path=output_dir/"policy.json";signature_path=output_dir/"policy.sig"
    canonical=jcs_bytes(values)
    policy_path.write_bytes(canonical)
    signature_path.write_text(base64.b64encode(private.sign(canonical)).decode("ascii"),encoding="ascii")
    import hashlib
    return policy_path,signature_path,hashlib.sha256(canonical).hexdigest()


def main() -> None:
    parser=argparse.ArgumentParser()
    parser.add_argument("--template",type=Path,default=Path("policy/policy.template.json"));parser.add_argument("--output-dir",type=Path,required=True)
    parser.add_argument("--private-key-b64-file",type=Path,required=True);parser.add_argument("--project-id",required=True);parser.add_argument("--project-number",required=True);parser.add_argument("--epoch",required=True);parser.add_argument("--tenant-id",required=True);parser.add_argument("--runner-principal",required=True);parser.add_argument("--conversation-principal",required=True)
    args=parser.parse_args();_,_,digest=generate(template=args.template,output_dir=args.output_dir,private_key_b64_file=args.private_key_b64_file,project_id=args.project_id,project_number=args.project_number,epoch=args.epoch,tenant_id=args.tenant_id,runner_principal=args.runner_principal,conversation_principal=args.conversation_principal)
    print(digest)

if __name__=="__main__": main()
