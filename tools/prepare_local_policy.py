"""Prepare public local-UDS policy artifacts from an operator-owned signing key."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from restricted_runtime.contracts import jcs_bytes
from restricted_runtime.policy import PolicyBundle


ROOT = Path(__file__).resolve().parents[1]


def _external(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        return resolved
    raise ValueError("local policy private key must remain outside the repository and build context")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key-b64-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "policy" / "generated")
    parser.add_argument("--epoch", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--runner-principal", required=True)
    parser.add_argument("--gateway-principal", required=True)
    parser.add_argument("--model-display-name", required=True)
    parser.add_argument("--model-sha256", required=True)
    args = parser.parse_args()

    values = json.loads((ROOT / "policy" / "local.policy.template.json").read_text(encoding="utf-8"))
    values.update({
        "policy_epoch": args.epoch,
        "tenant_id": args.tenant_id,
        "external_runner_principal": args.runner_principal,
        "gateway_invoker_principal": args.gateway_principal,
        "model": args.model_display_name,
        "model_sha256": args.model_sha256,
    })
    canonical = jcs_bytes(values)
    bundle = PolicyBundle(values, hashlib.sha256(canonical).hexdigest())
    bundle.validate()
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(_external(args.private_key_b64_file).read_text(encoding="ascii"), validate=True))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "policy.json").write_bytes(canonical)
    (args.output_dir / "policy.sig").write_text(base64.b64encode(private.sign(canonical)).decode("ascii"), encoding="ascii")
    print(bundle.digest)


if __name__ == "__main__":
    main()
