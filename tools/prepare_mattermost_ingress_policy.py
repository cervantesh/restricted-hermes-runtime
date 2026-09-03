"""Create a signed restricted Mattermost policy without embedding a bot token."""
from __future__ import annotations

import argparse
import base64
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from restricted_runtime.contracts import jcs_bytes
from restricted_runtime.mattermost_policy import MATTERMOST_POLICY_SCHEMA, MattermostPolicy


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-key-file", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--team-id", required=True)
    parser.add_argument("--channel-id", action="append", required=True)
    parser.add_argument("--user-id", action="append", required=True)
    parser.add_argument("--bot-user-id", required=True)
    parser.add_argument("--bot-username", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--epoch", required=True)
    parser.add_argument("--inference-policy-epoch", required=True)
    parser.add_argument("--inference-policy-digest", required=True)
    parser.add_argument("--not-before", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--max-message-bytes", type=int, default=4096)
    parser.add_argument("--outbox-key-fingerprint", required=True)
    args = parser.parse_args()
    values = {
        "schema_version": MATTERMOST_POLICY_SCHEMA, "policy_epoch": args.epoch,
        "inference_policy_epoch": args.inference_policy_epoch,
        "inference_policy_digest": args.inference_policy_digest, "tenant_id": args.tenant_id,
        "origin": args.origin, "team_id": args.team_id,
        "allowed_channel_ids": sorted(args.channel_id), "allowed_user_ids": sorted(args.user_id),
        "bot_user_id": args.bot_user_id, "bot_username": args.bot_username,
        "allowed_modality": "text", "dms_allowed": False, "files_allowed": False,
        "delivery_mode": "thread-only", "initiation_mode": "explicit-mention",
        "max_message_utf8_bytes": args.max_message_bytes,
        "not_before": args.not_before, "expires_at": args.expires_at, "clock_skew_seconds": 30,
        "websocket_timeout_seconds": 10, "rest_timeout_seconds": 8,
        "uds_timeout_seconds": 45, "conversation_deadline_seconds": 40,
        "outbox_key_fingerprint": args.outbox_key_fingerprint,
        "outbox_payload_retention_seconds": 3600, "outbox_payload_capacity": 1000,
        "outbox_tombstone_capacity": 1000, "outbox_scan_limit": 64,
    }
    document = MattermostPolicy(values, "")
    document.validate(now=datetime.now(UTC))
    key_raw = Path(args.private_key_file).read_text(encoding="ascii")
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_raw, validate=True))
    output = Path(args.output_dir)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = jcs_bytes(values)
    (output / "mattermost-ingress.json").write_bytes(payload)
    (output / "mattermost-ingress.sig").write_text(
        base64.b64encode(private.sign(payload)).decode("ascii"), encoding="ascii"
    )


if __name__ == "__main__":
    main()
