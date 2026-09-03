"""Explicit operator initialization for the ingress-local durable outbox."""
from __future__ import annotations

import os
from pathlib import Path

from ..contracts import ContractError
from ..mattermost_outbox import MattermostOutbox
from ..mattermost_policy import load_signed_mattermost_policy


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ContractError(f"required Mattermost outbox configuration missing: {name}")
    return value


def main() -> None:
    policy = load_signed_mattermost_policy(
        Path(_required("RESTRICTED_MATTERMOST_POLICY_PATH")),
        Path(_required("RESTRICTED_MATTERMOST_POLICY_SIGNATURE_PATH")),
        _required("RESTRICTED_MATTERMOST_POLICY_PUBLIC_KEY_B64"),
    )
    store = MattermostOutbox.initialize(
        Path("/var/lib/restricted-mattermost-outbox"),
        Path(_required("RESTRICTED_MATTERMOST_OUTBOX_KEY_PATH")),
        expected_fingerprint=policy.values["outbox_key_fingerprint"],
    )
    store.close()


if __name__ == "__main__":
    main()
