"""Production root for the standalone restricted Mattermost edge."""
from __future__ import annotations

import logging
import os
import ssl
import time
from pathlib import Path

from ..contracts import ContractError, jcs_bytes, load_closed_json
from ..mattermost_ingress import ClinicalQueryUdsClient, ConversationUdsClient, Ingress, MattermostEvent, MattermostRestClient
from ..mattermost_outbox import MattermostOutbox
from ..mattermost_policy import MAX_EVENT_BYTES, load_signed_mattermost_policy, load_token


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ContractError(f"required Mattermost ingress configuration missing: {name}")
    return value


def _websocket_uri(origin: str) -> str:
    return "wss://" + origin.removeprefix("https://") + "/api/v4/websocket"


def build_ingress() -> tuple[Ingress, str, object, ssl.SSLContext]:
    policy = load_signed_mattermost_policy(
        Path(_required("RESTRICTED_MATTERMOST_POLICY_PATH")),
        Path(_required("RESTRICTED_MATTERMOST_POLICY_SIGNATURE_PATH")),
        _required("RESTRICTED_MATTERMOST_POLICY_PUBLIC_KEY_B64"),
    )
    token = load_token(Path(_required("RESTRICTED_MATTERMOST_TOKEN_PATH")))
    ca_path = Path(_required("RESTRICTED_MATTERMOST_CA_PATH"))
    try:
        context = ssl.create_default_context(cafile=str(ca_path))
    except (OSError, ssl.SSLError) as exc:
        raise ContractError("Mattermost trust bundle rejected") from exc
    rest = MattermostRestClient(policy, token, ca_path=ca_path)
    outbox = MattermostOutbox.open(
        Path("/var/lib/restricted-mattermost-outbox"),
        Path(_required("RESTRICTED_MATTERMOST_OUTBOX_KEY_PATH")),
        expected_fingerprint=policy.values["outbox_key_fingerprint"],
    )
    clinical = ClinicalQueryUdsClient(policy) if "clinical_bindings" in policy.values else None
    ingress = Ingress(policy, rest, ConversationUdsClient(policy), outbox, clinical=clinical)
    ingress.preflight()
    return ingress, token, policy, context


def _authenticated_connection(ingress: Ingress, token: str, policy, context: ssl.SSLContext):
    try:
        from websockets.sync.client import connect
    except ImportError as exc:
        raise ContractError("Mattermost WebSocket transport unavailable") from exc
    connection = connect(
        _websocket_uri(policy.origin), ssl=context, proxy=None,
        open_timeout=policy.values["websocket_timeout_seconds"],
        close_timeout=policy.values["websocket_timeout_seconds"],
        max_size=MAX_EVENT_BYTES,
        compression=None,
    )
    sequence = 1
    # Mattermost's real WebSocket endpoint requires a JSON text frame; a binary
    # frame is closed before the authentication reply on the pinned ESR server.
    connection.send(
        jcs_bytes({"seq": sequence, "action": "authentication_challenge", "data": {"token": token}}).decode("utf-8")
    )
    deadline = time.monotonic() + policy.values["websocket_timeout_seconds"]
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            connection.close()
            raise ContractError("Mattermost WebSocket authentication timed out")
        raw = connection.recv(timeout=remaining)
        if not isinstance(raw, (str, bytes)):
            continue
        encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
        if len(encoded) > MAX_EVENT_BYTES:
            connection.close()
            raise ContractError("Mattermost WebSocket authentication response oversized")
        value = load_closed_json(encoded)
        if isinstance(value, dict) and value.get("seq_reply") == sequence:
            if value.get("status") != "OK":
                connection.close()
                raise ContractError("Mattermost WebSocket authentication rejected")
            ingress.mark_authenticated()
            logging.getLogger("restricted_mattermost").warning("mattermost_ingress_outcome=authenticated_ready")
            return connection


def run() -> None:
    try:
        from websockets.exceptions import ConnectionClosed
    except ImportError as exc:
        raise ContractError("Mattermost WebSocket transport unavailable") from exc
    for name in ("websockets", "websockets.client", "websockets.protocol"):
        logging.getLogger(name).disabled = True
    ingress, token, policy, context = build_ingress()
    delay = 1.0
    while True:
        connection = None
        periodic_recovery = None
        try:
            connection = _authenticated_connection(ingress, token, policy, context)
            periodic_recovery = ingress.start_periodic_recovery()
            delay = 1.0
            for raw in connection:
                try:
                    encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
                    ingress.handle(MattermostEvent.parse(encoded, max_bytes=MAX_EVENT_BYTES))
                except (ContractError, UnicodeError, TypeError):
                    logging.getLogger("restricted_mattermost").warning("mattermost_event_outcome=rejected")
        except ContractError:
            raise
        except (OSError, TimeoutError, ConnectionClosed):
            logging.getLogger("restricted_mattermost").warning("mattermost_connection_outcome=disconnected")
        finally:
            if periodic_recovery is not None:
                ingress.stop_periodic_recovery(periodic_recovery)
            if connection is not None:
                connection.close()
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


def main() -> None:
    try:
        run()
    except Exception:
        logging.getLogger("restricted_mattermost").error("mattermost_ingress_outcome=terminal")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
