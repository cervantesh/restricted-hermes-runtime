"""Production root for the standalone restricted Mattermost edge."""
from __future__ import annotations

import logging
import os
import queue
import ssl
import threading
import time
from pathlib import Path

from ..contracts import ContractError, jcs_bytes, load_closed_json
from ..mattermost_ingress import ClinicalQueryUdsClient, ConversationUdsClient, Ingress, MattermostEvent, MattermostRestClient
from ..mattermost_outbox import MattermostOutbox
from ..mattermost_policy import MAX_EVENT_BYTES, load_signed_mattermost_policy, load_token
from ..upstream_deadline import available as deadline_available


_EVENT_QUEUE_CAPACITY = 64


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
    if not deadline_available():
        raise ContractError("Mattermost REST deadline unavailable")
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


def _authenticated_connection(token: str, policy, context: ssl.SSLContext):
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
            logging.getLogger("restricted_mattermost").warning("mattermost_ingress_outcome=authenticated_ready")
            return connection


def _put(stop: threading.Event, events: queue.Queue, item: tuple[str, object | None]) -> bool:
    while not stop.is_set():
        try:
            events.put(item, timeout=0.2)
            return True
        except queue.Full:
            continue
    return False


def _websocket_producer(token: str, policy, context: ssl.SSLContext, events: queue.Queue, stop: threading.Event, active: dict, active_lock: threading.Lock) -> None:
    """Own only WebSocket I/O; the main thread owns every ingress/REST effect."""
    try:
        from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidStatus
    except ImportError:
        _put(stop, events, ("terminal", ContractError("Mattermost WebSocket transport unavailable")))
        return
    delay = 1.0
    while not stop.is_set():
        connection = None
        try:
            connection = _authenticated_connection(token, policy, context)
            with active_lock:
                active["connection"] = connection
            if not _put(stop, events, ("authenticated", None)):
                return
            delay = 1.0
            for raw in connection:
                if stop.is_set():
                    return
                encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
                if not isinstance(encoded, bytes) or len(encoded) > MAX_EVENT_BYTES:
                    _put(stop, events, ("malformed", None))
                    continue
                if not _put(stop, events, ("raw", encoded)):
                    return
        except ContractError as exc:
            _put(stop, events, ("terminal", exc))
            return
        except InvalidStatus as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status == 429 or isinstance(status, int) and 500 <= status <= 599:
                logging.getLogger("restricted_mattermost").warning("mattermost_connection_outcome=disconnected")
            else:
                _put(stop, events, ("terminal", ContractError("Mattermost WebSocket handshake rejected")))
                return
        except InvalidHandshake:
            _put(stop, events, ("terminal", ContractError("Mattermost WebSocket handshake rejected")))
            return
        except (OSError, TimeoutError, ConnectionClosed):
            logging.getLogger("restricted_mattermost").warning("mattermost_connection_outcome=disconnected")
        except Exception:
            _put(stop, events, ("terminal", ContractError("Mattermost WebSocket worker failed")))
            return
        finally:
            with active_lock:
                if active.get("connection") is connection:
                    active["connection"] = None
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    _put(stop, events, ("terminal", ContractError("Mattermost WebSocket worker failed")))
                    return
        if stop.wait(delay):
            return
        delay = min(delay * 2, 30.0)


def run() -> None:
    if not deadline_available():
        raise ContractError("Mattermost REST deadline unavailable")
    for name in ("websockets", "websockets.client", "websockets.protocol"):
        logging.getLogger(name).disabled = True
    ingress, token, policy, context = build_ingress()
    events: queue.Queue[tuple[str, object | None]] = queue.Queue(maxsize=_EVENT_QUEUE_CAPACITY)
    stop, active_lock, active = threading.Event(), threading.Lock(), {"connection": None}
    producer = threading.Thread(
        target=_websocket_producer, args=(token, policy, context, events, stop, active, active_lock),
        name="restricted-mattermost-websocket", daemon=True,
    )
    producer.start()
    next_scan = time.monotonic()
    scan_interval = policy.values["outbox_scan_interval_seconds"]
    try:
        while True:
            timeout = max(0.0, min(0.2, next_scan - time.monotonic()))
            try:
                kind, value = events.get(timeout=timeout)
                if kind == "terminal":
                    raise value
                if kind == "authenticated":
                    ingress.mark_authenticated()
                elif kind == "raw":
                    try:
                        ingress.handle(MattermostEvent.parse(value, max_bytes=MAX_EVENT_BYTES))
                    except (ContractError, UnicodeError, TypeError):
                        logging.getLogger("restricted_mattermost").warning("mattermost_event_outcome=rejected")
                elif kind == "malformed":
                    logging.getLogger("restricted_mattermost").warning("mattermost_event_outcome=rejected")
            except queue.Empty:
                if not producer.is_alive():
                    raise ContractError("Mattermost WebSocket worker stopped")
            if time.monotonic() >= next_scan:
                ingress.executor.drain()
                next_scan = time.monotonic() + scan_interval
    finally:
        stop.set()
        with active_lock:
            connection = active.get("connection")
        if connection is not None:
            connection.close()
        producer.join(timeout=policy.values["websocket_timeout_seconds"] + 1)
        if producer.is_alive():
            raise ContractError("Mattermost WebSocket worker did not stop")


def main() -> None:
    try:
        run()
    except Exception:
        logging.getLogger("restricted_mattermost").error("mattermost_ingress_outcome=terminal")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
