"""Fixed non-PHI diagnostic runner; no configurable request text or sink."""
from __future__ import annotations
import os
import uuid
import httpx
from google.auth.transport.requests import Request
from google.oauth2.id_token import fetch_id_token


PAYLOAD="HRH_RESTRICTED_RUNTIME_OK"


def main() -> None:
    audience=os.environ["RESTRICTED_RUNNER_AUDIENCE"]
    base=os.environ["RESTRICTED_CONVERSATION_URL"].rstrip("/")
    if os.environ.get("RESTRICTED_SYNTHETIC_PAYLOAD") != PAYLOAD:
        raise RuntimeError("synthetic runner payload is fixed")
    token=fetch_id_token(Request(),audience)
    headers={"Authorization":f"Bearer {token}"}
    conversation=f"synthetic-{uuid.uuid4()}"
    with httpx.Client(follow_redirects=False,trust_env=False,timeout=30) as client:
        created=client.post(f"{base}/v1/restricted/conversations/{conversation}",headers=headers)
        created.raise_for_status()
        epoch=created.json()["conversation_epoch"]
        turn=client.post(f"{base}/v1/restricted/conversations/{conversation}/turns",headers=headers,json={"schema_version":"restricted-turn.v1","client_request_id":str(uuid.uuid4()),"conversation_epoch":epoch,"message":PAYLOAD})
        turn.raise_for_status()
        if turn.json().get("status") != "COMMITTED": raise RuntimeError("synthetic runner did not commit")


if __name__ == "__main__": main()
