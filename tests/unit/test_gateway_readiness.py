"""Gateway readiness adapter rejects down, malformed, and stale pair responses."""
import pytest

from restricted_runtime.gateway_client import HttpGatewayClient

class Response:
    def __init__(self,status,body=None,malformed=False):self.status_code=status;self.body=body;self.malformed=malformed
    def json(self):
        if self.malformed:raise ValueError("malformed JSON")
        return self.body

class Client:
    def __init__(self,response):self.response=response
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def get(self,*args,**kwargs):return self.response

@pytest.mark.parametrize("response,expected",[
    (Response(200,{"status":"ready","policy_epoch":"e","policy_digest":"d"}),True),
    (Response(200,{"status":"ready","policy_epoch":"old","policy_digest":"d"}),False),
    (Response(200,None,True),False),
    (Response(503,{"status":"ready","policy_epoch":"e","policy_digest":"d"}),False),
])
def test_ready_requires_exact_live_gateway_pair(monkeypatch,response,expected):
    monkeypatch.setattr("restricted_runtime.gateway_client.httpx.Client",lambda *args,**kwargs:Client(response))
    client=HttpGatewayClient("https://gateway","aud");monkeypatch.setattr("restricted_runtime.gateway_client.GoogleIdTokenSupplier.__call__",lambda self:"token")
    assert client.ready("e","d") is expected
