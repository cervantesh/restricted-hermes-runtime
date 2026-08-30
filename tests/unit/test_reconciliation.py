from restricted_runtime.contracts import AttemptState, TurnState
from restricted_runtime.reconciliation import Reconciler

class Content:
    def __init__(self): self.calls=[]
    def claim_expired_lease(self, *_): return 2
    def mark_terminal_cas(self, *args): self.calls.append(args); return True
class Gateway:
    def __init__(self, state): self.state=state; self.fenced=False
    def status(self, *_, **__): return self.state
    def fence(self, *_, **__): self.fenced=True; return self.state

def test_dispatch_started_becomes_indeterminate_and_never_calls_inference():
    content, gateway = Content(), Gateway(AttemptState.DISPATCH_STARTED)
    assert Reconciler(content, gateway).reconcile_expired(tenant_id="t", turn_id="x", client_request_id="r", policy_epoch="p", policy_digest="d", owner="r") is TurnState.INDETERMINATE
    assert not gateway.fenced and content.calls[-1][3] is TurnState.INDETERMINATE

def test_reserved_is_fenced_before_failed():
    content, gateway = Content(), Gateway(AttemptState.CANCELLED_NO_DISPATCH)
    assert Reconciler(content, gateway).reconcile_expired(tenant_id="t", turn_id="x", client_request_id="r", policy_epoch="p", policy_digest="d", owner="r") is TurnState.FAILED
