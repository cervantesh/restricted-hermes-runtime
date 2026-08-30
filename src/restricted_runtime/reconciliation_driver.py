"""Bounded startup/periodic reconciliation driver; deliberately no provider import."""
from __future__ import annotations
from .reconciliation import Reconciler

class ReconciliationDriver:
    def __init__(self,store,reconciler:Reconciler,owner:str,policy_epoch:str):self.store,self.reconciler,self.owner,self.policy_epoch=store,reconciler,owner,policy_epoch
    def run_once(self,limit:int=32)->int:
        count=0
        for turn in self.store.expired_turns(limit):
            self.reconciler.reconcile_expired(tenant_id=turn.tenant_id,turn_id=turn.turn_id,client_request_id=turn.client_request_id,policy_epoch=self.policy_epoch,policy_digest=turn.policy_digest,owner=self.owner)
            count+=1
        return count
