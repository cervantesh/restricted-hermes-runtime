"""Bounded startup/periodic reconciliation driver; deliberately no provider import."""
from __future__ import annotations
import asyncio
from contextlib import asynccontextmanager
from .reconciliation import Reconciler

class ReconciliationDriver:
    def __init__(self,store,reconciler:Reconciler,owner:str,policy_epoch:str|None=None,*,authorization_gate=None):self.store,self.reconciler,self.owner,self.authorization_gate=store,reconciler,owner,authorization_gate
    def run_once(self,limit:int=32)->int:
        if self.authorization_gate is not None:self.authorization_gate()
        count=0
        for turn in self.store.expired_turns(limit):
            self.reconciler.reconcile_expired(tenant_id=turn.tenant_id,turn_id=turn.turn_id,client_request_id=turn.client_request_id,policy_epoch=turn.policy_epoch,policy_digest=turn.policy_digest,owner=self.owner)
            count+=1
        return count


def reconciliation_lifespan(driver):
    @asynccontextmanager
    async def lifespan(_app):
        await asyncio.to_thread(driver.run_once,32)
        stop=asyncio.Event()
        async def periodic():
            while not stop.is_set():
                try:await asyncio.to_thread(driver.run_once,32)
                except Exception:pass
                try:await asyncio.wait_for(stop.wait(),timeout=30)
                except asyncio.TimeoutError:pass
        task=asyncio.create_task(periodic())
        try:yield
        finally:
            stop.set();task.cancel()
            try:await task
            except asyncio.CancelledError:pass
    return lifespan
