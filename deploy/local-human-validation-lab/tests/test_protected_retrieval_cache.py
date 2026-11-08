"""Protected retrieval cache candidates are NEVER reused as authorization."""
from __future__ import annotations

import json
from dataclasses import asdict
import pytest
import redis

from app.index import Match
from app import api as rag_api
from app.retrieval_cache import (
    CacheUnavailable, cache_key, get_or_retrieve,
)


A = Match("finance-id","c1","Quarterly finance data","v1","finance.txt",
          "https://example.invalid/finance","attested-1",0.5)
B = Match("engineering-id","c2","Engineering deployment data","v1","engineering.txt",
          "https://example.invalid/engineering","attested-2",0.6)


class MemoryRedis:
    def __init__(self): self.values={};self.get_calls=0;self.set_calls=0
    def get(self,key):
        self.get_calls+=1
        return self.values.get(key)
    def setex(self,key,seconds,value):
        assert 1 <= seconds <= 90
        self.set_calls+=1
        self.values[key]=value


class SignedIndex:
    path="/tmp/synthetic.db"
    def __init__(self): self.calls=0;self.generation="g1"
    def stats(self):return {"generation":self.generation}
    def search(self,question,limit=5):
        self.calls+=1
        return [A,B]
    def by_name(self,name,limit=5):
        self.calls+=1
        return [A] if name=="finance.txt" else []


def retrieve(cache,index,question="Tell me about the company"):
    return get_or_retrieve(cache=cache,index=index,tenant="tenant-1",
        source="sharepoint",application="rag-v1",generation=index.generation,
        question=question,document_name=None)


def test_cache_is_scoped_to_index_generation_and_current_question():
    cache=MemoryRedis();index=SignedIndex()
    first, hit=retrieve(cache,index)
    assert first==[A,B] and hit is False and index.calls==1
    second, hit=retrieve(cache,index)
    assert second==first and hit is True and index.calls==1
    retrieve(cache,index,question="Another query")
    assert index.calls==2
    index.generation="g2"
    retrieve(cache,index)
    assert index.calls==3
    other=cache_key(tenant="other-tenant",source="sharepoint",
                    application="rag-v1",generation="g2",
                    question="Tell me about the company",document_name=None)
    current=cache_key(tenant="tenant-1",source="sharepoint",
                      application="rag-v1",generation="g2",
                      question="Tell me about the company",document_name=None)
    assert other!=current


def test_malformed_or_poisoned_cache_never_reaches_gateway():
    cache=MemoryRedis();index=SignedIndex()
    retrieve(cache,index)
    key=next(iter(cache.values))
    cache.values[key]=json.dumps({"generation":"g1","candidates":[{"content":"evil"}]})
    with pytest.raises(CacheUnavailable,match="CACHED_RETRIEVAL_INVALID"):
        retrieve(cache,index)
    assert index.calls==1
    cache.values[key]="\xff"
    with pytest.raises(CacheUnavailable):
        retrieve(cache,index)


def test_disconnected_redis_fails_closed():
    class Unavailable(MemoryRedis):
        def get(self,key): raise redis.RedisError("offline")
    with pytest.raises(CacheUnavailable,match="SIGNED_RETRIEVAL_CACHE_UNAVAILABLE"):
        retrieve(Unavailable(),SignedIndex())


class FakeGateway:
    def __init__(self): self.calls=[]
    def post(self,route,*,json,headers):
        # The Gateway receives BOTH signed candidates on EVERY call;
        # a different employee can never reuse the previous allow decision.
        self.calls.append((route,json,headers))
        actor=headers["Authorization"].removeprefix("Bearer ")
        if actor=="bob":
            return type("Response",(),{"status_code":403,"json":lambda _:{"detail":"no allowed resources"}})()
        return type("Response",(),{"status_code":200,"json":lambda _:{
            "choices":[{"message":{"content":"The employee-specific authorized answer"}}],
            "accessproof":{"decision":"allow","decision_id":"decision-"+actor}}})()


def test_cache_hit_always_calls_gateway_with_current_employee(monkeypatch):
    monkeypatch.setenv("LAB_PROTECTED_RETRIEVAL_CACHE","1")
    monkeypatch.setenv("LAB_TENANT_ID","tenant-1")
    monkeypatch.setenv("LAB_SOURCE_ID","sharepoint")
    monkeypatch.setenv("LAB_APPLICATION_ID","rag-v1")
    monkeypatch.setenv("LAB_GATEWAY_URL","http://accessproof-gateway:8090")
    monkeypatch.setattr(rag_api,"inspect_index",lambda *_:{"signed_index_ready":True})
    cache=MemoryRedis();index=SignedIndex();gateway=FakeGateway()
    rag=rag_api.Rag(index=index,cache=cache,gateway_client=gateway)
    alice=rag.protected("Summarize company", "alice")
    assert alice["cache_hit"] is False and alice["accessproof"]["decision"]=="allow"
    assert alice["cache_authorization"]=="CURRENT_EMPLOYEE_RECHECKED_BY_GATEWAY"
    assert index.calls==1
    with pytest.raises(rag_api.AccessDenied):
        rag.protected("Summarize company", "bob")
    assert index.calls==1
    assert len(gateway.calls)==2
    for route,payload,headers in gateway.calls:
        assert route.endswith("/v1/chat/completions")
        assert len(payload["retrieved_resources"])==2
        assert {r["resource_id"] for r in payload["retrieved_resources"]}=={"finance-id","engineering-id"}
    assert gateway.calls[0][2]["Authorization"]=="Bearer alice"
    assert gateway.calls[1][2]["Authorization"]=="Bearer bob"
    another=rag.protected("Summarize company", "alice")
    assert another["cache_hit"] is True and index.calls==1
    assert len(gateway.calls)==3


def test_cache_corruption_cannot_trigger_unprotected_model(monkeypatch):
    monkeypatch.setenv("LAB_PROTECTED_RETRIEVAL_CACHE","1")
    monkeypatch.setenv("LAB_TENANT_ID","tenant-1")
    monkeypatch.setenv("LAB_SOURCE_ID","sharepoint")
    monkeypatch.setenv("LAB_APPLICATION_ID","rag-v1")
    monkeypatch.setenv("LAB_GATEWAY_URL","http://accessproof-gateway:8090")
    monkeypatch.setattr(rag_api,"inspect_index",lambda *_:{"signed_index_ready":True})
    cache=MemoryRedis();index=SignedIndex();gateway=FakeGateway()
    rag=rag_api.Rag(index=index,cache=cache,gateway_client=gateway)
    rag.protected("Summarize", "alice")
    cache.values[next(iter(cache.values))]="not-json"
    with pytest.raises(rag_api.DependencyFailure,match="CACHED_RETRIEVAL_INVALID"):
        rag.protected("Summarize", "alice")
    assert len(gateway.calls)==1
