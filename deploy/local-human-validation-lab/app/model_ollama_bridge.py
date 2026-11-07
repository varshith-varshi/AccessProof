"""Nonpublic, bounded OpenAI-compatible relay to the host-only Ollama bridge.

The customer RAG is not attached to this model network: Gateway alone may
present filtered, signed and Guard-approved model context here.
"""
from __future__ import annotations
import asyncio
import os
import json
import time
import httpx
from fastapi import FastAPI,HTTPException,Request
from fastapi.responses import JSONResponse
from app import model_context_witness as witness

app=FastAPI(docs_url=None,redoc_url=None)
@app.post('/v1/chat/completions')
async def complete(request:Request):
    data=await request.body()
    if len(data)>120_000:raise HTTPException(413,'MODEL_REQUEST_TOO_LARGE')
    # Gateway's generic OpenAI-compatible contract can omit the model.
    # Select exactly the trusted lab's installed model inside the isolated
    # bridge. Reject attempts to select a different upstream model.
    pinned=os.environ.get('LAB_PINNED_MODEL','')
    if pinned!='llama3.2:3b':raise HTTPException(503,'PINNED_MODEL_NOT_CONFIGURED')
    try:
        payload=json.loads(data)
    except (ValueError,UnicodeDecodeError):
        raise HTTPException(400,'MODEL_REQUEST_INVALID') from None
    if not isinstance(payload,dict) or payload.get('model') not in (None,pinned):
        raise HTTPException(422,'MODEL_NAME_NOT_APPROVED')
    payload['model']=pinned
    payload['stream']=False
    data=json.dumps(payload,separators=(',',':'),ensure_ascii=True).encode('utf-8')
    if len(data)>120_000:raise HTTPException(413,'MODEL_REQUEST_TOO_LARGE')
    bridge=os.environ.get('LAB_LOCAL_OLLAMA_BRIDGE','')
    if not bridge.startswith('http://192.168.') or not bridge.endswith(':11436/v1/chat/completions'):
        raise HTTPException(503,'MODEL_BRIDGE_NOT_PINNED')
    # Lab-only test hook (route certification of an in-flight revocation):
    # while the operator's hold marker exists, delay the model answer (max 25 s,
    # under the Gateway's 30 s model timeout) without breaking the connection.
    started=time.monotonic()
    while os.path.exists('/witness/ap-hold') and time.monotonic()-started<25:
        await asyncio.sleep(0.2)
    try:
        with httpx.Client(timeout=90,trust_env=False,follow_redirects=False) as c:
            result=c.post(bridge,content=data,headers={'Content-Type':'application/json'})
        witness.record(data,result.content,result.status_code)
        if result.status_code!=200:
            print(f"MODEL_BRIDGE_UPSTREAM_HTTP_STATUS={result.status_code}",flush=True)
            raise HTTPException(503,'LOCAL_MODEL_UNAVAILABLE')
        if len(result.content)>1_000_000:raise HTTPException(502,'MODEL_RESPONSE_TOO_LARGE')
        try:
            parsed=result.json()
        except ValueError:
            print('MODEL_BRIDGE_UPSTREAM_INVALID_JSON',flush=True)
            raise HTTPException(503,'LOCAL_MODEL_RESPONSE_INVALID') from None
        return JSONResponse(parsed,headers={'Cache-Control':'no-store'})
    except httpx.HTTPError as exc:
        print(f"MODEL_BRIDGE_TRANSPORT_FAILURE={type(exc).__name__}",flush=True)
        raise HTTPException(503,'LOCAL_MODEL_UNAVAILABLE') from None
