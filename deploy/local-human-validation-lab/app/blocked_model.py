"""Closed model boundary used until real employee certification succeeds.

This is intentionally not a model emulator. It refuses every generation
request; customer data must never be sent to a synthetic or unapproved model.
"""
from fastapi import FastAPI,HTTPException
app=FastAPI()
@app.post('/v1/chat/completions')
def blocked():
    raise HTTPException(503,'MODEL_RELEASE_DISABLED_UNTIL_PROTECT_CERTIFICATION')
