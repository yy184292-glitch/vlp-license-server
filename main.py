import os, json
from datetime import datetime, date, timedelta
from fastapi import FastAPI, Request, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import select

from db import make_engine, make_session_factory
from models import Base, License, Machine, Nonce, Log
from security import sign, safe_eq, now_unix

app = FastAPI()

DB_URL = os.getenv("DB_URL", "sqlite:///./vlp_auth.db")
LICENSE_SECRET = os.getenv("LICENSE_SECRET")
ISSUER_ADMIN_TOKEN = os.getenv("ISSUER_ADMIN_TOKEN")

engine = make_engine(DB_URL)
SessionLocal = make_session_factory(engine)
Base.metadata.create_all(engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class VerifyReq(BaseModel):
    license_key: str
    machine_id: str
    ts: int
    nonce: str
    sig: str

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/verify")
def verify(body: VerifyReq, db: Session = Depends(get_db)):
    if abs(now_unix() - body.ts) > 300:
        return {"valid": False, "reason": "ts_invalid"}

    expected = sign(LICENSE_SECRET, body.license_key, body.machine_id, body.ts, body.nonce)
    if not safe_eq(expected, body.sig):
        return {"valid": False, "reason": "bad_sig"}

    lic = db.get(License, body.license_key)
    if not lic or lic.is_revoked or lic.expires_on < date.today():
        return {"valid": False, "reason": "invalid"}

    return {
        "valid": True,
        "expires_on": str(lic.expires_on),
        "plan": lic.plan,
        "features": json.loads(lic.features_json),
        "server_time": now_unix()
    }
