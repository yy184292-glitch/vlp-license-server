import os, json, secrets
from datetime import datetime, date, timedelta
from fastapi import FastAPI, Request, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import select, Column, String, DateTime
from db import make_engine, make_session_factory
from models import Base, License, Machine, Nonce, Log
from security import sign, safe_eq, now_unix
from fastapi.staticfiles import StaticFiles

app = FastAPI()

app.mount("/content", StaticFiles(directory="content"), name="content")

DB_URL = os.getenv("DB_URL", "sqlite:///./vlp_auth.db")
LICENSE_SECRET = os.getenv("LICENSE_SECRET") or ""
ISSUER_ADMIN_TOKEN = os.getenv("ISSUER_ADMIN_TOKEN") or ""  # legacy single token
ISSUER_ADMIN_TOKENS = os.getenv("ISSUER_ADMIN_TOKENS") or ""  # comma-separated


MAIN_MAX_DEVICES = int(os.getenv("MAIN_MAX_DEVICES", "1"))
PRO_MAX_DEVICES = int(os.getenv("PRO_MAX_DEVICES", "2"))
TS_WINDOW_SEC = int(os.getenv("TS_WINDOW_SEC", "300"))
NONCE_TTL_SEC = int(os.getenv("NONCE_TTL_SEC", "600"))

if not LICENSE_SECRET:
    raise RuntimeError("LICENSE_SECRET is required")
def _load_admin_tokens() -> set[str]:
    raw = (ISSUER_ADMIN_TOKENS or "").strip()
    toks = {t.strip() for t in raw.split(",") if t.strip()} if raw else set()
    if not toks and ISSUER_ADMIN_TOKEN:
        toks = {ISSUER_ADMIN_TOKEN.strip()}
    return toks

ADMIN_TOKENS = _load_admin_tokens()
if not ADMIN_TOKENS:
    raise RuntimeError("ISSUER_ADMIN_TOKEN or ISSUER_ADMIN_TOKENS is required")

engine = make_engine(DB_URL)
SessionLocal = make_session_factory(engine)


# ---------- customer (admin managed) ----------
class Customer(Base):
    __tablename__ = "customers"
    customer_id = Column(String, primary_key=True)
    name = Column(String, default="")
    phone = Column(String, default="")
    memo = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def client_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else ""

def require_admin(req: Request) -> str:
    """Validate admin bearer token.

    Returns the token string for audit logging.
    """
    auth = req.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = auth.removeprefix("Bearer ").strip()
    if token not in ADMIN_TOKENS:
        raise HTTPException(status_code=403, detail="invalid admin token")
    return token


def max_devices_for_plan(plan: str) -> int:
    p = (plan or "").strip().upper()
    if p == "PRO":
        return max(1, PRO_MAX_DEVICES)
    return max(1, MAIN_MAX_DEVICES)

def add_log(db: Session, *, actor: str, action: str, ip: str, result="ok", reason="", license_key="", machine_id="", meta=None):
    db.add(Log(
        actor=actor, action=action, ip=ip,
        result=result, reason=reason,
        license_key=license_key, machine_id=machine_id,
        meta_json=json.dumps(meta or {}, ensure_ascii=False),
    ))
    db.commit()

def cleanup_nonces(db: Session):
    cutoff = datetime.utcnow() - timedelta(seconds=NONCE_TTL_SEC)
    db.query(Nonce).filter(Nonce.used_at < cutoff).delete()
    db.commit()

@app.get("/health")
def health():
    return {"ok": True}

# ---------- verify ----------
class VerifyReq(BaseModel):
    license_key: str
    machine_id: str
    ts: int
    nonce: str
    sig: str

@app.post("/verify")
def verify(req: Request, body: VerifyReq, db: Session = Depends(get_db)):
    ip = client_ip(req)
    st = now_unix()

    if abs(st - body.ts) > TS_WINDOW_SEC:
        add_log(db, actor="verify", action="verify", ip=ip, result="ng", reason="ts_out_of_window",
                license_key=body.license_key, machine_id=body.machine_id)
        return {"valid": False, "reason": "ts_out_of_window", "server_time": st}

    cleanup_nonces(db)
    if db.get(Nonce, body.nonce):
        add_log(db, actor="verify", action="verify", ip=ip, result="ng", reason="nonce_reused",
                license_key=body.license_key, machine_id=body.machine_id)
        return {"valid": False, "reason": "nonce_reused", "server_time": st}
    db.add(Nonce(nonce=body.nonce))
    db.commit()

    expected = sign(LICENSE_SECRET, body.license_key, body.machine_id, body.ts, body.nonce)
    if not safe_eq(expected, body.sig):
        add_log(db, actor="verify", action="verify", ip=ip, result="ng", reason="bad_sig",
                license_key=body.license_key, machine_id=body.machine_id)
        return {"valid": False, "reason": "bad_sig", "server_time": st}

    lic = db.get(License, body.license_key)
    if not lic:
        add_log(db, actor="verify", action="verify", ip=ip, result="ng", reason="unknown_key",
                license_key=body.license_key, machine_id=body.machine_id)
        return {"valid": False, "reason": "unknown_key", "server_time": st}
    if lic.is_revoked:
        add_log(db, actor="verify", action="verify", ip=ip, result="ng", reason="revoked",
                license_key=body.license_key, machine_id=body.machine_id)
        return {"valid": False, "reason": "revoked", "server_time": st}
    if lic.expires_on < date.today():
        add_log(db, actor="verify", action="verify", ip=ip, result="ng", reason="expired",
                license_key=body.license_key, machine_id=body.machine_id)
        return {"valid": False, "reason": "expired", "server_time": st}

    # machine tracking (auto-bind on first activation with device limit)
    max_dev = max_devices_for_plan(lic.plan)

    m = db.execute(select(Machine).where(
        Machine.license_key == body.license_key,
        Machine.machine_id == body.machine_id
    )).scalar_one_or_none()

    if not m:
        # first time on this machine: enforce device limit (count only non-banned machines)
        rows = db.execute(select(Machine).where(Machine.license_key == body.license_key)).scalars().all()
        active_machine_ids = [x.machine_id for x in rows if not getattr(x, "is_banned", False)]
        if len(active_machine_ids) >= max_dev:
            add_log(db, actor="verify", action="verify", ip=ip, result="ng", reason="device_limit_reached",
                    license_key=body.license_key, machine_id=body.machine_id,
                    meta={"max_devices": max_dev, "devices_bound": len(active_machine_ids)})
            return {"valid": False, "reason": "device_limit_reached", "server_time": st}

        db.add(Machine(license_key=body.license_key, machine_id=body.machine_id))
    else:
        if getattr(m, "is_banned", False):
            add_log(db, actor="verify", action="verify", ip=ip, result="ng", reason="machine_banned",
                    license_key=body.license_key, machine_id=body.machine_id)
            return {"valid": False, "reason": "machine_banned", "server_time": st}
        m.last_seen = datetime.utcnow()
    db.commit()

    features = json.loads(lic.features_json or "{}")
    add_log(db, actor="verify", action="verify", ip=ip, result="ok", license_key=body.license_key,
            machine_id=body.machine_id, meta={"plan": lic.plan, "expires_on": str(lic.expires_on)})

    return {
        "valid": True,
        "reason": "ok",
        "expires_on": str(lic.expires_on),
        "plan": lic.plan,
        "features": features,
        "server_time": st
    }

# ---------- admin ----------
class IssueReq(BaseModel):
    # 顧客ID（例: FT0001 / C0001）。新UIでは必須推奨。
    customer_id: str = ""
    # 表示名（屋号/顧客名）
    customer_name: str = ""
    phone: str = ""
    memo: str = ""
    plan: str = "PRO"

    # GUI互換: expires_on（YYYY-MM-DD）または days
    expires_on: str | None = None
    days: int | None = None

    # 旧互換（既存クライアント向け）
    add_days: int = 365

    features: dict = {"main": True}

@app.post("/admin/issue")
def admin_issue(req: Request, body: IssueReq, db: Session = Depends(get_db)):
    admin_token = admin_token = admin_token = require_admin(req)
    ip = client_ip(req)

    # customer
    customer_id = (body.customer_id or "").strip() or (body.customer_name or "").strip()
    if not customer_id:
        raise HTTPException(status_code=400, detail="customer_id is required")

    cust = db.get(Customer, customer_id)
    if not cust:
        cust = Customer(
            customer_id=customer_id,
            name=(body.customer_name or customer_id),
            phone=(body.phone or ""),
            memo=(body.memo or ""),
        )
        db.add(cust)
    else:
        # update only when provided
        if body.customer_name:
            cust.name = body.customer_name
        if body.phone:
            cust.phone = body.phone
        if body.memo:
            cust.memo = body.memo
    db.commit()

    # license key generation (simple and strong enough)
    key = "VLP-" + secrets.token_hex(16).upper()

    # 優先順位: expires_on > days > add_days
    if body.expires_on:
        try:
            expires = date.fromisoformat(body.expires_on.strip())
        except Exception:
            raise HTTPException(status_code=400, detail="invalid expires_on (use YYYY-MM-DD)")
    elif body.days is not None:
        try:
            d = int(body.days)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid days")
        if d <= 0:
            raise HTTPException(status_code=400, detail="days must be positive")
        expires = date.today() + timedelta(days=d)
    else:
        expires = date.today() + timedelta(days=int(body.add_days))

    lic = License(
        license_key=key,
        plan=body.plan,
        expires_on=expires,
        features_json=json.dumps(body.features, ensure_ascii=False),
        is_revoked=False,
        # store customer_id in customer_name for backward-compatible schema
        customer_name=customer_id,
        phone=body.phone,
        memo=body.memo,
    )
    db.add(lic)
    db.commit()

    actor = f"admin:{admin_token[:8]}"
    add_log(db, actor=actor, action="issue", ip=ip, license_key=key,
            meta={"customer_id": customer_id, "expires_on": str(expires), "plan": body.plan})
    return {
        "ok": True,
        "license_key": key,
        "expires_on": str(expires),
        "plan": body.plan,
        "features": body.features,
        "customer_id": customer_id,
        "customer_name": cust.name,
    }


# ---------- customer admin APIs ----------
class CustomerUpsertReq(BaseModel):
    customer_id: str
    name: str = ""
    phone: str = ""
    memo: str = ""

@app.post("/admin/customers/upsert")
def admin_customers_upsert(req: Request, body: CustomerUpsertReq, db: Session = Depends(get_db)):
    admin_token = require_admin(req)
    ip = client_ip(req)
    cid = (body.customer_id or "").strip()
    if not cid:
        raise HTTPException(status_code=400, detail="customer_id is required")
    c = db.get(Customer, cid)
    if not c:
        c = Customer(customer_id=cid)
        db.add(c)
    if body.name:
        c.name = body.name
    if body.phone:
        c.phone = body.phone
    if body.memo:
        c.memo = body.memo
    db.commit()
    add_log(db, actor=f"admin:{admin_token[:8]}", action="customer_upsert", ip=ip, meta={"customer_id": cid})
    return {"ok": True, "customer_id": c.customer_id, "name": c.name, "phone": c.phone, "memo": c.memo}

class CustomerSearchReq(BaseModel):
    q: str = ""

@app.post("/admin/customers/search")
def admin_customers_search(req: Request, body: CustomerSearchReq, db: Session = Depends(get_db)):
    admin_token = require_admin(req)
    ip = client_ip(req)
    q = (body.q or "").strip()
    stmt = select(Customer)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            (Customer.customer_id.like(like)) |
            (Customer.name.like(like)) |
            (Customer.phone.like(like)) |
            (Customer.memo.like(like))
        )
    rows = db.execute(stmt).scalars().all()
    add_log(db, actor=f"admin:{admin_token[:8]}", action="customer_search", ip=ip, meta={"q": q, "count": len(rows)})
    return [{"customer_id": r.customer_id, "name": r.name, "phone": r.phone, "memo": r.memo} for r in rows]

@app.get("/admin/customers/{customer_id}")
def admin_customer_get(req: Request, customer_id: str, db: Session = Depends(get_db)):
    admin_token = require_admin(req)
    ip = client_ip(req)
    cid = (customer_id or "").strip()
    c = db.get(Customer, cid)
    if not c:
        raise HTTPException(status_code=404, detail="unknown customer_id")
    add_log(db, actor=f"admin:{admin_token[:8]}", action="customer_get", ip=ip, meta={"customer_id": cid})
    return {"customer_id": c.customer_id, "name": c.name, "phone": c.phone, "memo": c.memo}

@app.get("/admin/customers/{customer_id}/licenses")
def admin_customer_licenses(req: Request, customer_id: str, db: Session = Depends(get_db)):
    admin_token = require_admin(req)
    ip = client_ip(req)
    cid = (customer_id or "").strip()
    stmt = select(License).where(License.customer_name == cid)
    rows = db.execute(stmt).scalars().all()
    add_log(db, actor=f"admin:{admin_token[:8]}", action="customer_licenses", ip=ip, meta={"customer_id": cid, "count": len(rows)})
    return [{
        "license_key": r.license_key,
        "plan": r.plan,
        "expires_on": str(r.expires_on),
        "is_revoked": r.is_revoked,
        "features": json.loads(r.features_json or "{}"),
    } for r in rows]

class SearchReq(BaseModel):
    q: str = ""

@app.post("/admin/search")
def admin_search(req: Request, body: SearchReq, db: Session = Depends(get_db)):
    admin_token = admin_token = require_admin(req)
    ip = client_ip(req)

    q = (body.q or "").strip()
    stmt = select(License)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            (License.license_key.like(like)) |
            (License.customer_name.like(like)) |
            (License.phone.like(like)) |
            (License.memo.like(like))
        )
    rows = db.execute(stmt).scalars().all()
    # attach customer display info
    customer_ids = {r.customer_name for r in rows if getattr(r, 'customer_name', '')}
    cust_map = {}
    if customer_ids:
        cust_rows = db.execute(select(Customer).where(Customer.customer_id.in_(customer_ids))).scalars().all()
        cust_map = {c.customer_id: c for c in cust_rows}
    add_log(db, actor=f"admin:{admin_token[:8]}", action="search", ip=ip, meta={"q": q, "count": len(rows)})

    return [{
        "license_key": r.license_key,
        "customer_id": r.customer_name,
        "customer_name": (cust_map.get(r.customer_name).name if cust_map.get(r.customer_name) else r.customer_name),
        "phone": r.phone,
        "memo": r.memo,
        "plan": r.plan,
        "expires_on": str(r.expires_on),
        "is_revoked": r.is_revoked,
        "features": json.loads(r.features_json or "{}"),
    } for r in rows]

class ExtendReq(BaseModel):
    license_key: str
    add_days: int = 0
    new_expires_on: str = ""

@app.post("/admin/extend")
def admin_extend(req: Request, body: ExtendReq, db: Session = Depends(get_db)):
    admin_token = admin_token = require_admin(req)
    ip = client_ip(req)

    lic = db.get(License, body.license_key)
    if not lic:
        raise HTTPException(status_code=404, detail="unknown license_key")

    before = lic.expires_on
    if body.new_expires_on:
        lic.expires_on = date.fromisoformat(body.new_expires_on)
    else:
        lic.expires_on = lic.expires_on + timedelta(days=int(body.add_days))
    db.commit()

    add_log(db, actor=f"admin:{admin_token[:8]}", action="extend", ip=ip, license_key=body.license_key,
            meta={"before": str(before), "after": str(lic.expires_on), "add_days": body.add_days})
    return {"ok": True, "expires_on": str(lic.expires_on)}

class RevokeReq(BaseModel):
    license_key: str
    revoke: bool = True

@app.post("/admin/revoke")
def admin_revoke(req: Request, body: RevokeReq, db: Session = Depends(get_db)):
    admin_token = admin_token = require_admin(req)
    ip = client_ip(req)

    lic = db.get(License, body.license_key)
    if not lic:
        raise HTTPException(status_code=404, detail="unknown license_key")
    lic.is_revoked = bool(body.revoke)
    db.commit()

    add_log(db, actor=f"admin:{admin_token[:8]}", action="revoke", ip=ip, license_key=body.license_key, meta={"revoke": body.revoke})
    return {"ok": True, "is_revoked": lic.is_revoked}

@app.get("/admin/logs")
def admin_logs(req: Request, limit: int = 200, db: Session = Depends(get_db)):
    admin_token = admin_token = require_admin(req)
    ip = client_ip(req)

    limit = max(1, min(limit, 1000))
    rows = db.execute(select(Log).order_by(Log.id.desc()).limit(limit)).scalars().all()
    add_log(db, actor=f"admin:{admin_token[:8]}", action="logs", ip=ip, meta={"limit": limit})

    return [{
        "ts": r.ts.isoformat(),
        "actor": r.actor,
        "action": r.action,
        "license_key": r.license_key,
        "machine_id": r.machine_id,
        "ip": r.ip,
        "result": r.result,
        "reason": r.reason,
        "meta": json.loads(r.meta_json or "{}"),
    } for r in rows]