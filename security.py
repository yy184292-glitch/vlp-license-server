import hmac, hashlib, time

def sign(secret: str, license_key: str, machine_id: str, ts: int, nonce: str):
    msg = f"{license_key}|{machine_id}|{ts}|{nonce}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()

def safe_eq(a: str, b: str):
    return hmac.compare_digest(a, b)

def now_unix():
    return int(time.time())
