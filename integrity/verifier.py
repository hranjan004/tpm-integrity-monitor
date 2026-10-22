"""Single-host persistent verifier. SQLite transactions serialize nonce consumption."""
from contextlib import contextmanager
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import secrets
import sqlite3
import time

from cryptography.exceptions import InvalidSignature
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from .crypto import config_digest, decode, public_key, qualification, verify

log = logging.getLogger("integrity.events")
if not log.handlers:
    log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)
log.propagate = False


class Enrollment(BaseModel):
    device: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    public_key: str = Field(max_length=8192)
    pcr_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    config_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class Evidence(BaseModel):
    nonce: str = Field(pattern=r"^[0-9a-f]{64}$")
    message: str = Field(max_length=8192)
    signature: str = Field(max_length=2048)
    config: dict[str, str] = Field(max_length=64)


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_app(db_path=None, admin_token=None, ttl=60):
    path = Path(db_path or os.environ.get("INTEGRITY_DB", "state/verifier.db"))
    admin = admin_token or os.environ.get("ADMIN_TOKEN", "")
    if len(admin) < 32:
        raise RuntimeError("ADMIN_TOKEN must contain at least 32 characters")
    path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def db():
        con = sqlite3.connect(path, timeout=10)
        con.row_factory = sqlite3.Row
        try:
            with con:
                yield con
        finally:
            con.close()

    with db() as con:
        con.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS devices (
          device TEXT PRIMARY KEY, pem TEXT NOT NULL, pcr TEXT NOT NULL,
          config TEXT NOT NULL, token TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS challenges (
          device TEXT PRIMARY KEY, nonce TEXT NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY, ts REAL NOT NULL, device TEXT NOT NULL,
          accepted INTEGER NOT NULL, reason TEXT NOT NULL, details TEXT NOT NULL);
        ''')
    os.chmod(path, 0o600)
    app = FastAPI(title="TPM Integrity Monitor", version="0.1.0")

    def bearer(authorization):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "bearer_token_required")
        return authorization[7:]

    def administrator(authorization: str | None = Header(default=None)):
        if not hmac.compare_digest(bearer(authorization), admin):
            raise HTTPException(403, "admin_required")

    def device_auth(device: str, authorization: str | None = Header(default=None)):
        token = token_hash(bearer(authorization))
        with db() as con:
            row = con.execute("SELECT * FROM devices WHERE device=? AND active=1", (device,)).fetchone()
        if row is None or not hmac.compare_digest(token, row["token"]):
            raise HTTPException(403, "device_authentication_failed")
        return dict(row)

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.post("/v1/enroll", dependencies=[Depends(administrator)], status_code=201)
    def enroll(body: Enrollment):
        try:
            public_key(body.public_key)
        except (ValueError, TypeError):
            raise HTTPException(422, "invalid_public_key")
        token = secrets.token_urlsafe(32)
        try:
            with db() as con:
                con.execute("INSERT INTO devices(device,pem,pcr,config,token) VALUES (?,?,?,?,?)",
                            (body.device, body.public_key, body.pcr_digest, body.config_digest, token_hash(token)))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "already_enrolled")
        return {"device": body.device, "token": token}

    @app.delete("/v1/devices/{device}", dependencies=[Depends(administrator)])
    def revoke(device: str):
        with db() as con:
            con.execute("UPDATE devices SET active=0 WHERE device=?", (device,))
            con.execute("DELETE FROM challenges WHERE device=?", (device,))
        return {"revoked": device}

    @app.post("/v1/devices/{device}/challenge")
    def challenge(device: str, identity=Depends(device_auth)):
        nonce = secrets.token_hex(32)
        with db() as con:
            con.execute("INSERT OR REPLACE INTO challenges VALUES (?,?,?)", (device, nonce, time.time() + ttl))
        return {"nonce": nonce, "expires_in": ttl, "selection": "sha256:0,2,7,16"}

    @app.post("/v1/devices/{device}/attest")
    def attest(device: str, body: Evidence, identity=Depends(device_auth)):
        # Consume even failed submissions. BEGIN IMMEDIATE prevents two workers accepting a replay.
        with db() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT * FROM challenges WHERE device=?", (device,)).fetchone()
            live = con.execute("SELECT active FROM devices WHERE device=?", (device,)).fetchone()
            valid = live and live[0] and row and hmac.compare_digest(row["nonce"], body.nonce) and row["expires"] > time.time()
            if row and hmac.compare_digest(row["nonce"], body.nonce):
                con.execute("DELETE FROM challenges WHERE device=?", (device,))
            reason, details = "nonce_expired_or_replayed", {}
            if valid:
                try:
                    if any(len(k) > 256 or len(v) > 4096 for k, v in body.config.items()):
                        raise ValueError("config_too_large")
                    details = verify(identity["pem"], decode(body.message), decode(body.signature),
                                     qualification(body.nonce, device, body.config), identity["pcr"])
                    if config_digest(body.config) != identity["config"]:
                        raise ValueError("config_drift")
                    reason = "verified"
                except InvalidSignature:
                    reason = "signature_invalid"
                except (ValueError, TypeError) as exc:
                    # Only expose known validation codes, never parser internals or submitted text.
                    code = str(exc)
                    allowed = {"config_too_large", "pcr_drift", "config_drift", "nonce_or_config_binding", "pcr_selection", "unsafe_clock"}
                    reason = code if code in allowed else "malformed_evidence"
            accepted = reason == "verified"
            event = {"ts": time.time(), "device": device, "accepted": accepted, "reason": reason, "details": details}
            con.execute("INSERT INTO events(ts,device,accepted,reason,details) VALUES (?,?,?,?,?)",
                        (event["ts"], device, int(accepted), reason, json.dumps(details)))
        log.info(json.dumps(event))
        return event

    @app.get("/v1/events", dependencies=[Depends(administrator)])
    def events():
        with db() as con:
            return [dict(r) for r in con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 100")]

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        # Keep this endpoint on a private monitoring network; it reveals device IDs.
        lines = ["# TYPE integrity_attestations_total counter", "# TYPE integrity_device_trusted gauge", "# TYPE integrity_last_attestation_timestamp_seconds gauge"]
        with db() as con:
            for r in con.execute("SELECT device,reason,count(*) n FROM events GROUP BY device,reason"):
                lines.append(f'integrity_attestations_total{{device="{r["device"]}",reason="{r["reason"]}"}} {r["n"]}')
            for r in con.execute("SELECT e.* FROM events e JOIN (SELECT device,max(id) id FROM events GROUP BY device) x ON e.id=x.id"):
                lines.append(f'integrity_device_trusted{{device="{r["device"]}"}} {r["accepted"]}')
                lines.append(f'integrity_last_attestation_timestamp_seconds{{device="{r["device"]}"}} {r["ts"]}')
        return "\n".join(lines) + "\n"

    return app
