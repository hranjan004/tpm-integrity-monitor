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

event_logger = logging.getLogger("integrity.events")
if not event_logger.handlers:
    event_logger.addHandler(logging.StreamHandler())
event_logger.setLevel(logging.INFO)
event_logger.propagate = False


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


def token_hash(bearer_token):
    return hashlib.sha256(bearer_token.encode()).hexdigest()


def create_app(database_path=None, administrator_token=None, challenge_lifetime=60):
    database_file = Path(
        database_path or os.environ.get("INTEGRITY_DB", "state/verifier.db")
    )
    administrator_secret = administrator_token or os.environ.get("ADMIN_TOKEN", "")
    if len(administrator_secret) < 32:
        raise RuntimeError("ADMIN_TOKEN must contain at least 32 characters")
    database_file.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def db():
        connection = sqlite3.connect(database_file, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    with db() as connection:
        connection.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS devices (
          device TEXT PRIMARY KEY, pem TEXT NOT NULL, pcr TEXT NOT NULL,
          config TEXT NOT NULL, token TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS challenges (
          device TEXT PRIMARY KEY, nonce TEXT NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY, ts REAL NOT NULL, device TEXT NOT NULL,
          accepted INTEGER NOT NULL, reason TEXT NOT NULL, details TEXT NOT NULL);
        """)
    os.chmod(database_file, 0o600)
    application = FastAPI(title="TPM Integrity Monitor", version="0.1.0")

    def bearer(authorization):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "bearer_token_required")
        return authorization[7:]

    def administrator(authorization: str | None = Header(default=None)):
        if not hmac.compare_digest(bearer(authorization), administrator_secret):
            raise HTTPException(403, "admin_required")

    def device_auth(device: str, authorization: str | None = Header(default=None)):
        bearer_token = token_hash(bearer(authorization))
        with db() as connection:
            stored_record = connection.execute(
                "SELECT * FROM devices WHERE device=? AND active=1", (device,)
            ).fetchone()
        if stored_record is None or not hmac.compare_digest(
            bearer_token, stored_record["token"]
        ):
            raise HTTPException(403, "device_authentication_failed")
        return dict(stored_record)

    @application.get("/healthz")
    def health():
        return {"status": "ok"}

    @application.post(
        "/v1/enroll", dependencies=[Depends(administrator)], status_code=201
    )
    def enroll(submission: Enrollment):
        try:
            public_key(submission.public_key)
        except (ValueError, TypeError):
            raise HTTPException(422, "invalid_public_key")
        bearer_token = secrets.token_urlsafe(32)
        try:
            with db() as connection:
                connection.execute(
                    "INSERT INTO devices(device,pem,pcr,config,token) VALUES (?,?,?,?,?)",
                    (
                        submission.device,
                        submission.public_key,
                        submission.pcr_digest,
                        submission.config_digest,
                        token_hash(bearer_token),
                    ),
                )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "already_enrolled")
        return {"device": submission.device, "token": bearer_token}

    @application.delete("/v1/devices/{device}", dependencies=[Depends(administrator)])
    def revoke(device: str):
        with db() as connection:
            connection.execute("UPDATE devices SET active=0 WHERE device=?", (device,))
            connection.execute("DELETE FROM challenges WHERE device=?", (device,))
        return {"revoked": device}

    @application.post("/v1/devices/{device}/challenge")
    def challenge(device: str, enrolled_device=Depends(device_auth)):
        challenge_nonce = secrets.token_hex(32)
        with db() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO challenges VALUES (?,?,?)",
                (device, challenge_nonce, time.time() + challenge_lifetime),
            )
        return {
            "nonce": challenge_nonce,
            "expires_in": challenge_lifetime,
            "selection": "sha256:0,2,7,16",
        }

    @application.post("/v1/devices/{device}/attest")
    def attest(device: str, submission: Evidence, enrolled_device=Depends(device_auth)):
        # Consume even failed submissions. BEGIN IMMEDIATE prevents two workers accepting a replay.
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            stored_record = connection.execute(
                "SELECT * FROM challenges WHERE device=?", (device,)
            ).fetchone()
            device_status = connection.execute(
                "SELECT active FROM devices WHERE device=?", (device,)
            ).fetchone()
            challenge_is_valid = (
                device_status
                and device_status[0]
                and stored_record
                and hmac.compare_digest(stored_record["nonce"], submission.nonce)
                and stored_record["expires"] > time.time()
            )
            if stored_record and hmac.compare_digest(
                stored_record["nonce"], submission.nonce
            ):
                connection.execute("DELETE FROM challenges WHERE device=?", (device,))
            verdict_reason, quote_details = "nonce_expired_or_replayed", {}
            if challenge_is_valid:
                try:
                    if any(
                        len(field_name) > 256 or len(field_value) > 4096
                        for field_name, field_value in submission.config.items()
                    ):
                        raise ValueError("config_too_large")
                    quote_details = verify(
                        enrolled_device["pem"],
                        decode(submission.message),
                        decode(submission.signature),
                        qualification(submission.nonce, device, submission.config),
                        enrolled_device["pcr"],
                    )
                    if config_digest(submission.config) != enrolled_device["config"]:
                        raise ValueError("config_drift")
                    verdict_reason = "verified"
                except InvalidSignature:
                    verdict_reason = "signature_invalid"
                except (ValueError, TypeError) as error:
                    # Only expose known validation codes, never parser internals or submitted text.
                    validation_code = str(error)
                    public_error_codes = {
                        "config_too_large",
                        "pcr_drift",
                        "config_drift",
                        "nonce_or_config_binding",
                        "pcr_selection",
                        "unsafe_clock",
                    }
                    verdict_reason = (
                        validation_code
                        if validation_code in public_error_codes
                        else "malformed_evidence"
                    )
            is_accepted = verdict_reason == "verified"
            attestation_event = {
                "ts": time.time(),
                "device": device,
                "accepted": is_accepted,
                "reason": verdict_reason,
                "details": quote_details,
            }
            connection.execute(
                "INSERT INTO events(ts,device,accepted,reason,details) VALUES (?,?,?,?,?)",
                (
                    attestation_event["ts"],
                    device,
                    int(is_accepted),
                    verdict_reason,
                    json.dumps(quote_details),
                ),
            )
        event_logger.info(json.dumps(attestation_event))
        return attestation_event

    @application.get("/v1/events", dependencies=[Depends(administrator)])
    def events():
        with db() as connection:
            return [
                dict(event_row)
                for event_row in connection.execute(
                    "SELECT * FROM events ORDER BY id DESC LIMIT 100"
                )
            ]

    @application.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        # Keep this endpoint on a private monitoring network; it reveals device IDs.
        metric_lines = [
            "# TYPE integrity_attestations_total counter",
            "# TYPE integrity_device_trusted gauge",
            "# TYPE integrity_last_attestation_timestamp_seconds gauge",
        ]
        with db() as connection:
            for event_row in connection.execute(
                "SELECT device,reason,count(*) n FROM events GROUP BY device,reason"
            ):
                metric_lines.append(
                    f'integrity_attestations_total{{device="{event_row["device"]}",reason="{event_row["reason"]}"}} {event_row["n"]}'
                )
            for event_row in connection.execute(
                "SELECT e.* FROM events e JOIN (SELECT device,max(id) id FROM events GROUP BY device) x ON e.id=x.id"
            ):
                metric_lines.append(
                    f'integrity_device_trusted{{device="{event_row["device"]}"}} {event_row["accepted"]}'
                )
                metric_lines.append(
                    f'integrity_last_attestation_timestamp_seconds{{device="{event_row["device"]}"}} {event_row["ts"]}'
                )
        return "\n".join(metric_lines) + "\n"

    return application
