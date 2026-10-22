import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import sqlite3
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient
import pytest

from integrity.crypto import PCRS, config_digest, qualification, parse_quote
from integrity.verifier import create_app

ADMIN = "a" * 48
CONFIG = {"/etc/test": "approved", "secure_boot": "unknown"}
PCR = hashlib.sha256(bytes(128)).hexdigest()


def sized(b):
    return struct.pack(">H", len(b)) + b


def signed(key, nonce, device="node", config=None, pcr=PCR, mask=None, extra=None, safe=1):
    config = CONFIG if config is None else config
    mask = sum(1 << p for p in PCRS) if mask is None else mask
    msg = struct.pack(">IH", 0xff544347, 0x8018) + sized(b"\0\x0b" + bytes(32))
    msg += sized(extra if extra is not None else qualification(nonce, device, config))
    msg += struct.pack(">QIIBQ", 100, 0, 0, safe, 1)
    msg += struct.pack(">IHB", 1, 0x000b, 3) + mask.to_bytes(3, "little") + sized(bytes.fromhex(pcr))
    sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    return {"nonce": nonce, "config": config, "message": base64.b64encode(msg).decode(), "signature": base64.b64encode(sig).decode()}


@pytest.fixture
def setup(tmp_path):
    path = tmp_path / "test.db"
    client = TestClient(create_app(path, ADMIN))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    enrollment = {"device": "node", "public_key": pem, "pcr_digest": PCR, "config_digest": config_digest(CONFIG)}
    response = client.post("/v1/enroll", json=enrollment, headers={"Authorization": "Bearer " + ADMIN})
    assert response.status_code == 201
    headers = {"Authorization": "Bearer " + response.json()["token"]}
    return client, key, headers, path, enrollment


def issue(client, headers):
    r = client.post("/v1/devices/node/challenge", headers=headers)
    assert r.status_code == 200
    return r.json()["nonce"]


def submit(client, headers, body):
    r = client.post("/v1/devices/node/attest", json=body, headers=headers)
    assert r.status_code == 200
    return r.json()


def test_accept_replay_persistence(setup):
    c, key, h, path, _ = setup
    body = signed(key, issue(c, h))
    assert submit(c, h, body)["accepted"]
    restarted = TestClient(create_app(path, ADMIN))
    assert submit(restarted, h, body)["reason"] == "nonce_expired_or_replayed"
    assert 'reason="verified"} 1' in c.get("/metrics").text


@pytest.mark.parametrize("mutation,reason", [
    ({"pcr": "01" * 32}, "pcr_drift"),
    ({"config": {"/etc/test": "tampered"}}, "config_drift"),
    ({"mask": 1}, "pcr_selection"),
    ({"extra": b"wrong nonce"}, "nonce_or_config_binding"),
    ({"safe": 0}, "unsafe_clock"),
    ({"device": "another-device"}, "nonce_or_config_binding"),
])
def test_policy_rejections(setup, mutation, reason):
    c, key, h, _, _ = setup
    body = signed(key, issue(c, h), **mutation)
    assert submit(c, h, body)["reason"] == reason
    assert submit(c, h, body)["reason"] == "nonce_expired_or_replayed"


@pytest.mark.parametrize("field", ["signature", "message"])
def test_tamper(setup, field):
    c, key, h, _, _ = setup
    body = signed(key, issue(c, h))
    data = bytearray(base64.b64decode(body[field])); data[-1] ^= 1
    body[field] = base64.b64encode(data).decode()
    assert submit(c, h, body)["reason"] == "signature_invalid"


def test_unsigned_config_tamper(setup):
    c, key, h, _, _ = setup
    body = signed(key, issue(c, h)); body["config"] = {"fake": "approved"}
    assert submit(c, h, body)["reason"] == "nonce_or_config_binding"


def test_wrong_key(setup):
    c, _, h, _, _ = setup
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert submit(c, h, signed(key, issue(c, h)))["reason"] == "signature_invalid"


def test_expiry(setup):
    c, key, h, path, _ = setup
    body = signed(key, issue(c, h))
    with sqlite3.connect(path) as con:
        con.execute("UPDATE challenges SET expires=0")
    assert not submit(c, h, body)["accepted"]


def test_challenge_replacement(setup):
    c, key, h, _, _ = setup
    old = signed(key, issue(c, h)); current = signed(key, issue(c, h))
    assert not submit(c, h, old)["accepted"]
    assert submit(c, h, current)["accepted"]


def test_concurrent_replay(setup):
    c, key, h, _, _ = setup
    body = signed(key, issue(c, h))
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: submit(c, h, body), range(8)))
    assert sum(r["accepted"] for r in results) == 1


def test_admin_auth_and_duplicate(setup):
    c, _, h, _, enrollment = setup
    assert c.post("/v1/enroll", json=enrollment, headers=h).status_code == 403
    assert c.post("/v1/enroll", json=enrollment).status_code == 401
    assert c.post("/v1/enroll", json=enrollment, headers={"Authorization": "Bearer " + ADMIN}).status_code == 409
    assert c.get("/v1/events").status_code == 401
    assert c.post("/v1/devices/node/challenge", headers={"Authorization": "Bearer wrong"}).status_code == 403


def test_revocation(setup):
    c, key, h, _, _ = setup
    body = signed(key, issue(c, h))
    assert c.delete("/v1/devices/node", headers={"Authorization": "Bearer " + ADMIN}).status_code == 200
    assert c.post("/v1/devices/node/attest", json=body, headers=h).status_code == 403


@pytest.mark.parametrize("field,value", [("message", "@@@"), ("signature", "@@@"), ("message", "")])
def test_malformed(setup, field, value):
    c, key, h, _, _ = setup
    body = signed(key, issue(c, h)); body[field] = value
    assert not submit(c, h, body)["accepted"]


def test_truncation_and_trailing_data(setup):
    _, key, _, _, _ = setup
    msg = base64.b64decode(signed(key, "00" * 32)["message"])
    for length in range(len(msg)):
        with pytest.raises(ValueError):
            parse_quote(msg[:length])
    with pytest.raises(ValueError):
        parse_quote(msg + b"extra")


def test_requires_admin_secret(tmp_path):
    with pytest.raises(RuntimeError):
        create_app(tmp_path / "bad.db", "short")
