import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import sqlite3
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient
import pytest

from integrity.crypto import SELECTED_PCRS, config_digest, qualification, parse_quote
from integrity.verifier import create_app

ADMIN = "a" * 48
CONFIG = {"/etc/test": "approved", "secure_boot": "unknown"}
PCR = hashlib.sha256(bytes(128)).hexdigest()


def sized(payload):
    return struct.pack(">H", len(payload)) + payload


def signed(
    signing_key,
    nonce,
    device="node",
    config=None,
    pcr=PCR,
    mask=None,
    extra=None,
    safe=1,
):
    config = CONFIG if config is None else config
    mask = sum(1 << pcr_index for pcr_index in SELECTED_PCRS) if mask is None else mask
    quote_message = struct.pack(">IH", 0xFF544347, 0x8018) + sized(
        b"\0\x0b" + bytes(32)
    )
    quote_message += sized(
        extra if extra is not None else qualification(nonce, device, config)
    )
    quote_message += struct.pack(">QIIBQ", 100, 0, 0, safe, 1)
    quote_message += (
        struct.pack(">IHB", 1, 0x000B, 3)
        + mask.to_bytes(3, "little")
        + sized(bytes.fromhex(pcr))
    )
    quote_signature = signing_key.sign(
        quote_message, padding.PKCS1v15(), hashes.SHA256()
    )
    return {
        "nonce": nonce,
        "config": config,
        "message": base64.b64encode(quote_message).decode(),
        "signature": base64.b64encode(quote_signature).decode(),
    }


@pytest.fixture
def setup(tmp_path):
    database_file = tmp_path / "test.db"
    api_client = TestClient(create_app(database_file, ADMIN))
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = (
        signing_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    enrollment_request = {
        "device": "node",
        "public_key": public_key_pem,
        "pcr_digest": PCR,
        "config_digest": config_digest(CONFIG),
    }
    enrollment_response = api_client.post(
        "/v1/enroll",
        json=enrollment_request,
        headers={"Authorization": "Bearer " + ADMIN},
    )
    assert enrollment_response.status_code == 201
    device_headers = {"Authorization": "Bearer " + enrollment_response.json()["token"]}
    return api_client, signing_key, device_headers, database_file, enrollment_request


def issue(api_client, device_headers):
    response = api_client.post("/v1/devices/node/challenge", headers=device_headers)
    assert response.status_code == 200
    return response.json()["nonce"]


def submit(api_client, device_headers, quote_evidence):
    response = api_client.post(
        "/v1/devices/node/attest", json=quote_evidence, headers=device_headers
    )
    assert response.status_code == 200
    return response.json()


def test_accept_replay_persistence(setup):
    api_client, signing_key, device_headers, database_file, _ = setup
    quote_evidence = signed(signing_key, issue(api_client, device_headers))
    assert submit(api_client, device_headers, quote_evidence)["accepted"]
    restarted_client = TestClient(create_app(database_file, ADMIN))
    assert (
        submit(restarted_client, device_headers, quote_evidence)["reason"]
        == "nonce_expired_or_replayed"
    )
    assert 'reason="verified"} 1' in api_client.get("/metrics").text


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ({"pcr": "01" * 32}, "pcr_drift"),
        ({"config": {"/etc/test": "tampered"}}, "config_drift"),
        ({"mask": 1}, "pcr_selection"),
        ({"extra": b"wrong nonce"}, "nonce_or_config_binding"),
        ({"safe": 0}, "unsafe_clock"),
        ({"device": "another-device"}, "nonce_or_config_binding"),
    ],
)
def test_policy_rejections(setup, mutation, reason):
    api_client, signing_key, device_headers, _, _ = setup
    quote_evidence = signed(signing_key, issue(api_client, device_headers), **mutation)
    assert submit(api_client, device_headers, quote_evidence)["reason"] == reason
    assert (
        submit(api_client, device_headers, quote_evidence)["reason"]
        == "nonce_expired_or_replayed"
    )


@pytest.mark.parametrize("field", ["signature", "message"])
def test_tamper(setup, field):
    api_client, signing_key, device_headers, _, _ = setup
    quote_evidence = signed(signing_key, issue(api_client, device_headers))
    tampered_bytes = bytearray(base64.b64decode(quote_evidence[field]))
    tampered_bytes[-1] ^= 1
    quote_evidence[field] = base64.b64encode(tampered_bytes).decode()
    assert (
        submit(api_client, device_headers, quote_evidence)["reason"]
        == "signature_invalid"
    )


def test_unsigned_config_tamper(setup):
    api_client, signing_key, device_headers, _, _ = setup
    quote_evidence = signed(signing_key, issue(api_client, device_headers))
    quote_evidence["config"] = {"fake": "approved"}
    assert (
        submit(api_client, device_headers, quote_evidence)["reason"]
        == "nonce_or_config_binding"
    )


def test_wrong_key(setup):
    api_client, _, device_headers, _, _ = setup
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert (
        submit(
            api_client,
            device_headers,
            signed(signing_key, issue(api_client, device_headers)),
        )["reason"]
        == "signature_invalid"
    )


def test_expiry(setup):
    api_client, signing_key, device_headers, database_file, _ = setup
    quote_evidence = signed(signing_key, issue(api_client, device_headers))
    with sqlite3.connect(database_file) as connection:
        connection.execute("UPDATE challenges SET expires=0")
    assert not submit(api_client, device_headers, quote_evidence)["accepted"]


def test_challenge_replacement(setup):
    api_client, signing_key, device_headers, _, _ = setup
    previous_evidence = signed(signing_key, issue(api_client, device_headers))
    current_evidence = signed(signing_key, issue(api_client, device_headers))
    assert not submit(api_client, device_headers, previous_evidence)["accepted"]
    assert submit(api_client, device_headers, current_evidence)["accepted"]


def test_concurrent_replay(setup):
    api_client, signing_key, device_headers, _, _ = setup
    quote_evidence = signed(signing_key, issue(api_client, device_headers))
    with ThreadPoolExecutor(max_workers=8) as workers:
        verdicts = list(
            workers.map(
                lambda _: submit(api_client, device_headers, quote_evidence), range(8)
            )
        )
    assert sum(response["accepted"] for response in verdicts) == 1


def test_admin_auth_and_duplicate(setup):
    api_client, _, device_headers, _, enrollment_request = setup
    assert (
        api_client.post(
            "/v1/enroll", json=enrollment_request, headers=device_headers
        ).status_code
        == 403
    )
    assert api_client.post("/v1/enroll", json=enrollment_request).status_code == 401
    assert (
        api_client.post(
            "/v1/enroll",
            json=enrollment_request,
            headers={"Authorization": "Bearer " + ADMIN},
        ).status_code
        == 409
    )
    assert api_client.get("/v1/events").status_code == 401
    assert (
        api_client.post(
            "/v1/devices/node/challenge", headers={"Authorization": "Bearer wrong"}
        ).status_code
        == 403
    )


def test_revocation(setup):
    api_client, signing_key, device_headers, _, _ = setup
    quote_evidence = signed(signing_key, issue(api_client, device_headers))
    assert (
        api_client.delete(
            "/v1/devices/node", headers={"Authorization": "Bearer " + ADMIN}
        ).status_code
        == 200
    )
    assert (
        api_client.post(
            "/v1/devices/node/attest", json=quote_evidence, headers=device_headers
        ).status_code
        == 403
    )


@pytest.mark.parametrize(
    "field,value", [("message", "@@@"), ("signature", "@@@"), ("message", "")]
)
def test_malformed(setup, field, value):
    api_client, signing_key, device_headers, _, _ = setup
    quote_evidence = signed(signing_key, issue(api_client, device_headers))
    quote_evidence[field] = value
    assert not submit(api_client, device_headers, quote_evidence)["accepted"]


def test_truncation_and_trailing_data(setup):
    _, signing_key, _, _, _ = setup
    quote_message = base64.b64decode(signed(signing_key, "00" * 32)["message"])
    for prefix_length in range(len(quote_message)):
        with pytest.raises(ValueError):
            parse_quote(quote_message[:prefix_length])
    with pytest.raises(ValueError):
        parse_quote(quote_message + b"extra")


def test_requires_admin_secret(tmp_path):
    with pytest.raises(RuntimeError):
        create_app(tmp_path / "bad.db", "short")
