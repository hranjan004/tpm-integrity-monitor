"""End-to-end real swtpm quotes; never substitute mocks for these tests."""
import base64
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from integrity.agent import baseline, evidence, run
from integrity.crypto import qualification
from integrity.verifier import create_app

pytestmark = pytest.mark.skipif(not os.environ.get("TPM_AK"), reason="Run scripts/simulator.sh for real TPM integration")


def test_real_tpm_quote_and_attacks(tmp_path):
    config = tmp_path / "config"; config.write_text("approved\n")
    paths = [str(config)]
    admin = "integration-admin-" + "a" * 32
    client = TestClient(create_app(tmp_path / "verifier.db", admin))
    approved = baseline("real-tpm", os.environ["TPM_PEM"], paths)
    enrollment = client.post("/v1/enroll", json=approved, headers={"Authorization": "Bearer " + admin})
    assert enrollment.status_code == 201
    headers = {"Authorization": "Bearer " + enrollment.json()["token"]}

    def quote():
        nonce = client.post("/v1/devices/real-tpm/challenge", headers=headers).json()["nonce"]
        return evidence("real-tpm", nonce, os.environ["TPM_AK"], paths)

    def submit(body):
        r = client.post("/v1/devices/real-tpm/attest", headers=headers, json=body)
        assert r.status_code == 200
        return r.json()

    body = quote()
    # Independently confirm our wire format/signature with upstream tpm2_checkquote.
    msg, sig = tmp_path / "quote.msg", tmp_path / "quote.sig"
    msg.write_bytes(base64.b64decode(body["message"]))
    sig.write_bytes(base64.b64decode(body["signature"]))
    run("tpm2_checkquote", "-u", os.environ["TPM_PEM"], "-m", str(msg), "-s", str(sig), "-g", "sha256",
        "-q", qualification(body["nonce"], "real-tpm", body["config"]).hex())
    assert submit(body)["accepted"]
    assert submit(body)["reason"] == "nonce_expired_or_replayed"
    body = quote()
    sig = bytearray(base64.b64decode(body["signature"])); sig[0] ^= 1
    body["signature"] = base64.b64encode(sig).decode()
    assert submit(body)["reason"] == "signature_invalid"
    config.write_text("changed\n")
    assert submit(quote())["reason"] == "config_drift"
    config.write_text("approved\n")
    # PCR16 is a disposable application PCR; modifying it proves hardware-backed drift detection.
    run("tpm2_pcrextend", "16:sha256=" + "42" * 32)
    assert submit(quote())["reason"] == "pcr_drift"
