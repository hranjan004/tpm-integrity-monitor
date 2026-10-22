"""End-to-end real swtpm quotes; never substitute mocks for these tests."""

import base64
import os
import pytest
from fastapi.testclient import TestClient
from integrity.agent import baseline, evidence, run
from integrity.crypto import qualification
from integrity.verifier import create_app

pytestmark = pytest.mark.skipif(
    not os.environ.get("TPM_AK"),
    reason="Run scripts/simulator.sh for real TPM integration",
)


def test_real_tpm_quote_and_attacks(tmp_path):
    config_file = tmp_path / "config"
    config_file.write_text("approved\n")
    watched_paths = [str(config_file)]
    administrator_secret = "integration-admin-" + "a" * 32
    api_client = TestClient(create_app(tmp_path / "verifier.db", administrator_secret))
    enrollment_request = baseline("real-tpm", os.environ["TPM_PEM"], watched_paths)
    enrollment_response = api_client.post(
        "/v1/enroll",
        json=enrollment_request,
        headers={"Authorization": "Bearer " + administrator_secret},
    )
    assert enrollment_response.status_code == 201
    device_headers = {"Authorization": "Bearer " + enrollment_response.json()["token"]}

    def quote():
        challenge_nonce = api_client.post(
            "/v1/devices/real-tpm/challenge", headers=device_headers
        ).json()["nonce"]
        return evidence(
            "real-tpm", challenge_nonce, os.environ["TPM_AK"], watched_paths
        )

    def submit(quote_evidence):
        attestation_response = api_client.post(
            "/v1/devices/real-tpm/attest", headers=device_headers, json=quote_evidence
        )
        assert attestation_response.status_code == 200
        return attestation_response.json()

    quote_evidence = quote()
    # Independently confirm our wire format/signature with upstream tpm2_checkquote.
    message_path, signature_data = tmp_path / "quote.msg", tmp_path / "quote.sig"
    message_path.write_bytes(base64.b64decode(quote_evidence["message"]))
    signature_data.write_bytes(base64.b64decode(quote_evidence["signature"]))
    run(
        "tpm2_checkquote",
        "-u",
        os.environ["TPM_PEM"],
        "-m",
        str(message_path),
        "-s",
        str(signature_data),
        "-g",
        "sha256",
        "-q",
        qualification(
            quote_evidence["nonce"], "real-tpm", quote_evidence["config"]
        ).hex(),
    )
    assert submit(quote_evidence)["accepted"]
    assert submit(quote_evidence)["reason"] == "nonce_expired_or_replayed"
    quote_evidence = quote()
    signature_data = bytearray(base64.b64decode(quote_evidence["signature"]))
    signature_data[0] ^= 1
    quote_evidence["signature"] = base64.b64encode(signature_data).decode()
    assert submit(quote_evidence)["reason"] == "signature_invalid"
    config_file.write_text("changed\n")
    assert submit(quote())["reason"] == "config_drift"
    config_file.write_text("approved\n")
    # PCR16 is a disposable application PCR; modifying it proves hardware-backed drift detection.
    run("tpm2_pcrextend", "16:sha256=" + "42" * 32)
    assert submit(quote())["reason"] == "pcr_drift"
