"""Fresh enrollment each run; emits real verifier decisions, then monitors briefly."""

import base64
import json
import os
from pathlib import Path
import secrets
import time
import httpx
from integrity.agent import baseline, evidence, run

verifier_url = os.environ.get("VERIFIER_URL", "http://localhost:8000")
device_id = "demo-" + secrets.token_hex(4)
config_file = Path("/tmp/demo-security.conf")
config_file.write_text("remote_admin=disabled\n")
watched_paths = [str(config_file)]
with httpx.Client(base_url=verifier_url, timeout=30) as verifier_client:
    response = verifier_client.post(
        "/v1/enroll",
        json=baseline(device_id, os.environ["TPM_PEM"], watched_paths),
        headers={"Authorization": "Bearer " + os.environ["ADMIN_TOKEN"]},
    )
    response.raise_for_status()
    verifier_client.headers["Authorization"] = "Bearer " + response.json()["token"]

    def quote():
        response = verifier_client.post(f"/v1/devices/{device_id}/challenge")
        response.raise_for_status()
        return evidence(
            device_id, response.json()["nonce"], os.environ["TPM_AK"], watched_paths
        )

    def submit(scenario_name, quote_evidence, expected_reason):
        response = verifier_client.post(
            f"/v1/devices/{device_id}/attest", json=quote_evidence
        )
        response.raise_for_status()
        verdict = response.json()
        print(json.dumps({"scenario": scenario_name, **verdict}), flush=True)
        assert verdict["reason"] == expected_reason, verdict

    quote_evidence = quote()
    submit("healthy", quote_evidence, "verified")
    submit("replay", quote_evidence, "nonce_expired_or_replayed")
    quote_evidence = quote()
    tampered_signature = bytearray(base64.b64decode(quote_evidence["signature"]))
    tampered_signature[-1] ^= 1
    quote_evidence["signature"] = base64.b64encode(tampered_signature).decode()
    submit("signature tamper", quote_evidence, "signature_invalid")
    config_file.write_text("remote_admin=enabled\n")
    submit("configuration drift", quote(), "config_drift")
    config_file.write_text("remote_admin=disabled\n")
    submit("restored configuration", quote(), "verified")
    run("tpm2_pcrextend", "16:sha256=" + "42" * 32)
    submit("PCR drift", quote(), "pcr_drift")
    for _ in range(3):
        time.sleep(5)
        submit("periodic monitor", quote(), "pcr_drift")
print("Demo completed; view Grafana at http://localhost:3001/d/tpm-integrity")
