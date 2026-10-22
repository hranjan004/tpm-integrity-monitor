"""Fresh enrollment each run; emits real verifier decisions, then monitors briefly."""
import base64
import json
import os
from pathlib import Path
import secrets
import time
import httpx
from integrity.agent import baseline, evidence, run

url = os.environ.get("VERIFIER_URL", "http://localhost:8000")
device = "demo-" + secrets.token_hex(4)
config = Path("/tmp/demo-security.conf")
config.write_text("remote_admin=disabled\n")
paths = [str(config)]
with httpx.Client(base_url=url, timeout=30) as client:
    r = client.post("/v1/enroll", json=baseline(device, os.environ["TPM_PEM"], paths),
                    headers={"Authorization": "Bearer " + os.environ["ADMIN_TOKEN"]})
    r.raise_for_status()
    client.headers["Authorization"] = "Bearer " + r.json()["token"]

    def quote():
        r = client.post(f"/v1/devices/{device}/challenge"); r.raise_for_status()
        return evidence(device, r.json()["nonce"], os.environ["TPM_AK"], paths)

    def submit(label, body, expected):
        r = client.post(f"/v1/devices/{device}/attest", json=body); r.raise_for_status()
        result = r.json()
        print(json.dumps({"scenario": label, **result}), flush=True)
        assert result["reason"] == expected, result

    body = quote()
    submit("healthy", body, "verified")
    submit("replay", body, "nonce_expired_or_replayed")
    body = quote()
    sig = bytearray(base64.b64decode(body["signature"])); sig[-1] ^= 1
    body["signature"] = base64.b64encode(sig).decode()
    submit("signature tamper", body, "signature_invalid")
    config.write_text("remote_admin=enabled\n")
    submit("configuration drift", quote(), "config_drift")
    config.write_text("remote_admin=disabled\n")
    submit("restored configuration", quote(), "verified")
    run("tpm2_pcrextend", "16:sha256=" + "42" * 32)
    submit("PCR drift", quote(), "pcr_drift")
    for _ in range(3):
        time.sleep(5)
        submit("periodic monitor", quote(), "pcr_drift")
print("Demo completed; view Grafana at http://localhost:3001/d/tpm-integrity")
