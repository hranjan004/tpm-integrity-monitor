"""Linux collector and tpm2-tools quote client. No shell evaluation of remote data."""
import argparse
import base64
import glob
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

import httpx
from .crypto import SELECTION, config_digest, qualification


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=20).stdout


def collect(paths):
    result = {}
    for name in sorted(paths):
        path = Path(name)
        try:
            result[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        except FileNotFoundError:
            result[str(path)] = "missing"
    variables = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
    result["secure_boot"] = "unknown"
    if variables:
        value = Path(variables[0]).read_bytes()
        result["secure_boot"] = "enabled" if len(value) >= 5 and value[4] == 1 else "disabled"
    return result


def evidence(device, nonce, ak, paths):
    config = collect(paths)
    with tempfile.TemporaryDirectory() as directory:
        msg, sig = Path(directory) / "quote.msg", Path(directory) / "quote.sig"
        run("tpm2_quote", "-c", ak, "-l", SELECTION, "-q", qualification(nonce, device, config).hex(),
            "-m", str(msg), "-s", str(sig), "-f", "plain", "-g", "sha256")
        return {"nonce": nonce, "config": config,
                "message": base64.b64encode(msg.read_bytes()).decode(),
                "signature": base64.b64encode(sig.read_bytes()).decode()}


def baseline(device, pem, paths):
    with tempfile.TemporaryDirectory() as directory:
        pcrs = Path(directory) / "pcrs"
        run("tpm2_pcrread", SELECTION, "-o", str(pcrs))
        values = pcrs.read_bytes()
        if len(values) != 128:
            raise RuntimeError("Expected exactly four SHA256 PCR values")
    return {"device": device, "public_key": Path(pem).read_text(),
            "pcr_digest": hashlib.sha256(values).hexdigest(),
            "config_digest": config_digest(collect(paths))}


def attest(client, device, ak, paths):
    challenge = client.post(f"/v1/devices/{device}/challenge")
    challenge.raise_for_status()
    body = evidence(device, challenge.json()["nonce"], ak, paths)
    response = client.post(f"/v1/devices/{device}/attest", json=body)
    response.raise_for_status()
    return response.json()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=["baseline", "once", "watch"])
    p.add_argument("--device", default="demo-node")
    p.add_argument("--url", default="http://localhost:8000")
    p.add_argument("--ak", default="0x81010002")
    p.add_argument("--pem", default="state/ak.pem")
    p.add_argument("--file", action="append", dest="paths", default=[])
    p.add_argument("--interval", type=int, default=30)
    a = p.parse_args()
    if a.interval < 1:
        p.error("interval must be positive")
    if a.command == "baseline":
        print(json.dumps(baseline(a.device, a.pem, a.paths), indent=2))
        return
    token = os.environ["DEVICE_TOKEN"]
    with httpx.Client(base_url=a.url, headers={"Authorization": "Bearer " + token}, timeout=30) as client:
        while True:
            try:
                result = attest(client, a.device, a.ak, a.paths)
                print(json.dumps(result), flush=True)
                if a.command == "once":
                    raise SystemExit(0 if result["accepted"] else 2)
            except (httpx.HTTPError, subprocess.SubprocessError, OSError) as exc:
                print(json.dumps({"accepted": False, "reason": "agent_error", "error": type(exc).__name__}), flush=True)
                if a.command == "once":
                    raise SystemExit(1)
            time.sleep(a.interval)


if __name__ == "__main__":
    main()
