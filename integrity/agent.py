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
from .crypto import PCR_SELECTION, config_digest, qualification


def run(*command_arguments):
    return subprocess.run(
        command_arguments, check=True, capture_output=True, timeout=20
    ).stdout


def collect(watched_paths):
    report = {}
    for file_name in sorted(watched_paths):
        file_path = Path(file_name)
        try:
            report[str(file_path)] = hashlib.sha256(file_path.read_bytes()).hexdigest()
        except FileNotFoundError:
            report[str(file_path)] = "missing"
    secure_boot_variables = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
    report["secure_boot"] = "unknown"
    if secure_boot_variables:
        secure_boot_bytes = Path(secure_boot_variables[0]).read_bytes()
        report["secure_boot"] = (
            "enabled"
            if len(secure_boot_bytes) >= 5 and secure_boot_bytes[4] == 1
            else "disabled"
        )
    return report


def evidence(device_id, challenge_nonce, attestation_key, watched_paths):
    configuration = collect(watched_paths)
    with tempfile.TemporaryDirectory() as temporary_directory:
        message_path, signature_path = (
            Path(temporary_directory) / "quote.msg",
            Path(temporary_directory) / "quote.sig",
        )
        run(
            "tpm2_quote",
            "-c",
            attestation_key,
            "-l",
            PCR_SELECTION,
            "-q",
            qualification(challenge_nonce, device_id, configuration).hex(),
            "-m",
            str(message_path),
            "-s",
            str(signature_path),
            "-f",
            "plain",
            "-g",
            "sha256",
        )
        return {
            "nonce": challenge_nonce,
            "config": configuration,
            "message": base64.b64encode(message_path.read_bytes()).decode(),
            "signature": base64.b64encode(signature_path.read_bytes()).decode(),
        }


def baseline(device_id, public_key_path, watched_paths):
    with tempfile.TemporaryDirectory() as temporary_directory:
        pcr_values_path = Path(temporary_directory) / "pcrs"
        run("tpm2_pcrread", PCR_SELECTION, "-o", str(pcr_values_path))
        pcr_values = pcr_values_path.read_bytes()
        if len(pcr_values) != 128:
            raise RuntimeError("Expected exactly four SHA256 PCR values")
    return {
        "device": device_id,
        "public_key": Path(public_key_path).read_text(),
        "pcr_digest": hashlib.sha256(pcr_values).hexdigest(),
        "config_digest": config_digest(collect(watched_paths)),
    }


def attest(verifier_client, device_id, attestation_key, watched_paths):
    challenge_response = verifier_client.post(f"/v1/devices/{device_id}/challenge")
    challenge_response.raise_for_status()
    quote_evidence = evidence(
        device_id, challenge_response.json()["nonce"], attestation_key, watched_paths
    )
    attestation_response = verifier_client.post(
        f"/v1/devices/{device_id}/attest", json=quote_evidence
    )
    attestation_response.raise_for_status()
    return attestation_response.json()


def main():
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("command", choices=["baseline", "once", "watch"])
    argument_parser.add_argument("--device", default="demo-node")
    argument_parser.add_argument("--url", default="http://localhost:8000")
    argument_parser.add_argument("--ak", default="0x81010002")
    argument_parser.add_argument("--pem", default="state/ak.pem")
    argument_parser.add_argument("--file", action="append", dest="paths", default=[])
    argument_parser.add_argument("--interval", type=int, default=30)
    options = argument_parser.parse_args()
    if options.interval < 1:
        argument_parser.error("interval must be positive")
    if options.command == "baseline":
        print(
            json.dumps(baseline(options.device, options.pem, options.paths), indent=2)
        )
        return
    device_token = os.environ["DEVICE_TOKEN"]
    with httpx.Client(
        base_url=options.url,
        headers={"Authorization": "Bearer " + device_token},
        timeout=30,
    ) as verifier_client:
        while True:
            try:
                report = attest(
                    verifier_client, options.device, options.ak, options.paths
                )
                print(json.dumps(report), flush=True)
                if options.command == "once":
                    raise SystemExit(0 if report["accepted"] else 2)
            except (httpx.HTTPError, subprocess.SubprocessError, OSError) as error:
                print(
                    json.dumps(
                        {
                            "accepted": False,
                            "reason": "agent_error",
                            "error": type(error).__name__,
                        }
                    ),
                    flush=True,
                )
                if options.command == "once":
                    raise SystemExit(1)
            time.sleep(options.interval)


if __name__ == "__main__":
    main()
