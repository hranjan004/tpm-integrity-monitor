# Physical Linux TPM

Install `tpm2-tools` and Python 3.11+, create a virtual environment, and install
`pip install -e '.[test]'`. Use `TPM2TOOLS_TCTI=device:/dev/tpmrm0` and grant only the
agent account access to that device. Inspect `tpm2_getcap properties-fixed` and
`tpm2_getcap handles-persistent` before choosing unused persistent handles.
Do not run the simulator provisioning script against real hardware.

Under controlled provisioning, create an EK and restricted AK with
`tpm2_createek` / `tpm2_createak`, persist the AK using `tpm2_evictcontrol`, and
export its PEM public key. Handle values and hierarchy authorization depend on
your machine; never evict existing platform keys to make this example fit.
Generate the baseline **only on a separately approved, known-good platform**:

```sh
mkdir -p state
integrity-agent baseline --device server-01 --pem state/ak.pem \
  --file /etc/ssh/sshd_config > state/enrollment.json
```

Transfer this baseline to the administrator over a trusted channel and submit it
with the admin credential to `POST /v1/enroll`. Securely install the returned token
in the agent's environment, then run:

```sh
integrity-agent watch --device server-01 --ak 0x81010002 \
  --url https://verifier.example --file /etc/ssh/sshd_config --interval 30
```

Set `DEVICE_TOKEN` from a protected service credential, not a command-line argument.
The client validates HTTPS certificates by default. Terminate TLS at a trusted
reverse proxy for remote use. The Compose HTTP configuration is a localhost lab.
The collector reports EFI Secure Boot as enabled, disabled, or unknown; containers
usually report unknown. Secure Boot is not claimed merely because a quote verifies.


See [the threat model](THREAT_MODEL.md) before enrolling real devices.
