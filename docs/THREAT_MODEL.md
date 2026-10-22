# Threat model

## What the verifier establishes

A party possessing the enrolled RSA key signed a quote with the current challenge,
the required PCR selection, and the enrolled PCR aggregate. The signature binds
the collected configuration report to that challenge. The verifier compares this
report's digest with the operator-approved configuration digest.

The enrolled public key is the root of this application's trust. Enrollment is
manual and authenticated; it does not establish manufacturer provenance. A
software-generated RSA key could forge TPM-shaped messages if an administrator
enrolled it. A production deployment must verify EK certificates and use
MakeCredential/ActivateCredential or an equivalent authenticated provisioning chain.

## Attacks exercised

- Signature/message corruption and wrong-key substitution.
- Replay after use, restart, expiry, challenge replacement, and concurrent submission.
- Incorrect nonce, cross-device binding, changed configuration, unexpected PCR bank/selection.
- Changed PCR state, truncated messages, trailing bytes, invalid base64, unsafe TPM clock.
- Unauthorized enrollment, overwrite attempts, incorrect device tokens, revoked devices.

## Trust boundaries and residual risks

- Root compromise can lie about files and Secure Boot. Qualification binds the
  reported bytes; it does not prove how those bytes were collected. Use kernel IMA
  and event-log verification for stronger configuration evidence.
- A TPM quote is a point-in-time measurement. Approved PCRs do not guarantee
  runtime safety, absence of malware, or protection against relay/cuckoo attacks.
- swtpm state and keys are files readable by the simulator host; there is no
  physical isolation. Container PCRs are synthetic and do not describe host boot.
- No boot event log is replayed. PCR drift identifies a mismatch, not its cause.
- TLS, administrator provisioning, device credentials, the verifier host/database,
  and the selected known-good baseline must be trusted.
- The safe-clock flag is required, but clock/reset counters are informational;
  freshness is enforced by verifier-side nonces and expiry, not TPM clock continuity.
- The verifier serializes SQLite writes during cryptographic verification. This
  favors consistency over scale and is unsuitable for high-volume untrusted traffic.
- Per-device authentication and bounded fields reduce abuse; production needs
  reverse-proxy request-size/rate limits and quotas. Authentication failures are
  represented by HTTP status, not by per-device attestation events.
- Bearer tokens grant reporting access, not attestation signing authority. Compromise
  can consume challenges and cause denial of service even without the AK.
- Metrics reveal inventory and verdicts; isolate them on a private monitoring network.
- No untrusted LLM or generated classification participates in security decisions.
