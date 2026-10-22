# Validation record

Executed on October 22, 2026 in the harshranjan macOS development environment,
using Docker Desktop 28.0.4 and Linux containers. Work and commit chronology use
the actual execution date; this work is not represented as completed on October 15.

## Automated verification

22 tests passed with no skipped tests in the swtpm-enabled container. The real-TPM
integration test created a restricted RSA attestation key using tpm2-tools, verified
its quote with both the Python verifier and upstream `tpm2_checkquote`, and exercised
replay, signature tampering, configuration drift, and a real PCR16 extension.
API/unit tests additionally covered nonce expiry, restart persistence, eight-way
concurrent replay, wrong signing key, cross-device binding, PCR selection, unsafe
clock, malformed/truncated/trailing evidence, enrollment authorization, duplicate
enrollment, and revocation.

One third-party deprecation warning is emitted by Starlette's test client regarding
an AnyIO alias. It does not affect the test result.

## Live services

The HTTP demo passed all scenario assertions. Prometheus successfully scraped the
verifier, reporting 2 verified events, 1 replay rejection, 1 signature rejection,
1 configuration rejection, and 4 PCR drift rejections for the first demo device.
Grafana's API confirmed the provisioned `TPM Device Integrity` dashboard and all
three panels. Dashboard data comes from the verifier's actual events.

The existing host Grafana uses port 3000, so this project's Grafana uses port 3001.
An initial directory mount hid Grafana's default configuration; the final Compose
file mounts only provisioning and dashboards, and its API check passed.

## Scope and limits

No physical TPM or actual Linux measured boot was tested. All TPM integration ran
against swtpm inside Docker. Container Secure Boot is unknown. See the threat model
for the enrollment trust assumption and limits of agent-reported configuration.

Reviewed source, dependency configuration, secret exclusions, database resource
handling, subprocess argument handling, strict quote parsing, atomic replay handling,
and Compose exposure. No credentials or private keys are committed. Runtime secrets
are generated locally in the ignored `.env` file.
