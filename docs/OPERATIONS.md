# Operations

## Configuration

Verifier: `ADMIN_TOKEN` (minimum 32 characters), `INTEGRITY_DB` (default
`state/verifier.db`). Generate high-entropy tokens, restrict state-directory access,
and back up SQLite with its backup API or while the service is stopped. Do not copy
only the main database while its WAL is active.

Agent: `DEVICE_TOKEN`, `TPM2TOOLS_TCTI`; CLI options select device, AK handle,
verifier URL, files, interval. `once` exits 0 on acceptance, 2 on rejection, and 1 on
transport/collection/tool failures. `watch` logs errors and retries on the next interval.
The simulator generates an empty-auth AK only inside its disposable isolated TPM.
Use TPM hierarchy/key authorization and restricted service accounts in real deployments.

## Events and monitoring

`GET /v1/events` requires the admin token and returns the last 100 decisions.
SQLite retains full history; configure an explicit retention/archive procedure for
long-running use. Logs emit the same JSON decision fields. Start uvicorn with an
appropriate logging configuration if forwarding application INFO logs to a collector.

Metrics expose counters by device/reason, last verdict, and last report timestamp.
Prometheus alerts cover rejected reports, stale reports (>120 seconds), and verifier
unavailability. Latest trust is meaningful only alongside freshness. The sample
demo stops reporting intentionally and will become stale. Prometheus/Grafana state
is disposable; the verifier SQLite volume is persistent. Devices that never report
are not yet represented in these event-derived metrics.

## Enrollment, rotation, decommissioning

Validate AK identity and known-good measurements out of band. Keep the admin token
off unattended agents; the demo container gets it only to bootstrap disposable nodes.
For rotation, enroll a new device ID, install its new credential, verify it, and
`DELETE /v1/devices/{old_id}` with the administrator token. Revocation preserves audit
history. Securely erase device credentials and follow platform-specific procedures
for TPM object disposal. Never clear a physical TPM without understanding disk
encryption and other platform dependencies.

## Troubleshooting

- Docker unavailable: start Docker Desktop/Engine and check `docker info`.
- TPM object memory errors: clear transient contexts on the disposable simulator;
  do not flush arbitrary contexts on a shared hardware TPM.
- PCR drift: inspect selected PCRs and firmware/boot changes, review known-good
  provenance, then explicitly enroll a new approved baseline. Never auto-learn.
- Config drift: compare configured file paths and hashes. A missing file is an
  explicit `missing` value, not silently ignored.
- Nonce rejection: request a new challenge; do not retry evidence with an old nonce.
- Container Secure Boot unknown: expected; it does not attest the host's EFI state.

## Reproducibility

Python dependencies (including transitives in `requirements.lock`) and container
image versions are pinned. OS packages are resolved during build, so builds are repeatable
in procedure but not bit-for-bit hermetic. A production pipeline should maintain the lockfile,
pin image digests, and regularly scan/update them.
