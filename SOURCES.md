# Sources and references

These are the upstream tools and documents behind the project. The first two TPM manuals were consulted during the original implementation. The additional official references were checked while preparing this documentation. A link identifies the relevant upstream project; it does not imply that upstream reviewed or endorsed this code.

## TPM protocol and tooling

| Source | Used for | Project location |
|---|---|---|
| [tpm2_quote manual](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_quote.1/) | Quote output, signature format, PCR selection, qualification data | `integrity/agent.py` |
| [tpm2_checkquote manual](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_checkquote.1/) | Independent quote and nonce verification | `tests/test_tpm.py` |
| [swtpm upstream repository](https://github.com/stefanberger/swtpm) | Software TPM and socket-based test environment | `scripts/simulator.sh`, `Dockerfile` |

The verifier's supported quote profile is intentionally narrow. Its wire-format handling is tested against tpm2-tools output, including an independent checkquote call. The manual links track upstream documentation; the validation record describes what this project actually ran.

## Application and monitoring

| Source | Role in this project |
|---|---|
| [FastAPI documentation](https://fastapi.tiangolo.com/) | HTTP endpoints, request validation, and generated API documentation |
| [cryptography RSA documentation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/) | Public key loading and RSA signature verification |
| [Prometheus overview](https://prometheus.io/docs/introduction/overview/) | Metrics collection and time-series monitoring |
| [Grafana provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/) | Dashboard and data-source configuration kept in Git |

## Other installed tools

Python's standard library supplies hashing, JSON, SQLite, subprocess execution, and temporary files. Uvicorn serves FastAPI. HTTPX sends agent requests. Pydantic validates API models. pytest runs tests. Docker Compose runs the services, and GitHub Actions repeats the Linux build and tests.

Exact Python dependencies are recorded in [requirements.lock](requirements.lock). Service image versions are in [compose.yaml](compose.yaml). These files are the version record for this repository; latest upstream documentation may describe newer releases.

## Project-specific choices

The fixed PCR set, report-binding format, enrollment rules, single-use challenge storage, demo scenarios, and dashboard queries are implemented in this repository. They are design choices for this lab, not a claim of compliance with a complete production attestation standard.
