# A tour of the system

## 1. Know the terms

| Term | Meaning here |
|---|---|
| TPM | The component that holds the signing key and PCR measurements |
| AK | Attestation key; its public half is pinned during enrollment |
| PCR | A register that accumulates measurements through hashing |
| Quote | A signed TPM message containing selected PCR information |
| Nonce | A fresh random challenge that can be used once |
| Baseline | Measurements the administrator has approved |
| Drift | A measurement no longer matches that baseline |

## 2. Follow one report

```mermaid
sequenceDiagram
    actor Admin as Administrator
    participant Agent as Linux agent
    participant TPM as TPM or swtpm
    participant API as Verifier
    participant DB as SQLite
    Admin->>API: Enroll approved public key and baseline
    API-->>Admin: Device token
    Admin->>Agent: Install device token
    Agent->>API: Request challenge with device token
    API->>DB: Store random nonce with 60-second expiry
    API-->>Agent: Nonce and PCR selection
    Agent->>Agent: Hash watched files and read Secure Boot state
    Agent->>TPM: Quote with nonce + device + report binding
    TPM-->>Agent: Signed TPM quote
    Agent->>API: Nonce, report, message, signature
    API->>DB: Lock transaction and consume current nonce
    API->>API: Check signature, binding, and policy
    API->>DB: Save verdict and commit
    API-->>Agent: Accepted or rejection reason
```

A new challenge replaces the previous one for that device. A failed submission with the current nonce consumes it too. Database transactions prevent two workers from accepting the same challenge.

## 3. Look inside the quote

```mermaid
flowchart TD
    Files[Watched file hashes and Secure Boot report] --> Binding
    Nonce[Server nonce] --> Binding
    Device[Device ID] --> Binding
    Binding[SHA256 of domain separator and canonical JSON] --> Extra[Quote qualification field]
    PCRs[SHA256 PCRs 0, 2, 7, 16] --> Aggregate[SHA256 of selected PCR values]
    Aggregate --> Digest[Quote PCR digest]
    Extra --> Message[TPMS_ATTEST message]
    Digest --> Message
    Metadata[Type, signer, clock, firmware, selection] --> Message
    Message --> Signature[RSA PKCS1 v1.5 signature with SHA256]
```

The supported profile uses one SHA256 bank and exactly PCRs 0, 2, 7, and 16. The verifier checks the bank and selection explicitly. It compares the signed PCR digest with the approved aggregate.

The report binding prevents changing reported configuration after signing. It does not prove that a compromised agent reported the real file contents.

## 4. See why a report passes or fails

```mermaid
flowchart TD
    Request[Evidence arrives] --> Auth{Valid device token?}
    Auth -->|No| HTTP[HTTP 401 or 403]
    Auth -->|Yes| Nonce{Current unexpired nonce?}
    Nonce -->|No| Replay[Reject expired or replayed nonce]
    Nonce -->|Yes| Consume[Consume nonce in transaction]
    Consume --> Signature{Valid enrolled-key signature?}
    Signature -->|No| BadSignature[Reject signature or malformed evidence]
    Signature -->|Yes| Format{Supported quote and safe clock?}
    Format -->|No| BadFormat[Reject malformed quote or policy]
    Format -->|Yes| Binding{Nonce, device and config binding match?}
    Binding -->|No| BadBinding[Reject report binding]
    Binding -->|Yes| PCR{PCR digest matches?}
    PCR -->|No| PCRDrift[Reject PCR drift]
    PCR -->|Yes| Config{Config digest matches?}
    Config -->|No| ConfigDrift[Reject config drift]
    Config -->|Yes| Pass[Accept verified report]
```

API shape validation can return HTTP 422 before evidence processing. The diagram shows the path for a structurally valid request. A malformed signature or quote never produces acceptance.

## 5. Read the dashboard

```mermaid
flowchart LR
    Verdicts[(Stored verdicts)] --> Latest[Latest verdict: 1 or 0]
    Verdicts --> Counts[Counts by rejection reason]
    Verdicts --> Age[Seconds since last report]
    Latest --> Review[Read verdict and freshness together]
    Counts --> Review
    Age --> Review
```

| Panel | What to look for |
|---|---|
| Latest attestation verdict | `1` means the last submitted report passed; `0` means it failed |
| Attestations by result | Which reasons are increasing, and on which device |
| Seconds since last report | Whether a device has stopped reporting |

The demo ends with intentional PCR drift. A failed verdict at its end is expected. Later, its report age increases because the demo has stopped. Alert rules flag rejection, reports older than 120 seconds, and verifier outages. No notification destination is configured.

## 6. Follow the device lifecycle

```mermaid
stateDiagram-v2
    [*] --> Unenrolled
    Unenrolled --> Enrolled: Admin approves key and baseline
    Enrolled --> Reporting: Install device token
    Reporting --> Reporting: Challenge and verify
    Reporting --> Rejected: Drift or invalid evidence
    Rejected --> Reporting: Fresh report matches approved state
    Enrolled --> Revoked: Admin revokes identity
    Reporting --> Revoked: Admin revokes identity
    Rejected --> Revoked: Admin revokes identity
    Revoked --> [*]
```

Revocation disables authentication and removes the pending challenge. History stays in SQLite. An existing enrollment cannot be overwritten. Rotation and baseline changes use a new reviewed device identity.

## 7. Understand the trust boundary

```mermaid
flowchart LR
    Operator[Trusted enrollment operator] --> Pin[Approved public key and baseline]
    Pin --> Verifier[Trusted verifier and database]
    Agent[Agent-reported file hashes] --> Quote[Signed report binding]
    TPM[TPM-held signing key] --> Quote
    Quote --> Verifier
    Host[Simulator host can access swtpm state] -.-> TPM
```

The software TPM is suitable for testing the protocol. Its host can access its state. A physical TPM adds isolation, but trusted enrollment and honest measurement collection still matter. See the [threat model](THREAT_MODEL.md) for the remaining assumptions.

## 8. Find the code

| File | Responsibility |
|---|---|
| `integrity/agent.py` | Collect files, request quotes, submit reports, repeat |
| `integrity/crypto.py` | Parse the quote and verify its signature and binding |
| `integrity/verifier.py` | Authenticate, enroll, consume nonces, store results |
| `scripts/simulator.sh` | Start swtpm and provision the demo key |
| `scripts/demo.py` | Run the attack and recovery scenarios |
| `tests/test_tpm.py` | Exercise actual tpm2-tools commands against swtpm |
| `tests/test_verifier.py` | Exercise API, parser, policy, and replay cases |
| `monitoring/` | Configure metrics, alert rules, and dashboards |
