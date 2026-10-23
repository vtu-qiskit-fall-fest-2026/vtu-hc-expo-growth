\# Q Guards — Requirements and Verification Matrix



\## Purpose



This matrix maps project requirements to implementation modules, tests, and evidence. It describes the current prototype and does not imply that unimplemented production requirements are complete.



\## Verification Matrix



| ID | Requirement | Feature / implementation | Module | Verification | Evidence / status |

|---|---|---|---|---|---|

| RQ-01 | Generate sensor telemetry | Simulated sensor readings and packet creation | `src/qguards/telemetry/sensor\_simulator.py`, `src/qguards/telemetry/packet.py` | Telemetry unit tests | Existing test suite; rerun before submission |

| RQ-02 | Establish a post-quantum shared secret | ML-KEM-768 encapsulation and decapsulation | `src/qguards/security/pq\_kem.py`, `src/qguards/security/key\_exchange.py` | Key agreement tests | `tests/unit/test\_pq\_kem.py`, `tests/unit/test\_key\_exchange.py` |

| RQ-03 | Derive a symmetric encryption key | HKDF-SHA256 derives a 32-byte key | `src/qguards/security/pq\_kem.py` | Matching derived-key and input-validation tests | `tests/unit/test\_pq\_kem.py` |

| RQ-04 | Protect telemetry confidentiality and integrity | AES-256-GCM encryption and authenticated decryption | `src/qguards/security/encryption.py` | Encryption and tampering tests | `tests/unit/test\_encryption.py`, `tests/security/test\_tampering.py` |

| RQ-05 | Authenticate message senders | HMAC validation using a separately provisioned key | `src/qguards/security/authentication.py`, gateway validation | Authentication and invalid-message tests | `tests/unit/test\_authentication.py`, `tests/security/test\_invalid\_messages.py` |

| RQ-06 | Reject replayed messages | Sequence/replay tracking | `src/qguards/security/replay\_protection.py`, gateway validation | Replay attack tests | `tests/unit/test\_replay\_protection.py`, `tests/security/test\_replay\_attack.py` |

| RQ-07 | Validate incoming packets | Check packet format, authentication, and message validity | `src/qguards/gateway/validator.py`, `src/qguards/gateway/receiver.py` | Integration and malformed-message tests | `tests/integration/test\_end\_to\_end.py`, `tests/security/test\_invalid\_messages.py` |

| RQ-08 | Generate security alerts | Alert handling for rejected or suspicious events | `src/qguards/gateway/alert\_manager.py` | Alert manager tests | `tests/unit/test\_alert\_manager.py` |

| RQ-09 | Record monitoring events | Event logging and security metrics | `src/qguards/monitoring/event\_logger.py`, `src/qguards/monitoring/metrics.py` | Logging and metrics tests | `tests/unit/test\_event\_logger.py`, `tests/unit/test\_metrics.py` |

| RQ-10 | Display system status | Streamlit monitoring interface | `dashboard/app.py` | Manual browser verification | User reported dashboard working; retain screenshot as submission evidence |

| RQ-11 | Demonstrate simulated quantum behavior | BB84 simulation with optional intercept-resend eavesdropping | `bb84\_protocol.py`, `experiment\_runner.py` | BB84 experiment tests | `tests/test\_bb84\_protocol.py`, `tests/test\_experiment\_runner.py`; simulation only |

| RQ-12 | Estimate QBER and flag threshold crossings | Configurable QBER assessment | `qber\_detector.py` | QBER boundary and input-validation tests | `tests/test\_qber\_detector.py`; threshold is illustrative |

| RQ-13 | Provide a reproducible entry point | Main application and demo scripts | `src/qguards/main.py`, `scripts/run\_demo.py` | Execute both commands from the repository root | Previously reported successful; rerun before submission |

| RQ-14 | Provide regression verification | Automated unit, integration, and security tests | `tests/` | `python -m pytest -q` | Previously reported: 137 passed, 8 subtests passed |

| RQ-15 | Keep security claims accurate | Document assumptions and limitations | `docs/threat\_model.md`, `docs/limitations.md` | Manual documentation review | Pending documentation completion |



\## Important Scope Boundaries



\- ML-KEM provides shared-secret establishment, not peer authentication by itself.

\- AES-GCM and HMAC are separate security mechanisms with separate key-management requirements.

\- BB84 and QBER outputs come from a simulation, not a physical quantum channel.

\- A passing test suite demonstrates tested behavior, not proof of production-grade security.

\- Performance, detection rates, and resource usage must be measured before numerical claims are published.



\## Submission Evidence Checklist



\- \[ ] Fresh full test-suite output saved.

\- \[ ] Fresh six-scenario security-demo output saved.

\- \[ ] Main application output saved.

\- \[ ] Dashboard screenshot captured.

\- \[ ] BB84 simulation output saved and labeled as simulated.

\- \[ ] Every referenced test and source path checked against the final repository.

\- \[ ] Official hackathon requirements and judging criteria linked when verified.