# Verified status (honest)

Verified = exercised by an automated test or a manual run in the build sandbox (Python 3.12, Linux). Nothing here was run against your original repository or ZIPs, which were **not provided**; this is a clean implementation of the brief.

| Layer | Status | Evidence |
|---|---|---|
| Domain (policy, scoring, lifecycles) | Complete, verified | 21 tests incl. boundaries, invalid weights, determinism, counterfactual arithmetic |
| Intelligence (normalise/dedupe/correlate) | Complete for local/inline sources | 8 tests; no live feeds |
| RAG (ingest/chunk/retrieve/cite) | Working with a **lexical dev embedder** | 10 tests + eval; not semantic |
| Models layer (ModelRegistry, RiskModel, AnomalyDetector, TextClassifier, PyTorch/HF) | **Not implemented** | Deliberately omitted: no trained model exists to evaluate, and the brief forbids unmeasured ML claims. Hook point: `EmbeddingProvider`, advisory evidence items |
| Services/orchestrator | Complete, verified | e2e tests |
| Persistence | SQLite + migrations, verified; PostgreSQL **not tested** | persistence tests |
| Security | Implemented, verified by negative tests | 29 tests. Not independently pen-tested; no token revocation list (short TTL only); no MFA |
| Observability | Logs/metrics/health verified; tracing is span logging only | no OpenTelemetry |
| Workers | Verified with fake clock + real thread | in-process DB-backed queue; no broker |
| API | Verified over HTTP sockets | stdlib server, not FastAPI (FastAPI/pydantic were not installable in the build sandbox; untested code was not shipped) |
| Frontend | Executed under Node with a fake DOM against a live server | **Not viewed in a real browser**; visual layout, responsiveness and dark mode are unverified |
| Docker / deployment / CI | Not provided | |

## Known limitations / risks
* Single locked SQLite connection: fine for a prototype, not for concurrency at scale.
* Ledger head should be anchored off-box to defeat a full-chain rewrite by someone with file access.
* Rate limiter state is in memory (per process).
* Demo data is synthetic (`.example` domains, documentation IPs, `CVE-2099-*`); never present it as live intelligence.
* Owner decisions needed: half-open bands, missing-data renormalisation policy, "accepted ≠ resolved", the 63 vs 64 illustration, and whether to migrate the API layer to FastAPI.
* Confirm the academic deadline and whether the evaluation requires FastAPI/PostgreSQL specifically.
