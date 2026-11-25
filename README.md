# Assay: explainable, replayable cyber-risk assessment

Final-year project (B.Tech CSE AI & ML, The NorthCap University) · owner: Sanchit Kumar.
Built from the *Final Project Handoff Brief* (9 Nov 2026). **Standard library only**: no `pip install`, no network, no paid credentials.

## What makes it different

| Idea | What it does | Where |
|---|---|---|
| **Replayable assessments** | Every run stores its exact evidence snapshot, policy hash and result hash. `GET /assessments/{id}/verify` re-scores from the snapshot and proves the stored result is reproducible. | `service.verify_run`, `domain/risk.py` |
| **Tamper-evident audit ledger** | Hash-chained, append-only (SQLite triggers block UPDATE/DELETE; the chain exposes anything bypassing them). Each assessment run is anchored in the chain. | `ledger.py` |
| **Counterfactual explanations** | Not just *why* the score is High, but *what would drop the level*: the exact factor score needed, and which single fix moves the score most (each verified by re-scoring). | `domain/risk.py::_counterfactuals` |
| **Honest missing data** | A factor with no evidence is never treated as zero: weights are renormalised, coverage is reported and the result is flagged `partial`. No evidence at all produces *no score*. | `domain/risk.py` |
| **AI is advisory only** | Intelligence and RAG supply evidence; the deterministic domain policy alone decides score and level. A test proves a poisoned document cannot change a score. | tests |

## Quick start (fresh clone, Python 3.11+)

```bash
export SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
export DATABASE_URL=sqlite:///./cyber_risk.db     # defaults shown in .env.example; the app reads real environment variables, not .env
python -m cyberrisk seed        # creates SYNTHETIC demo data; prints 3 user passwords ONCE
python -m cyberrisk serve       # http://127.0.0.1:8000
python -m unittest discover -s tests -t .      # 97 tests
python scripts/eval_rag.py      # retrieval evaluation on the synthetic corpus
python -m cyberrisk verify-ledger
```

Sign in at `/` as `analyst@demo.example`, `assessor@demo.example` or `admin@demo.example` with the printed passwords.

## Five-minute demo (matches brief §16)

1. **Dashboard** (any role): counts, risk distribution, open findings, jobs, recent activity.
2. **Vendors → Northwind Payments → "Annual third-party assessment"**: the *assay scale* shows the score needle on the 0–100 bands, each factor's contribution as a labelled segment and the dashed line where the level would drop.
3. Read the factor table (score, weight, contribution, rationale) and **What would change the risk level**.
4. **Intelligence**: normalised/deduplicated signals; the same phishing URL arrives from two sources in two spellings and becomes one indicator with corroborated confidence 0.88 and both provenance records kept.
5. **Evidence search**: ask *"How quickly must exploited critical vulnerabilities be patched?"*: cited passage; then ask about pizza → *no evidence found*.
6. As **analyst**, mark the RCE finding *resolved*; as **assessor**, *Run risk assessment*: score drops, old run stays verifiable.
7. **Create task** from a finding → move it across the **Workflows** board (illegal jumps such as todo→done are rejected).
8. **Generate report** → **Reports → Download** (Markdown or HTML with integrity proof).
9. **Assessment → Re-verify by replay** (✔), then as **admin**: **Audit ledger → Verify chain**.
10. Show tests, `/health/ready`, `/metrics` (admin) and `docs/STATUS.md` (limits).

## Layout

```
cyberrisk/domain        pure policy + risk engine + lifecycles (no framework imports)
cyberrisk/intelligence  normalise, parse, correlate        cyberrisk/rag  chunk, embed, retrieve, cite
cyberrisk/security      scrypt, HS256 tokens, RBAC, rate limit, SSRF guard, sanitiser
cyberrisk/service.py    orchestrator (use cases, transactions)   cyberrisk/jobs.py  queue + worker
cyberrisk/api.py        HTTP boundary                      cyberrisk/web  UI (no build step)
tests/                  97 tests (domain, intel/RAG, security, workers, persistence, e2e, UI smoke)
docs/                   ARCHITECTURE.md · STATUS.md (verified status) · EVALUATION.md
```

See `docs/STATUS.md` for exactly what is verified and what is not.
