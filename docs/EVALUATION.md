# Evaluation (measured, with limits)

Environment: Python 3.12.3, Linux sandbox, single process, in-memory SQLite for tests. Numbers below were produced by `python scripts/eval_rag.py` and `python -m unittest` in that environment. They are **not** performance or accuracy claims about real-world use.

## Tests
97 tests, all passing on a fresh copy: domain 21 · intelligence/RAG 18 · security 29 · workers/persistence 16 · end-to-end 10 · UI smoke 3 (≈34 s total). Bugs found and fixed by the tests during development: counterfactual rounding boundary, API-key creator foreign key, metrics label collision, dashboard rendering a Promise.

## Retrieval (hash-embedding development adapter)
Corpus: 6 synthetic documents → 6 chunks (each document is one chunk).

| Set | Answerable hit@1 | hit@3 | MRR | Unanswerable returning evidence |
|---|---|---|---|---|
| Tuning (10 q + 4 off-topic) | 10/10 | 10/10 | 1.000 | 0/4 |
| Held-out (6 q + 3 off-topic, written before they were run) | 6/6 | 6/6 | 1.000 | 0/3 |

Mean query latency ≈ 0.8 ms. **Limits**: tiny corpus of clearly distinct topics, so perfect scores demonstrate the mechanics (hybrid scoring, thresholded *no-evidence-found*, valid citations), **not** semantic retrieval quality. The embedder is lexical; synonym/paraphrase queries would fail. One tuning-set question initially missed until a general stemming rule ("-ation") was added; the threshold (0.30) and stemmer were set using the tuning set only. A semantic provider can be dropped in behind `EmbeddingProvider`.

## Not measured
Throughput under load, large-corpus behaviour, browser rendering, accessibility audit, cross-browser support, PostgreSQL, any ML model quality (none is shipped).
