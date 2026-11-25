"""Measure retrieval quality on the curated synthetic eval set. Prints real numbers; invents none."""
import json, pathlib, sys, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from cyberrisk.db import Database
from cyberrisk.rag.store import RagStore

DATA = pathlib.Path(__file__).resolve().parent.parent / "cyberrisk" / "data"


def run(label, answerable, unanswerable, rs):
    hit1 = hit3 = 0; rr = 0.0; lat = []
    for item in answerable:
        t = time.perf_counter(); r = rs.query(item["q"], top_k=3); lat.append(time.perf_counter() - t)
        titles = [p["citation"]["title"] for p in r["passages"]]
        rank = next((i + 1 for i, t_ in enumerate(titles) if item["expect"].lower() in t_.lower()), None)
        hit1 += rank == 1; hit3 += rank is not None; rr += 1 / rank if rank else 0
    fp = 0
    for q in unanswerable:
        fp += rs.query(q)["status"] != "no_evidence_found"
    n = len(answerable)
    print(f"{label}: answerable={n} hit@1={hit1}/{n} hit@3={hit3}/{n} MRR={rr / n:.3f} | unanswerable={len(unanswerable)} "
          f"false_evidence={fp}/{len(unanswerable)} | mean query latency={1000 * sum(lat) / len(lat):.2f} ms")


if __name__ == "__main__":
    db = Database(":memory:"); db.migrate(); rs = RagStore(db)
    docs = sorted((DATA / "corpus").glob("*.md"))
    for p in docs:
        t = p.read_text(encoding="utf-8"); rs.ingest(t.splitlines()[0].lstrip("# ").strip(), t, "synthetic-corpus", synthetic=True)
    ev = json.loads((DATA / "rag_eval.json").read_text())
    print(f"corpus: {len(docs)} synthetic documents, {db.one('SELECT COUNT(*) c FROM chunks')['c']} chunks, embedder=hash-v1 (lexical, not semantic)")
    run("tuning set ", ev["answerable"], ev["unanswerable"], rs)
    run("held-out set", ev["heldout"]["answerable"], ev["heldout"]["unanswerable"], rs)
