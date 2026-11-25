"""Ingestion + hybrid retrieval with cited passages. RAG is an EVIDENCE PROVIDER: it never scores risk."""
from __future__ import annotations

import hashlib
import json
import math
from typing import Optional

from ..db import Database, new_id, utcnow_iso
from ..observability import span
from ..security.sanitize import clean_text, injection_suspected
from .chunking import chunk_text
from .embeddings import EmbeddingProvider, HashEmbedding, cosine, tokens

ALLOWED_MEDIA = ("text/plain", "text/markdown")
MAX_DOC_BYTES = 200_000
MIN_SCORE = 0.30  # tuned on data/rag_eval.json; see docs/EVALUATION.md


class RagError(ValueError):
    pass


class RagStore:
    def __init__(self, db: Database, embedder: Optional[EmbeddingProvider] = None, min_score: float = MIN_SCORE):
        self.db, self.embedder, self.min_score = db, embedder or HashEmbedding(), min_score

    def ingest(self, title: str, text: str, source: str, media_type: str = "text/markdown", synthetic: bool = False) -> dict:
        if media_type not in ALLOWED_MEDIA:
            raise RagError(f"media_type must be one of {ALLOWED_MEDIA}")
        raw = text.encode("utf-8", errors="strict")
        if len(raw) > MAX_DOC_BYTES:
            raise RagError(f"document exceeds {MAX_DOC_BYTES} bytes")
        if "\x00" in text:
            raise RagError("binary content is not accepted")
        title, source = clean_text(title, 200), clean_text(source, 200)
        text = text.replace("\r\n", "\n").strip()
        if not text:
            raise RagError("document is empty")
        digest = hashlib.sha256(text.encode()).hexdigest()
        with self.db.tx():
            existing = self.db.one("SELECT id FROM documents WHERE content_hash=?", (digest,))
            if existing:
                return {"document_id": existing["id"], "duplicate": True, "chunks": self._count(existing["id"])}
            doc_id = new_id("doc")
            self.db.execute("INSERT INTO documents VALUES(?,?,?,?,?,?,?,?)",
                            (doc_id, title, source, digest, media_type, len(raw), int(synthetic), utcnow_iso()))
            chunks = chunk_text(text)
            for c in chunks:
                self.db.execute("INSERT INTO chunks VALUES(?,?,?,?,?,?)",
                                (f"{doc_id}:{c.ordinal}", doc_id, c.ordinal, c.text, c.char_start,
                                 json.dumps(self.embedder.embed(c.text), separators=(",", ":"))))
        return {"document_id": doc_id, "duplicate": False, "chunks": len(chunks), "content_hash": digest}

    def _count(self, doc_id: str) -> int:
        return self.db.one("SELECT COUNT(*) c FROM chunks WHERE document_id=?", (doc_id,))["c"]

    def query(self, question: str, top_k: int = 4) -> dict:
        question = clean_text(question, 500)
        qtoks = set(tokens(question))
        if not qtoks:
            return {"status": "no_evidence_found", "reason": "query has no searchable terms", "passages": []}
        rows = self.db.all("SELECT c.id, c.document_id, c.ordinal, c.text, c.char_start, c.embedding, d.title, d.source, d.content_hash, d.synthetic "
                           "FROM chunks c JOIN documents d ON d.id=c.document_id")
        if not rows:
            return {"status": "no_evidence_found", "reason": "corpus is empty", "passages": []}
        with span("rag.query"):
            ctoks = [set(tokens(r["text"])) for r in rows]
            n = len(rows)
            idf = {t: math.log(1 + n / (1 + sum(1 for s in ctoks if t in s))) for t in qtoks}
            denom = sum(idf.values()) or 1.0
            qvec = self.embedder.embed(question)
            scored = []
            for r, toks in zip(rows, ctoks):
                cov = sum(idf[t] for t in qtoks if t in toks) / denom
                cos = cosine(qvec, {int(k): v for k, v in json.loads(r["embedding"]).items()})
                scored.append((0.5 * cov + 0.5 * max(cos, 0.0), cov, r))
            scored.sort(key=lambda s: (-s[0], s[2]["id"]))
        passages = []
        for score, cov, r in scored[:top_k]:
            if score < self.min_score or cov < 0.34:
                continue
            passages.append({
                "text": r["text"], "score": round(score, 4), "untrusted": True,
                "injection_suspected": injection_suspected(r["text"]),
                "citation": {"document_id": r["document_id"], "chunk_id": r["id"], "title": r["title"], "source": r["source"],
                             "content_hash": r["content_hash"], "ordinal": r["ordinal"], "char_start": r["char_start"],
                             "synthetic": bool(r["synthetic"])}})
        if not passages:
            return {"status": "no_evidence_found", "reason": "no passage scored above the evidence threshold", "passages": []}
        return {"status": "ok", "passages": passages}

    def citation_valid(self, citation: dict) -> bool:
        row = self.db.one("SELECT d.content_hash FROM chunks c JOIN documents d ON d.id=c.document_id WHERE c.id=? AND d.id=?",
                          (citation.get("chunk_id"), citation.get("document_id")))
        return bool(row) and row["content_hash"] == citation.get("content_hash")
