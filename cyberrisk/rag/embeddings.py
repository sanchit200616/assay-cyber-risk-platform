"""Embedding adapters. HashEmbedding is a DEVELOPMENT/TEST adapter (feature hashing of stemmed
unigrams+bigrams). It captures lexical overlap, not semantics. Swap in a semantic provider by
implementing the EmbeddingProvider protocol."""
from __future__ import annotations

import hashlib
import math
import re
from typing import Dict, List, Protocol

STOP = frozenset("a an the and or of to in on for with is are was be been by at as it this that these those from how what when "
                 "who which should must do does we our you your can could would will shall there their they not no any all".split())


def stem(tok: str) -> str:
    for suf in ("ation", "ing", "ed", "es", "s", "ly"):
        if len(tok) > len(suf) + 3 and tok.endswith(suf):
            return tok[: -len(suf)]
    return tok


def tokens(text: str) -> List[str]:
    return [stem(t) for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in STOP and len(t) > 1]


class EmbeddingProvider(Protocol):
    name: str
    dim: int

    def embed(self, text: str) -> Dict[int, float]: ...


class HashEmbedding:
    name = "hash-v1"

    def __init__(self, dim: int = 512):
        self.dim = dim

    def _slot(self, feat: str) -> tuple[int, float]:
        h = int.from_bytes(hashlib.md5(feat.encode()).digest()[:8], "big")
        return h % self.dim, 1.0 if (h >> 40) & 1 else -1.0

    def embed(self, text: str) -> Dict[int, float]:
        toks = tokens(text)
        feats: Dict[str, int] = {}
        for t in toks:
            feats[t] = feats.get(t, 0) + 1
        for a, b in zip(toks, toks[1:]):
            feats[a + "_" + b] = feats.get(a + "_" + b, 0) + 1
        vec: Dict[int, float] = {}
        for f, c in feats.items():
            idx, sign = self._slot(f)
            vec[idx] = vec.get(idx, 0.0) + sign * (1.0 + math.log(c))
        norm = math.sqrt(sum(v * v for v in vec.values()))
        return {k: v / norm for k, v in vec.items()} if norm else {}


def cosine(a: Dict[int, float], b: Dict[int, float]) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(v * b.get(k, 0.0) for k, v in a.items())
