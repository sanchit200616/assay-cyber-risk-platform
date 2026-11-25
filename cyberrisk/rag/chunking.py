"""Deterministic word-window chunker that keeps character offsets for citations."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Chunk:
    ordinal: int
    text: str
    char_start: int


def chunk_text(text: str, max_words: int = 110, overlap: int = 20) -> List[Chunk]:
    if max_words <= overlap or overlap < 0:
        raise ValueError("max_words must exceed overlap and overlap must be >= 0")
    spans = [(m.start(), m.end()) for m in re.finditer(r"\S+", text)]
    if not spans:
        return []
    chunks, i, step = [], 0, max_words - overlap
    while i < len(spans):
        window = spans[i:i + max_words]
        start, end = window[0][0], window[-1][1]
        chunks.append(Chunk(len(chunks), text[start:end], start))
        if i + max_words >= len(spans):
            break
        i += step
    return chunks
