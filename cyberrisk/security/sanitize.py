"""Input sanitisation helpers and prompt-injection screening for retrieved text."""
from __future__ import annotations

import html
import re

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_INJECTION = [re.compile(p, re.I) for p in (
    r"ignore (all |any )?(previous|prior|above) (instructions|prompts)", r"disregard (the )?(system|previous) (prompt|instructions)",
    r"you are now ", r"reveal (your )?(system )?prompt", r"(set|change|override) (the )?(risk )?(score|weights?)",
    r"<\s*/?\s*(system|assistant)\s*>",
)]


def clean_text(value: str, max_len: int) -> str:
    value = _CONTROL.sub("", value).strip()
    if len(value) > max_len:
        raise ValueError(f"text exceeds {max_len} characters")
    return value


def escape_html(value) -> str:
    return html.escape(str(value), quote=True)


def injection_suspected(text: str) -> bool:
    return any(p.search(text) for p in _INJECTION)
