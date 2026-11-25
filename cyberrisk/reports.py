"""Report rendering: one neutral block structure -> Markdown or escaped HTML (no raw HTML from data)."""
from __future__ import annotations

from .security.sanitize import escape_html

CSS = ("body{font:15px/1.55 Georgia,serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#14232b}"
       "table{border-collapse:collapse;width:100%;margin:.8rem 0}th,td{border:1px solid #b9c6cd;padding:.35rem .5rem;text-align:left;vertical-align:top}"
       "th{background:#e6edf0}code{font-family:ui-monospace,monospace;font-size:.85em;word-break:break-all}.note{border-left:4px solid #b7791f;padding:.2rem .8rem;background:#f6efe0}")


def _md_cell(v) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ")


def to_markdown(blocks: list) -> str:
    out = []
    for b in blocks:
        kind = b[0]
        if kind in ("h1", "h2", "h3"):
            out.append("#" * int(kind[1]) + " " + b[1])
        elif kind == "p":
            out.append(b[1])
        elif kind == "note":
            out.append("> " + b[1])
        elif kind == "ul":
            out.append("\n".join(f"- {i}" for i in b[1]))
        elif kind == "table":
            out.append("| " + " | ".join(map(_md_cell, b[1])) + " |\n|" + "---|" * len(b[1]) + "\n" +
                       "\n".join("| " + " | ".join(map(_md_cell, r)) + " |" for r in b[2]))
    return "\n\n".join(out) + "\n"


def to_html(blocks: list, title: str) -> str:
    e, out = escape_html, []
    for b in blocks:
        kind = b[0]
        if kind in ("h1", "h2", "h3"):
            out.append(f"<{kind}>{e(b[1])}</{kind}>")
        elif kind == "p":
            out.append(f"<p>{e(b[1])}</p>")
        elif kind == "note":
            out.append(f'<p class="note">{e(b[1])}</p>')
        elif kind == "ul":
            out.append("<ul>" + "".join(f"<li>{e(i)}</li>" for i in b[1]) + "</ul>")
        elif kind == "table":
            out.append("<table><thead><tr>" + "".join(f"<th>{e(h)}</th>" for h in b[1]) + "</tr></thead><tbody>" +
                       "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in r) + "</tr>" for r in b[2]) + "</tbody></table>")
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" '
            f'content="default-src \'none\'; style-src \'unsafe-inline\'"><title>{e(title)}</title><style>{CSS}</style></head><body>'
            + "\n".join(out) + "</body></html>")
