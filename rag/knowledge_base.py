"""
Loads the trusted knowledge base (OWASP / CWE / NIST markdown files under
rag/data/) and splits it into retrieval-friendly chunks.

Keeping the corpus as version-controlled markdown files (rather than
scraping live sites at runtime) keeps the RAG pipeline reproducible,
offline-capable, and auditable — every chunk's provenance is just its
file path.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"


@dataclass
class KBChunk:
    chunk_id: str
    source_path: str       # e.g. "owasp/a03_injection.md"
    source_label: str      # human-readable, e.g. "OWASP A03:2021 - Injection"
    text: str


def _split_markdown(text: str, max_chars: int = 900, overlap: int = 150) -> list[str]:
    """
    Simple heading-aware chunker: splits on '## ' subsections first (each
    subsection is usually a coherent unit — "Prevention", "Summary", etc.),
    then further splits any subsection that's still too long, with a small
    character overlap to preserve context across chunk boundaries.
    """
    sections = []
    current = []
    for line in text.splitlines():
        if line.startswith("## ") and current:
            sections.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        sections.append("\n".join(current))

    chunks = []
    for section in sections:
        if len(section) <= max_chars:
            chunks.append(section.strip())
            continue
        start = 0
        while start < len(section):
            end = start + max_chars
            chunks.append(section[start:end].strip())
            start = end - overlap
    return [c for c in chunks if c]


def load_knowledge_base() -> list[KBChunk]:
    chunks: list[KBChunk] = []
    if not DATA_DIR.exists():
        return chunks

    for md_file in sorted(DATA_DIR.rglob("*.md")):
        rel_path = md_file.relative_to(DATA_DIR).as_posix()
        text = md_file.read_text(encoding="utf-8")
        title_line = next((l for l in text.splitlines() if l.startswith("# ")), rel_path)
        label = title_line.lstrip("# ").strip()

        for i, chunk_text in enumerate(_split_markdown(text)):
            chunks.append(KBChunk(
                chunk_id=f"{rel_path}::{i}",
                source_path=rel_path,
                source_label=label,
                text=chunk_text,
            ))
    return chunks


if __name__ == "__main__":
    kb = load_knowledge_base()
    print(f"Loaded {len(kb)} knowledge base chunks from {DATA_DIR}")
    for c in kb[:3]:
        print("---", c.chunk_id, "---")
        print(c.text[:200])
