"""
Retriever: given a Finding, builds a targeted query (category + CWE/OWASP
IDs + short evidence) and pulls the top-k most relevant chunks from the
ChromaDB knowledge base, to ground the LLM's explanation and fix in
trusted OWASP/CWE/NIST content rather than the model's parametric memory
alone.

Falls back gracefully (empty context) if ChromaDB/embeddings aren't
available, so the rest of the app still works without the RAG layer.
"""
from __future__ import annotations

from dataclasses import dataclass

from backend.models import Finding
from rag.ingest import get_chroma_client, get_embedding_function, COLLECTION_NAME


@dataclass
class RetrievedContext:
    text: str
    source_label: str
    source_path: str
    relevance: float  # 1 - distance, higher is better


_collection_cache = None


def _get_collection():
    global _collection_cache
    if _collection_cache is not None:
        return _collection_cache
    try:
        client = get_chroma_client()
        embed_fn = get_embedding_function()
        _collection_cache = client.get_or_create_collection(
            name=COLLECTION_NAME, embedding_function=embed_fn
        )
        return _collection_cache
    except Exception as e:
        print(f"[rag.retriever] ChromaDB unavailable ({e}); RAG context will be empty.")
        return None


def build_query(finding: Finding) -> str:
    category = finding.category.value if hasattr(finding.category, "value") else finding.category
    ids = " ".join(finding.cwe_ids + finding.owasp_ids)
    return f"{category} {ids} {finding.description}".strip()


def retrieve_context(finding: Finding, top_k: int = 3) -> list[RetrievedContext]:
    collection = _get_collection()
    if collection is None or collection.count() == 0:
        return []

    query = build_query(finding)
    try:
        results = collection.query(query_texts=[query], n_results=min(top_k, collection.count()))
    except Exception as e:
        print(f"[rag.retriever] Query failed: {e}")
        return []

    contexts = []
    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    dists = results.get("distances", [[]])[0]
    for doc, meta, dist in zip(docs, metas, dists):
        contexts.append(RetrievedContext(
            text=doc,
            source_label=meta.get("source_label", "Unknown source"),
            source_path=meta.get("source_path", ""),
            relevance=round(max(0.0, 1 - dist), 3),
        ))
    return contexts


def format_context_for_prompt(contexts: list[RetrievedContext]) -> str:
    if not contexts:
        return "(No trusted reference context retrieved — rely on general secure coding principles.)"
    blocks = []
    for c in contexts:
        blocks.append(f"[Source: {c.source_label}]\n{c.text}")
    return "\n\n".join(blocks)
