"""
Ingests the OWASP/CWE/NIST knowledge base into a persistent ChromaDB
collection using sentence-transformers embeddings.

Run standalone to (re)build the vector store:
    python -m rag.ingest
"""
from __future__ import annotations

import os

from rag.knowledge_base import load_knowledge_base

CHROMA_DIR = os.environ.get("CHROMA_PERSIST_DIR", "./chroma_db")
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
COLLECTION_NAME = "securelens_knowledge"


def get_chroma_client():
    import chromadb
    return chromadb.PersistentClient(path=CHROMA_DIR)


def get_embedding_function():
    from chromadb.utils import embedding_functions
    return embedding_functions.SentenceTransformerEmbeddingFunction(model_name=EMBEDDING_MODEL)


def build_vector_store(force_rebuild: bool = False):
    client = get_chroma_client()
    embed_fn = get_embedding_function()

    existing = [c.name for c in client.list_collections()]
    if COLLECTION_NAME in existing and force_rebuild:
        client.delete_collection(COLLECTION_NAME)
        existing.remove(COLLECTION_NAME)

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME, embedding_function=embed_fn,
        metadata={"description": "OWASP/CWE/NIST trusted security knowledge for SecureLens AI"},
    )

    if collection.count() > 0 and not force_rebuild:
        print(f"[rag.ingest] Collection already populated ({collection.count()} chunks). "
              f"Pass force_rebuild=True to rebuild.")
        return collection

    chunks = load_knowledge_base()
    if not chunks:
        print("[rag.ingest] No knowledge base files found under rag/data/.")
        return collection

    collection.add(
        ids=[c.chunk_id for c in chunks],
        documents=[c.text for c in chunks],
        metadatas=[{"source_path": c.source_path, "source_label": c.source_label} for c in chunks],
    )
    print(f"[rag.ingest] Ingested {len(chunks)} chunks into collection '{COLLECTION_NAME}'.")
    return collection


if __name__ == "__main__":
    build_vector_store(force_rebuild=True)
