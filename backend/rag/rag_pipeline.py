"""Documents -> extraction -> chunking -> embeddings -> vector store -> similarity search.
Results always carry the real source file name. Nothing is invented."""
from backend.config import settings
from backend.rag.document_loader import load_documents
from backend.rag.chunker import chunk_documents
from backend.rag.embeddings import Embedder
from backend.rag.vector_store import VectorStore
from backend.rag.retriever import Retriever

_RET = None


def get_retriever():
    global _RET
    if _RET is None:
        chunks = chunk_documents(load_documents(settings.knowledge_dir))
        if not chunks:
            raise RuntimeError(f"Knowledge base is empty: {settings.knowledge_dir}")
        emb = Embedder([c["text"] for c in chunks])
        _RET = Retriever(emb, VectorStore(emb.encode([c["text"] for c in chunks]), chunks))
        _RET.backend = emb.kind
    return _RET


def search(query, k=4):
    return get_retriever().retrieve(query, k)


def dedupe_sources(results):
    seen, out = set(), []
    for r in results:
        if r["source"] not in seen:
            seen.add(r["source"]); out.append(r)
    return out
