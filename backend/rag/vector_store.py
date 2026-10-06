import numpy as np


class VectorStore:
    """FAISS inner-product index if available, else numpy cosine similarity."""
    def __init__(self, vectors, items):
        self.items, self.vectors = items, vectors
        self.index = None
        try:
            import faiss
            self.index = faiss.IndexFlatIP(vectors.shape[1])
            self.index.add(vectors)
        except Exception:
            self.index = None

    def search(self, qvec, k=4):
        if self.index is not None:
            sims, ids = self.index.search(qvec, k)
            return [(int(i), float(s)) for i, s in zip(ids[0], sims[0]) if i >= 0]
        sims = (self.vectors @ qvec[0])
        order = np.argsort(-sims)[:k]
        return [(int(i), float(sims[i])) for i in order]
