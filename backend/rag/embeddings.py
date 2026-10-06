"""Embeddings: Sentence Transformers if installed (EMBEDDING_BACKEND=sbert/auto), else TF-IDF."""
import numpy as np
from backend.config import settings


class Embedder:
    def __init__(self, texts):
        self.kind = "tfidf"
        want = settings.embedding_backend
        if want in ("auto", "sbert"):
            try:
                from sentence_transformers import SentenceTransformer
                self.model = SentenceTransformer("all-MiniLM-L6-v2")
                self.kind = "sentence-transformers/all-MiniLM-L6-v2"
            except Exception:
                if want == "sbert":
                    raise
        if self.kind == "tfidf":
            from sklearn.feature_extraction.text import TfidfVectorizer
            self.vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True).fit(texts)

    def encode(self, texts):
        if self.kind == "tfidf":
            m = self.vec.transform(texts).toarray().astype("float32")
        else:
            m = np.asarray(self.model.encode(texts), dtype="float32")
        n = np.linalg.norm(m, axis=1, keepdims=True)
        return m / np.clip(n, 1e-9, None)
