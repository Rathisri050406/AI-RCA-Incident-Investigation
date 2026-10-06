class Retriever:
    def __init__(self, embedder, store, min_score=0.05):
        self.embedder, self.store, self.min_score = embedder, store, min_score

    def retrieve(self, query, k=4):
        hits = self.store.search(self.embedder.encode([query]), k)
        return [{"source": self.store.items[i]["source"], "chunk_id": self.store.items[i]["chunk_id"],
                 "text": self.store.items[i]["text"], "score": round(s, 4)}
                for i, s in hits if s >= self.min_score]
