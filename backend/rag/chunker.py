def chunk_text(text, size=120, overlap=30):
    words = text.split()
    step = max(1, size - overlap)
    return [" ".join(words[i:i + size]) for i in range(0, max(1, len(words)), step) if words[i:i + size]]


def chunk_documents(docs, size=120, overlap=30):
    out = []
    for d in docs:
        for i, c in enumerate(chunk_text(d["text"], size, overlap)):
            out.append({"source": d["source"], "chunk_id": i, "text": c})
    return out
