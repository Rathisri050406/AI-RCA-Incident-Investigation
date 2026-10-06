from pathlib import Path


def load_documents(folder):
    """Return [{'source': filename, 'text': str}] for .md/.txt/.pdf files."""
    docs = []
    for p in sorted(Path(folder).glob("**/*")):
        if p.suffix.lower() in (".md", ".txt"):
            docs.append({"source": p.name, "text": p.read_text(encoding="utf-8", errors="ignore")})
        elif p.suffix.lower() == ".pdf":
            try:
                from pypdf import PdfReader
                docs.append({"source": p.name, "text": "\n".join((pg.extract_text() or "") for pg in PdfReader(str(p)).pages)})
            except Exception:
                continue
    return docs
