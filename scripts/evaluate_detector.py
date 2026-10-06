"""Prints the metrics saved by train_detector.py (computed on the held-out test split)."""
import json, sys
from pathlib import Path
f = Path(__file__).resolve().parent.parent / "backend/models/metrics.json"
if not f.exists():
    sys.exit("Run scripts/train_detector.py first.")
d = json.loads(f.read_text())
print("Data source:", d["data_source"], "| test rows:", d["n_test"])
if d.get("warning"): print("WARNING:", d["warning"])
for n, r in d["results"].items():
    print(f"\n{n}")
    for k, v in r.items(): print(f"  {k}: {v}")
