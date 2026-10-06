"""Usage:
  python scripts/train_detector.py --cic datasets/raw/cic-ids2017 [--max-rows 300000]
  python scripts/train_detector.py --csv my_flows.csv --label-col Label
  python scripts/train_detector.py --synthetic        (no dataset; metrics labelled synthetic)
"""
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.ml import data_loader
from backend.ml.train import train_and_evaluate

p = argparse.ArgumentParser()
p.add_argument("--cic"); p.add_argument("--csv"); p.add_argument("--label-col", default="label")
p.add_argument("--synthetic", action="store_true"); p.add_argument("--max-rows", type=int)
a = p.parse_args()

if a.cic:
    df = data_loader.load_cic_ids2017(a.cic, a.max_rows); src = f"CIC-IDS2017 ({a.cic})"
elif a.csv:
    df = data_loader.load_custom_csv(a.csv); src = f"custom CSV ({a.csv})"
else:
    df = data_loader.generate_synthetic_flows(); src = "synthetic"
df.columns = [str(c).strip().lower() if str(c).strip().lower() != a.label_col.lower() else "label" for c in df.columns]
info = train_and_evaluate(df, src)
print(json.dumps({k: v for k, v in info.items() if k != "results"}, indent=2))
for n, r in info["results"].items():
    print(f"\n{n}\n  " + "  ".join(f"{k}={v:.4f}" for k, v in r.items() if isinstance(v, float)))
print("\nSaved backend/models/detector.pkl, metrics.json and plots/")
