"""Dataset loaders. Each dataset has its own loader because column names differ.

TRAINING data  -> train split of CIC-IDS2017 (or synthetic fallback)
TEST data      -> held-out split, never used for fitting
LIVE data      -> demo scenarios / uploaded CSV (backend/utils/demo.py)
"""
from pathlib import Path
import re
import numpy as np
import pandas as pd


def load_cic_ids2017(path, max_rows=None):
    """Load one CSV file or every CSV in a folder of CIC-IDS2017 (MachineLearningCVE)."""
    path = Path(path)
    files = sorted(path.glob("*.csv")) if path.is_dir() else [path]
    if not files:
        raise FileNotFoundError(f"No CSV files found in {path}")
    frames = [pd.read_csv(f, encoding="latin-1", low_memory=False) for f in files]
    df = pd.concat(frames, ignore_index=True)
    if max_rows and len(df) > max_rows:
        df = df.sample(max_rows, random_state=42).reset_index(drop=True)
    return df


def load_bgl(path, max_lines=200000):
    """BGL log loader. Each line: '<label> <timestamp> ... <message>'; label '-' means normal."""
    rows = []
    with open(path, "r", encoding="latin-1") as fh:
        for i, line in enumerate(fh):
            if i >= max_lines:
                break
            parts = line.rstrip("\n").split(" ", 8)
            if len(parts) < 9:
                continue
            rows.append({"label": 0 if parts[0] == "-" else 1,
                         "timestamp": parts[1], "message": parts[8]})
    return pd.DataFrame(rows)


def load_hdfs(path, max_lines=200000):
    """HDFS raw log loader. Labels come from anomaly_label.csv, joined on block id."""
    rows = []
    with open(path, "r", encoding="latin-1") as fh:
        for i, line in enumerate(fh):
            if i >= max_lines:
                break
            m = re.search(r"(blk_-?\d+)", line)
            rows.append({"block_id": m.group(1) if m else None, "message": line.strip()})
    return pd.DataFrame(rows)


def load_custom_csv(path):
    return pd.read_csv(path, low_memory=False)


# ---------------------------------------------------------------------------
# Synthetic flows: ONLY used when no real dataset is supplied (and for demos).
# Metrics computed on synthetic data are labelled as such and say nothing
# about real-world performance.
# ---------------------------------------------------------------------------
def make_benign_flows(n, rng):
    return pd.DataFrame({
        "flow_duration": rng.lognormal(11, 1.5, n),
        "total_fwd_packets": rng.poisson(12, n) + 1,
        "total_bwd_packets": rng.poisson(10, n) + 1,
        "fwd_bytes": rng.lognormal(7, 1.2, n),
        "bwd_bytes": rng.lognormal(8, 1.5, n),
        "dst_port": rng.choice([80, 443, 53, 8080, 993, 22], n, p=[.3, .4, .15, .05, .05, .05]),
        "syn_flag_count": rng.binomial(1, 0.6, n),
        "label": 0,
    })


def make_attack_flows(kind, n, rng):
    if kind == "portscan":
        df = pd.DataFrame({"flow_duration": rng.lognormal(4, 1, n), "total_fwd_packets": rng.poisson(1.5, n) + 1,
                           "total_bwd_packets": rng.poisson(0.5, n), "fwd_bytes": rng.lognormal(3.5, .4, n),
                           "bwd_bytes": rng.lognormal(2, .8, n), "dst_port": rng.integers(1, 10000, n),
                           "syn_flag_count": np.ones(n, dtype=int)})
    elif kind == "dos":
        df = pd.DataFrame({"flow_duration": rng.lognormal(13, 1, n), "total_fwd_packets": rng.poisson(40, n) + 5,
                           "total_bwd_packets": rng.poisson(1, n), "fwd_bytes": rng.lognormal(6, .6, n),
                           "bwd_bytes": rng.lognormal(2, .8, n), "dst_port": np.full(n, 80),
                           "syn_flag_count": rng.binomial(1, 0.9, n)})
    else:  # bruteforce
        df = pd.DataFrame({"flow_duration": rng.lognormal(9, .6, n), "total_fwd_packets": rng.poisson(8, n) + 2,
                           "total_bwd_packets": rng.poisson(7, n) + 2, "fwd_bytes": rng.lognormal(5.5, .3, n),
                           "bwd_bytes": rng.lognormal(5.8, .3, n), "dst_port": rng.choice([21, 22, 3389], n),
                           "syn_flag_count": rng.binomial(1, 0.8, n)})
    df["label"] = 1
    return df


def generate_synthetic_flows(n=20000, attack_ratio=0.25, seed=42):
    rng = np.random.default_rng(seed)
    n_att = int(n * attack_ratio)
    kinds = rng.choice(["portscan", "dos", "bruteforce"], n_att)
    parts = [make_benign_flows(n - n_att, rng)]
    for k in ["portscan", "dos", "bruteforce"]:
        c = int((kinds == k).sum())
        if c:
            parts.append(make_attack_flows(k, c, rng))
    df = pd.concat(parts, ignore_index=True)
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)
