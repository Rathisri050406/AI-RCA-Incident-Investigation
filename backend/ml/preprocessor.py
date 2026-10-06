"""Dataset-specific cleaning: map differing column names to one canonical schema."""
import numpy as np
import pandas as pd

CANONICAL = ["flow_duration", "total_fwd_packets", "total_bwd_packets", "fwd_bytes",
             "bwd_bytes", "dst_port", "syn_flag_count"]

ALIASES = {
    "flow duration": "flow_duration", "total fwd packets": "total_fwd_packets",
    "total backward packets": "total_bwd_packets",
    "total length of fwd packets": "fwd_bytes", "total length of bwd packets": "bwd_bytes",
    "destination port": "dst_port", "dst port": "dst_port", "syn flag count": "syn_flag_count",
}


def normalize_columns(df):
    out = df.copy()
    out.columns = [str(c).strip().lower() for c in out.columns]
    return out.rename(columns={c: ALIASES[c] for c in out.columns if c in ALIASES})


def binarize_label(lab):
    """Benign -> 0, anything else -> 1. Works for CIC string labels and 0/1 labels."""
    if pd.api.types.is_numeric_dtype(lab):
        return (lab != 0).astype(int)
    return (~lab.astype(str).str.strip().str.upper().isin(["BENIGN", "NORMAL", "0"])).astype(int)


def clean(df, label_col="label"):
    """cleaning -> missing values -> duplicate removal. Returns (X_df, y)."""
    df = normalize_columns(df)
    if label_col not in df.columns:
        raise ValueError("Dataset has no label column")
    missing = [c for c in CANONICAL if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")
    df = df[CANONICAL + [label_col]].replace([np.inf, -np.inf], np.nan).dropna()
    df = df.drop_duplicates().reset_index(drop=True)  # BEFORE the split => no duplicate leakage
    y = binarize_label(df[label_col])
    return df[CANONICAL], y
