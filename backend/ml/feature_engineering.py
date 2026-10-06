import pandas as pd
from backend.ml.preprocessor import CANONICAL

FEATURES = CANONICAL + ["packets_per_sec", "bytes_per_sec", "avg_packet_size", "fwd_bwd_ratio"]


def build_features(df):
    d = df[CANONICAL].astype(float).copy()
    dur_s = d["flow_duration"].clip(lower=1) / 1e6
    pk = d["total_fwd_packets"] + d["total_bwd_packets"]
    by = d["fwd_bytes"] + d["bwd_bytes"]
    d["packets_per_sec"] = (pk / dur_s).clip(upper=1e7)
    d["bytes_per_sec"] = (by / dur_s).clip(upper=1e9)
    d["avg_packet_size"] = by / pk.clip(lower=1)
    d["fwd_bwd_ratio"] = d["fwd_bytes"] / (d["bwd_bytes"] + 1)
    return d[FEATURES]
