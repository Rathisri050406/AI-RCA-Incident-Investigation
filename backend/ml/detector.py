"""Incident detection: ML flow scoring + log rules -> NORMAL / SUSPICIOUS / INCIDENT."""
import math
from collections import defaultdict
from datetime import datetime
import joblib
import pandas as pd

from backend.config import settings
from backend.ml.feature_engineering import build_features
from backend.ml.data_loader import generate_synthetic_flows
from backend.ml.train import train_and_evaluate

_MODEL = None


def get_model():
    """Load detector.pkl; if absent, train once on synthetic data (clearly flagged)."""
    global _MODEL
    if _MODEL is None:
        path = settings.model_dir / "detector.pkl"
        if not path.exists():
            train_and_evaluate(generate_synthetic_flows(12000), "synthetic (auto-generated)")
        _MODEL = joblib.load(path)
    return _MODEL


def reset_model_cache():
    global _MODEL
    _MODEL = None


def score_flows(events):
    """List of (event_index, probability_malicious) for events that carry flow features."""
    idx = [i for i, e in enumerate(events) if e.get("flow")]
    if not idx:
        return []
    bundle = get_model()
    df = pd.DataFrame([events[i]["flow"] for i in idx])
    X = build_features(df)[bundle["features"]]
    return list(zip(idx, bundle["model"].predict_proba(X)[:, 1].tolist()))


def parse_ts(ts):
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).replace(tzinfo=None)


def max_window_count(timestamps, window_s=300):
    ts = sorted(parse_ts(t) for t in timestamps)
    best, j = 0, 0
    for i in range(len(ts)):
        while (ts[i] - ts[j]).total_seconds() > window_s:
            j += 1
        best = max(best, i - j + 1)
    return best


def _auth_conf(count):
    return 0.0 if count < 5 else min(0.99, 0.45 + 0.54 * (1 - math.exp(-count / 40)))


def detect(events):
    signals = []  # (incident_type, confidence, evidence_event_ids)

    # Rule 1: repeated authentication failures from one source
    by_src = defaultdict(list)
    for e in events:
        if e.get("event_type") == "auth_failure":
            by_src[e.get("src_ip")].append(e)
    for src, evs in by_src.items():
        c = max_window_count([e["timestamp"] for e in evs])
        signals.append(("authentication_attack", _auth_conf(c), [e["id"] for e in evs]))

    # Rule 2: repeated database / application errors
    db = [e for e in events if e.get("event_type") in ("db_timeout", "app_error")]
    if len(db) >= 5:
        signals.append(("system_failure", min(0.97, 0.5 + len(db) / 60), [e["id"] for e in db]))

    # Rule 3: port-scan pattern (many distinct destination ports from one source),
    # independent of the ML model
    ports = defaultdict(set)
    for e in events:
        if e.get("event_type") in ("flow", "connection") and e.get("dst_port") is not None:
            ports[e.get("src_ip")].add(int(e["dst_port"]))
    for src, p in ports.items():
        if len(p) >= 15:
            ids = [e["id"] for e in events
                   if e.get("src_ip") == src and e.get("event_type") in ("flow", "connection")]
            signals.append(("network_attack", min(0.97, 0.5 + len(p) / 120), ids))

    # ML detector on flow features
    scored = score_flows(events)
    if scored:
        probs = sorted((p for _, p in scored), reverse=True)
        top = probs[: min(5, len(probs))]
        mal = [events[i]["id"] for i, p in scored if p >= 0.5]
        if mal:
            signals.append(("network_attack", sum(top) / len(top), mal))

    if not signals or max(s[1] for s in signals) < 0.35:
        return {"incident_detected": False, "classification": "NORMAL", "incident_type": "none",
                "severity": "none", "confidence": round(max([s[1] for s in signals] or [0.0]), 3),
                "timestamp": _first_ts(events), "evidence_ids": []}

    strong = [s for s in signals if s[1] >= 0.7]
    top_sig = max(signals, key=lambda s: s[1])
    types = {s[0] for s in strong}
    incident_type = "multi_stage_attack" if len(types) >= 2 else top_sig[0]
    conf = max(s[1] for s in (strong if strong else signals))
    classification = "INCIDENT" if conf >= 0.7 else "SUSPICIOUS"
    ev_ids = sorted({i for s in (strong or [top_sig]) for i in s[2]})
    severity = ("critical" if incident_type == "multi_stage_attack" and conf >= 0.85 else
                "high" if conf >= 0.8 else "medium" if conf >= 0.5 else "low")
    sel = [e for e in events if e["id"] in set(ev_ids)] or events
    return {"incident_detected": classification == "INCIDENT", "classification": classification,
            "incident_type": incident_type, "severity": severity, "confidence": round(conf, 3),
            "timestamp": _first_ts(sel), "evidence_ids": ev_ids}


def _first_ts(events):
    return min((e["timestamp"] for e in events), default=datetime.utcnow().isoformat())