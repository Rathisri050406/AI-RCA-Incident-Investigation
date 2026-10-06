"""Log Analysis agent: parse, group, find repeated errors / abnormal patterns."""
import re
from collections import Counter, defaultdict
from backend.ml.detector import max_window_count


def _template(msg):
    return re.sub(r"\d+", "<N>", str(msg))


def analyze(events, incident_id=None):
    findings = []
    auth = defaultdict(list)
    for e in events:
        if e.get("event_type") == "auth_failure":
            auth[e.get("src_ip")].append(e)
    total_fail = sum(len(v) for v in auth.values())
    for src, evs in auth.items():
        w = max_window_count([e["timestamp"] for e in evs])
        if w >= 5:
            users = Counter(e.get("user") for e in evs)
            findings.append({
                "finding": "Repeated authentication failures", "category": "auth_failures",
                "count": len(evs), "source": src, "time_window": "5 minutes", "peak_in_window": w,
                "confidence": round(min(0.99, 0.45 + 0.54 * (1 - 2.718 ** (-w / 40))), 3),
                "timestamp": min(e["timestamp"] for e in evs),
                "details": {"distinct_users": len(users), "top_users": users.most_common(3),
                            "source_share": round(len(evs) / total_fail, 3)},
                "evidence_ids": [e["id"] for e in evs]})
    db = [e for e in events if e.get("event_type") == "db_timeout"]
    if len(db) >= 3:
        lat = [e.get("latency_ms", 0) for e in db]
        findings.append({"finding": "Repeated database timeouts", "category": "db_timeouts", "count": len(db),
                         "source": db[0].get("dst_ip"), "time_window": _span(db),
                         "confidence": round(min(0.97, 0.5 + len(db) / 60), 3),
                         "timestamp": min(e["timestamp"] for e in db),
                         "details": {"avg_latency_ms": round(sum(lat) / len(lat))},
                         "evidence_ids": [e["id"] for e in db]})
    app = [e for e in events if e.get("event_type") == "app_error"]
    if len(app) >= 3:
        findings.append({"finding": "Repeated application errors", "category": "app_errors", "count": len(app),
                         "source": app[0].get("src_ip"), "time_window": _span(app),
                         "confidence": round(min(0.95, 0.45 + len(app) / 50), 3),
                         "timestamp": min(e["timestamp"] for e in app),
                         "details": {"top_message": Counter(_template(e["message"]) for e in app).most_common(1)[0]},
                         "evidence_ids": [e["id"] for e in app]})
    return findings


def _span(evs):
    from backend.ml.detector import parse_ts
    ts = [parse_ts(e["timestamp"]) for e in evs]
    return f"{int((max(ts) - min(ts)).total_seconds() // 60) + 1} minutes"
