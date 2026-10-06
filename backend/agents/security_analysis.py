"""Network / Security Analysis agent. Passive analysis of supplied events only."""
from collections import defaultdict
from backend.ml.detector import max_window_count, score_flows


def analyze(events, incident_id=None):
    findings = []
    ports = defaultdict(set)
    reqs = defaultdict(list)
    fails, succ = defaultdict(list), defaultdict(list)
    for e in events:
        s = e.get("src_ip")
        if e.get("dst_port") is not None and e.get("event_type") in ("flow", "connection"):
            ports[s].add(int(e["dst_port"]))
        if e.get("event_type") in ("http_request", "auth_failure"):
            reqs[s].append(e)
        if e.get("event_type") == "auth_failure":
            fails[s].append(e)
        if e.get("event_type") == "auth_success":
            succ[s].append(e)

    for s, p in ports.items():
        if len(p) >= 15:
            ev = [e["id"] for e in events if e.get("src_ip") == s and e.get("event_type") in ("flow", "connection")]
            findings.append({"finding": "Many distinct destination ports probed (port-scan pattern)",
                             "category": "port_scan", "count": len(p), "source": s, "time_window": "burst",
                             "confidence": round(min(0.97, 0.5 + len(p) / 120), 3),
                             "timestamp": min(e["timestamp"] for e in events if e["id"] in set(ev)),
                             "details": {"distinct_ports": len(p)}, "evidence_ids": ev})
    for s, evs in reqs.items():
        peak = max_window_count([e["timestamp"] for e in evs], 60)
        if peak >= 60:
            findings.append({"finding": "Abnormally high request frequency from one source",
                             "category": "high_rate", "count": len(evs), "source": s, "time_window": "1 minute",
                             "peak_in_window": peak, "confidence": round(min(0.97, 0.5 + peak / 400), 3),
                             "timestamp": min(e["timestamp"] for e in evs),
                             "details": {"peak_per_minute": peak}, "evidence_ids": [e["id"] for e in evs]})
    for s in succ:
        if len(fails.get(s, [])) >= 10:
            findings.append({"finding": "Successful login from a source with many prior failures",
                             "category": "success_after_failures", "count": len(succ[s]), "source": s,
                             "time_window": "n/a", "confidence": 0.9,
                             "timestamp": min(e["timestamp"] for e in succ[s]),
                             "details": {"prior_failures": len(fails[s]), "users": sorted({e.get("user") for e in succ[s]})},
                             "evidence_ids": [e["id"] for e in succ[s]]})
    scored = score_flows(events)
    mal = [(i, p) for i, p in scored if p >= 0.5]
    if mal:
        srcs = defaultdict(int)
        for i, _ in mal:
            srcs[events[i].get("src_ip")] += 1
        top = max(srcs, key=srcs.get)
        findings.append({"finding": "Flows classified malicious by the ML detector", "category": "ml_malicious_flows",
                         "count": len(mal), "source": top, "time_window": "n/a",
                         "confidence": round(sum(p for _, p in mal) / len(mal), 3),
                         "timestamp": min(events[i]["timestamp"] for i, _ in mal),
                         "details": {"malicious_flows": len(mal), "total_flows": len(scored)},
                         "evidence_ids": [events[i]["id"] for i, _ in mal]})
    return findings
