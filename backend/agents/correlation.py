"""Evidence correlation: turn findings into evidence items and link independent observations."""
SEV = lambda c: "high" if c >= 0.8 else "medium" if c >= 0.5 else "low"


def correlate(findings_by_module, incident_ref):
    evidence, n = [], 0
    for module, findings in findings_by_module.items():
        for f in findings:
            n += 1
            evidence.append({"id": f"EV-{n:03d}", "source": module, "category": f["category"],
                             "description": f"{f['finding']} (count={f['count']}, source={f['source']}, window={f['time_window']})",
                             "timestamp": f["timestamp"], "severity": SEV(f["confidence"]),
                             "confidence": f["confidence"], "related_incident": incident_ref,
                             "source_ip": f["source"], "raw_event_ids": f.get("evidence_ids", [])[:50]})
    by_src = {}
    for ev in evidence:
        by_src.setdefault(ev["source_ip"], []).append(ev)
    groups = []
    for src, evs in by_src.items():
        cats = sorted({e["category"] for e in evs})
        if len(cats) >= 2:
            groups.append({"source": src, "categories": cats, "evidence_ids": [e["id"] for e in evs]})
    # independent observations: evidence from different categories; strength via noisy-OR, damped
    prod = 1.0
    for ev in evidence:
        prod *= (1 - ev["confidence"] * 0.8)
    strength = round(1 - prod, 3) if evidence else 0.0
    summary = (f"{len(evidence)} independent observations from {len({e['source'] for e in evidence})} analysis modules"
               + (f"; {len(groups)} source(s) linked across multiple evidence categories." if groups
                  else "; no single source linked across categories.")) if evidence else "No supporting evidence found."
    return {"evidence": evidence, "groups": groups, "strength": strength, "summary": summary}
