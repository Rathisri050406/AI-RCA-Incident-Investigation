"""Risk scoring (0-100). Fully deterministic; no random values.

score = 100 * (0.30*severity + 0.20*confidence + 0.20*impact + 0.15*evidence_strength + 0.15*type_weight)
  severity         : low .25 / medium .5 / high .75 / critical 1.0 (from detection)
  confidence       : RCA confidence (0-1)
  impact           : min(1, affected_resources / 10)   (distinct sources + users + target hosts)
  evidence_strength: from evidence correlation (0-1)
  type_weight      : intrusion types weigh more than availability faults
Levels: <25 LOW, <50 MEDIUM, <75 HIGH, otherwise CRITICAL.
"""
SEVERITY = {"none": 0.0, "low": .25, "medium": .5, "high": .75, "critical": 1.0}
TYPE_WEIGHT = {"multi_stage_attack": 1.0, "authentication_attack": .8, "network_attack": .7,
               "system_failure": .6, "none": 0.0}
W = {"severity": .30, "confidence": .20, "impact": .20, "strength": .15, "type": .15}


def assess(detection, rca, correlation, events):
    ev_ids = set(detection["evidence_ids"])
    rel = [e for e in events if e["id"] in ev_ids]
    affected = len({e.get("src_ip") for e in rel} | {e.get("user") for e in rel if e.get("user")} |
                   {e.get("dst_ip") for e in rel})
    comp = {"severity": SEVERITY.get(detection["severity"], 0), "confidence": rca["confidence"],
            "impact": min(1.0, affected / 10), "strength": correlation["strength"],
            "type": TYPE_WEIGHT.get(detection["incident_type"], .5)}
    score = round(100 * sum(W[k] * comp[k] for k in W), 1)
    level = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
    return {"score": score, "level": level, "components": {k: round(v, 3) for k, v in comp.items()},
            "weights": W, "affected_resources": affected,
            "logic": "Weighted sum of severity, RCA confidence, impact, evidence strength and incident-type weight."}
