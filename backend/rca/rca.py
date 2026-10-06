"""Rule-weighted Root-Cause Analysis.

Hypotheses that leave observed evidence categories unexplained are penalised (up to 50%).
Each hypothesis lists the evidence categories that support it with weights.
score = sum(weight * finding_confidence for categories present) / sum(weights).
RAG results add at most +0.03 when a retrieved document actually concerns the hypothesis.
Confidence is capped at 0.95: we never claim certainty.
"""
HYPOTHESES = {
    "brute_force": {"label": "Brute-force authentication activity",
                    "w": {"auth_failures": .45, "high_rate": .2, "single_source": .2, "single_target": .15},
                    "keywords": ["brute", "authentication"]},
    "password_spraying": {"label": "Password spraying / credential stuffing",
                          "w": {"auth_failures": .4, "many_users": .4, "single_source": .2},
                          "keywords": ["spray", "credential"]},
    "compromised_account": {"label": "Compromised account after credential attack (multi-stage intrusion)",
                            "w": {"success_after_failures": .45, "auth_failures": .2, "port_scan": .2, "ml_malicious_flows": .15},
                            "keywords": ["valid accounts", "compromise"]},
    "port_scan": {"label": "Network reconnaissance (port scanning)",
                  "w": {"port_scan": .55, "ml_malicious_flows": .35, "single_source": .1},
                  "keywords": ["scan", "reconnaissance"]},
    "dos_flood": {"label": "Denial-of-service / request flooding",
                  "w": {"high_rate": .5, "ml_malicious_flows": .4, "single_source": .1},
                  "keywords": ["denial", "flood"]},
    "database_failure": {"label": "Database performance failure causing application errors",
                         "w": {"db_timeouts": .55, "app_errors": .35, "high_latency": .1},
                         "keywords": ["database", "timeout"]},
    "application_fault": {"label": "Application fault (not database related)",
                          "w": {"app_errors": .7, "high_latency": .3}, "keywords": ["application"]},
}
ALT_NOTES = {
    "brute_force": "A compromised legitimate client or misconfigured service retrying credentials.",
    "compromised_account": "Legitimate administrator who mistyped a password many times before succeeding.",
    "database_failure": "A resource-exhausted application host producing timeouts independent of the database.",
}


def _features(findings):
    cats = {}
    for f in findings:
        cats[f["category"]] = max(cats.get(f["category"], 0), f["confidence"])
        if f["category"] == "auth_failures":
            d = f.get("details", {})
            if d.get("source_share", 0) >= 0.8:
                cats["single_source"] = 0.9
            if d.get("distinct_users", 0) >= 5:
                cats["many_users"] = 0.9
            if d.get("distinct_users", 99) <= 2:
                cats["single_target"] = 0.8
        if f["category"] == "db_timeouts" and f.get("details", {}).get("avg_latency_ms", 0) > 10000:
            cats["high_latency"] = 0.8
    return cats


def analyze(incident, findings, correlation, rag_results):
    cats = _features(findings)
    observed = {f["category"] for f in findings}
    scores = {}
    for h, spec in HYPOTHESES.items():
        total = sum(spec["w"].values())
        s = sum(w * cats.get(c, 0) for c, w in spec["w"].items()) / total
        if observed:  # penalise hypotheses that leave observed evidence unexplained
            s *= 1 - 0.5 * len(observed - set(spec["w"])) / len(observed)
        docs = " ".join(r["text"].lower() + r["source"].lower() for r in rag_results)
        if s > 0.2 and any(k in docs for k in spec["keywords"]):
            s += 0.03
        scores[h] = round(min(s, 1.0), 3)
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    if not ranked or ranked[0][1] < 0.3:
        return {"root_cause_key": "undetermined", "root_cause": "Insufficient evidence to determine a root cause",
                "confidence": round(ranked[0][1], 3) if ranked else 0.0, "supporting_evidence": [],
                "alternative_causes": [], "hypothesis_scores": scores,
                "explanation": "No hypothesis reached the minimum score of 0.30; manual review is advised."}
    top, top_s = ranked[0]
    margin = top_s - (ranked[1][1] if len(ranked) > 1 else 0)
    conf = round(min(0.95, top_s * (0.85 + min(0.15, margin))), 3)
    spec = HYPOTHESES[top]
    needed = set(spec["w"])
    supporting = [e["id"] for e in correlation["evidence"] if e["category"] in needed]
    alts = [{"cause": HYPOTHESES[h]["label"], "score": s, "note": ALT_NOTES.get(h, "")}
            for h, s in ranked[1:4] if s >= 0.2]
    if top in ALT_NOTES:
        alts.append({"cause": "Benign explanation", "score": None, "note": ALT_NOTES[top]})
    present = [c for c in spec["w"] if cats.get(c, 0) > 0]
    explanation = (f"The hypothesis '{spec['label']}' best matches the observed evidence: "
                   f"{', '.join(present)} were observed. {correlation['summary']}")
    return {"root_cause_key": top, "root_cause": spec["label"], "confidence": conf,
            "supporting_evidence": supporting, "alternative_causes": alts,
            "hypothesis_scores": scores, "explanation": explanation}
