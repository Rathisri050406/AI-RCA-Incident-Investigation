"""Investigation orchestrator: a controlled, traceable workflow.

Plan depends on the incident type. Every step is recorded with module name, input,
output, timestamp, evidence used and status. (Equivalent to a LangGraph graph with a
fixed topology; kept dependency-free so it is deterministic and easy to test.)
"""
import time
from datetime import datetime

from backend.agents import log_analysis, security_analysis, correlation
from backend.rca import rca as rca_mod
from backend.risk import risk as risk_mod
from backend.rag import rag_pipeline
from backend.utils import llm

PLANS = {
    "authentication_attack": ["log_analysis", "security_analysis"],
    "network_attack": ["security_analysis", "log_analysis"],
    "system_failure": ["log_analysis"],
    "multi_stage_attack": ["log_analysis", "security_analysis"],
    "none": ["log_analysis"],
}
RAG_QUERY = {
    "authentication_attack": "brute force authentication failed logins response", "network_attack":
    "port scan network reconnaissance flooding", "system_failure": "database timeout application errors troubleshooting",
    "multi_stage_attack": "compromised account after credential attack port scan multi-stage", "none": "incident response process",
}


def run_investigation(events, detection, incident_ref="INC-NEW"):
    trace, t_start = [], time.perf_counter()

    def step(name, inp, fn, ev_ids=None):
        ts, status = datetime.utcnow().isoformat(timespec="seconds"), "completed"
        try:
            out = fn()
        except Exception as exc:
            out, status = {"error": str(exc)}, "failed"
        trace.append({"module": name, "input": inp, "output": _brief(out), "timestamp": ts,
                      "evidence_used": ev_ids or [], "status": status})
        if status == "failed":
            raise RuntimeError(f"{name} failed: {exc}")
        return out

    plan = PLANS.get(detection["incident_type"], PLANS["none"])
    trace.append({"module": "orchestrator", "input": {"incident_type": detection["incident_type"]},
                  "output": {"plan": plan + ["evidence_correlation", "rca", "risk_assessment", "rag", "generative_ai"]},
                  "timestamp": datetime.utcnow().isoformat(timespec="seconds"), "evidence_used": [], "status": "completed"})
    findings = {}
    mods = {"log_analysis": log_analysis.analyze, "security_analysis": security_analysis.analyze}
    for m in plan:
        findings[m] = step(m, {"events": len(events)}, lambda m=m: mods[m](events, incident_ref))
    # security analysis is always useful for multi-signal incidents; keep plan-driven otherwise
    corr = step("evidence_correlation", {k: len(v) for k, v in findings.items()},
                lambda: correlation.correlate(findings, incident_ref))
    all_findings = [f for v in findings.values() for f in v]
    rag_res = step("rag_retrieval", {"query": RAG_QUERY.get(detection["incident_type"])},
                   lambda: rag_pipeline.search(RAG_QUERY.get(detection["incident_type"], "incident response"), 4))
    rca = step("rca", {"findings": len(all_findings), "rag_chunks": len(rag_res)},
               lambda: rca_mod.analyze(detection, all_findings, corr, rag_res), [e["id"] for e in corr["evidence"]])
    risk = step("risk_assessment", {"rca_conf": rca["confidence"]},
                lambda: risk_mod.assess(detection, rca, corr, events))
    recs = llm.build_recommendations(rca)
    ctx = {"detection": detection, "findings": all_findings, "correlation": corr, "rca": rca,
           "risk": risk, "rag": rag_res, "recommendations": recs}
    ai = step("generative_ai", {"provider": "configured"}, lambda: llm.generate(ctx))
    trace.append({"module": "human_approval", "input": {}, "output": {"state": "PENDING"},
                  "timestamp": datetime.utcnow().isoformat(timespec="seconds"), "evidence_used": [], "status": "pending"})
    return {"findings": findings, "correlation": corr, "rag": rag_res, "rca": rca, "risk": risk,
            "recommendations": recs, "ai": ai, "trace": trace,
            "duration_s": round(time.perf_counter() - t_start, 3)}


def _brief(o):
    if isinstance(o, list):
        return {"items": len(o)}
    if isinstance(o, dict):
        return {k: (v if isinstance(v, (str, int, float, bool, type(None))) else f"<{type(v).__name__}>") for k, v in list(o.items())[:8]}
    return str(o)[:200]
