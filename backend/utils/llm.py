"""Generative AI module. Runs only AFTER structured evidence exists.

LLM_PROVIDER=none               -> deterministic template narrative (no external call)
LLM_PROVIDER=openai_compatible  -> any OpenAI-compatible /chat/completions endpoint (key from .env)
Every statement is tagged FACT / INFERENCE / RECOMMENDATION.
"""
import json
from backend.config import settings

SYSTEM_PROMPT = (
    "You are a security incident analyst assistant. Use ONLY the provided structured context. "
    "Tag every statement as [FACT], [INFERENCE] or [RECOMMENDATION]. Never claim certainty beyond the "
    "evidence. Cite RAG sources only by the file names provided. Return JSON with keys: summary, "
    "technical_explanation, root_cause, supporting_evidence (list), risk_explanation, "
    "recommended_response (list), limitations (list).")

RECOMMENDATIONS = {
    "brute_force": ["Review the targeted accounts for suspicious successful logins",
                    "Enable additional authentication controls (MFA / rate limiting)",
                    "Investigate the source address activity", "Review authentication logs"],
    "password_spraying": ["Review all targeted accounts", "Enforce MFA and password-policy checks",
                          "Investigate the source address activity"],
    "compromised_account": ["Treat the account as potentially compromised and review its sessions",
                            "Reset the account credentials after approval", "Check for lateral movement",
                            "Preserve logs as evidence"],
    "port_scan": ["Confirm the source is not an authorised scanner", "Review exposed services and close unused ports",
                  "Monitor the source for follow-up authentication attempts"],
    "dos_flood": ["Confirm the traffic is not a legitimate spike", "Apply rate limiting after approval",
                  "Coordinate upstream filtering with the network provider"],
    "database_failure": ["Inspect slow-query logs and active locks", "Compare connection pool size to load",
                         "Review recent deployments or schema changes"],
    "application_fault": ["Review application logs and recent deployments", "Check dependent services"],
    "undetermined": ["Escalate to an analyst for manual review"],
}


def build_recommendations(rca):
    key = rca["root_cause_key"]
    return [{"action": a, "rationale": f"Addresses probable root cause: {rca['root_cause']}",
             "requires_approval": True} for a in RECOMMENDATIONS.get(key, RECOMMENDATIONS["undetermined"])]


def _template(ctx):
    d, rca, risk, corr = ctx["detection"], ctx["rca"], ctx["risk"], ctx["correlation"]
    ev = [f"[FACT] {e['id']}: {e['description']}" for e in corr["evidence"]]
    refs = ", ".join(sorted({r["source"] for r in ctx["rag"]})) or "none retrieved"
    return {
        "provider": "template (no LLM configured)",
        "summary": f"[FACT] {d['classification']} detected: {d['incident_type']} at {d['timestamp']} "
                   f"(detection confidence {d['confidence']:.0%}, severity {d['severity']}).",
        "technical_explanation": f"[INFERENCE] {rca['explanation']} Knowledge-base references used: {refs}.",
        "root_cause": f"[INFERENCE] Probable root cause: {rca['root_cause']} (confidence {rca['confidence']:.0%}).",
        "supporting_evidence": ev,
        "risk_explanation": f"[FACT] Risk score {risk['score']}/100 ({risk['level']}), computed from "
                            f"{', '.join(f'{k}={v}' for k, v in risk['components'].items())}.",
        "recommended_response": [f"[RECOMMENDATION] {r['action']} (requires human approval)" for r in ctx["recommendations"]],
        "limitations": ["Findings derive from the supplied events only; other data sources were not examined.",
                        "Root cause is a ranked hypothesis, not proof; alternatives are listed in the RCA.",
                        "Rule thresholds and the ML detector may be miscalibrated for other environments."],
    }


def generate(ctx):
    if settings.llm_provider != "openai_compatible" or not settings.llm_api_key:
        return _template(ctx)
    try:
        import httpx
        payload = {"model": settings.llm_model, "temperature": 0.1,
                   "response_format": {"type": "json_object"},
                   "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                {"role": "user", "content": json.dumps(ctx, default=str)[:24000]}]}
        r = httpx.post(f"{settings.llm_base_url}/chat/completions", json=payload, timeout=60,
                       headers={"Authorization": f"Bearer {settings.llm_api_key}"})
        r.raise_for_status()
        out = json.loads(r.json()["choices"][0]["message"]["content"])
        out["provider"] = f"{settings.llm_provider}:{settings.llm_model}"
        return out
    except Exception as exc:  # fall back safely, never fail the investigation
        t = _template(ctx)
        t["provider"] = f"template (LLM call failed: {type(exc).__name__})"
        return t
