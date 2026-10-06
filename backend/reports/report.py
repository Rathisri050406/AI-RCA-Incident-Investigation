"""Incident report builder (16 required sections) + PDF export via ReportLab."""
import io
from xml.sax.saxutils import escape


def build_report(inc, inv, approval):
    """inc: incident dict, inv: investigation result dict, approval: dict(status, comment, decided_by)."""
    d, rca, risk, corr, ai = inc["detection"], inv["rca"], inv["risk"], inv["correlation"], inv["ai"]
    return {
        "1_incident_id": inc["code"], "2_date_time": inc["detected_at"], "3_incident_type": d["incident_type"],
        "4_severity": d["severity"],
        "5_detection_result": {"classification": d["classification"], "confidence": d["confidence"]},
        "6_summary": ai.get("summary"),
        "7_investigation_timeline": [{"time": t["timestamp"], "module": t["module"], "status": t["status"]} for t in inv["trace"]],
        "8_evidence": [{"id": e["id"], "source": e["source"], "description": e["description"], "severity": e["severity"],
                        "confidence": e["confidence"], "timestamp": e["timestamp"]} for e in corr["evidence"]],
        "9_root_cause": rca["root_cause"], "10_confidence": rca["confidence"],
        "11_alternative_explanations": rca["alternative_causes"],
        "12_rag_references": sorted({r["source"] for r in inv["rag"]}),
        "13_risk_assessment": {"score": risk["score"], "level": risk["level"], "components": risk["components"]},
        "14_recommended_response": [r["action"] for r in inv["recommendations"]],
        "15_human_approval": approval,
        "16_limitations": ai.get("limitations", []),
        "ai_explanation": {k: ai.get(k) for k in ("technical_explanation", "root_cause", "risk_explanation")},
    }


TITLES = {"1_incident_id": "1. Incident ID", "2_date_time": "2. Date and time", "3_incident_type": "3. Incident type",
          "4_severity": "4. Severity", "5_detection_result": "5. Detection result", "6_summary": "6. Incident summary",
          "7_investigation_timeline": "7. Investigation timeline", "8_evidence": "8. Evidence", "9_root_cause": "9. Root cause",
          "10_confidence": "10. Confidence", "11_alternative_explanations": "11. Alternative explanations",
          "12_rag_references": "12. RAG references", "13_risk_assessment": "13. Risk assessment",
          "14_recommended_response": "14. Recommended response", "15_human_approval": "15. Human approval status",
          "16_limitations": "16. Investigation limitations"}


def _lines(v):
    if isinstance(v, list):
        return [_one(x) for x in v] or ["None"]
    return [_one(v)]


def _one(x):
    if isinstance(x, dict):
        return "; ".join(f"{k}: {v}" for k, v in x.items())
    return str(x)


def to_pdf(report):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=f"Incident Report {report['1_incident_id']}")
    st = getSampleStyleSheet()
    story = [Paragraph("Incident Investigation Report", st["Title"]),
             Paragraph("AI-Based Autonomous Root-Cause Analysis and Cybersecurity Incident Investigation", st["Italic"]),
             Spacer(1, 12)]
    for key, title in TITLES.items():
        story.append(Paragraph(title, st["Heading3"]))
        for line in _lines(report[key]):
            story.append(Paragraph(escape(line), st["BodyText"]))
    doc.build(story)
    return buf.getvalue()
