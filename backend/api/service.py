"""Business logic between the API and the engine; persists everything."""
from datetime import datetime
from backend.agents.orchestrator import run_investigation
from backend.database import models as m
from backend.ml.detector import detect
from backend.reports.report import build_report


def audit(db, user, action, detail=""):
    db.add(m.AuditLog(username=user, action=action, detail=detail[:500]))


def create_incident(db, title, events, user, source="api"):
    for i, e in enumerate(events):
        e.setdefault("id", f"E{i + 1:05d}")
    det = detect(events)
    inc = m.Incident(title=title, source=source, classification=det["classification"],
                     incident_type=det["incident_type"], severity=det["severity"], confidence=det["confidence"],
                     status="DETECTED" if det["classification"] != "NORMAL" else "NORMAL",
                     detection=det, events=events, detected_at=det["timestamp"])
    db.add(inc)
    audit(db, user, "incident_created", f"{title} -> {det['classification']}")
    db.commit()
    db.refresh(inc)
    return inc


def investigate(db, inc, user):
    code = f"INC-{inc.id:03d}"
    res = run_investigation(inc.events, inc.detection, code)
    for t in db.query(m.Investigation).filter_by(incident_id=inc.id).all():
        db.delete(t)
    for M in (m.AgentFinding, m.Evidence, m.RiskAssessment, m.RagSource, m.Report, m.ResponseRecommendation):
        for row in db.query(M).filter_by(incident_id=inc.id).all():
            db.delete(row)
    db.add(m.Investigation(incident_id=inc.id, steps=res["trace"], result=res, duration_s=res["duration_s"]))
    for mod, fs in res["findings"].items():
        for f in fs:
            db.add(m.AgentFinding(incident_id=inc.id, module=mod, category=f["category"], finding=f["finding"],
                                  confidence=f["confidence"], data={k: v for k, v in f.items() if k != "evidence_ids"}))
    for e in res["correlation"]["evidence"]:
        db.add(m.Evidence(incident_id=inc.id, code=e["id"], source=e["source"], description=e["description"],
                          timestamp=e["timestamp"], severity=e["severity"], confidence=e["confidence"]))
    db.add(m.RiskAssessment(incident_id=inc.id, score=res["risk"]["score"], level=res["risk"]["level"],
                            components=res["risk"]["components"]))
    for r in res["rag"]:
        db.add(m.RagSource(incident_id=inc.id, source=r["source"], score=r["score"], excerpt=r["text"][:400]))
    db.add(m.Report(incident_id=inc.id, ai=res["ai"]))
    for r in res["recommendations"]:
        db.add(m.ResponseRecommendation(incident_id=inc.id, action=r["action"], rationale=r["rationale"]))
    if inc.status != "NORMAL":
        inc.status = "INVESTIGATED"
    audit(db, user, "investigation_run", code)
    db.commit()
    return res


def approval_state(db, inc):
    recs = db.query(m.ResponseRecommendation).filter_by(incident_id=inc.id).all()
    if not recs:
        return {"status": "N/A"}
    st = recs[0].status
    return {"status": st, "comment": recs[0].comment, "decided_by": recs[0].decided_by,
            "decided_at": recs[0].decided_at.isoformat() if recs[0].decided_at else None,
            "actions": [{"action": r.action, "rationale": r.rationale} for r in recs]}


def get_result(db, inc_id):
    inv = db.query(m.Investigation).filter_by(incident_id=inc_id).order_by(m.Investigation.id.desc()).first()
    return inv.result if inv else None


def decide(db, inc, user, approve, comment):
    st = "APPROVED" if approve else "REJECTED"
    for r in db.query(m.ResponseRecommendation).filter_by(incident_id=inc.id).all():
        r.status, r.decided_by, r.decided_at, r.comment = st, user, datetime.utcnow(), comment
    inc.status = st
    audit(db, user, f"response_{st.lower()}", f"INC-{inc.id:03d} {comment}")
    db.commit()


def incident_dict(inc, with_events=False):
    d = {"id": inc.id, "code": f"INC-{inc.id:03d}", "title": inc.title, "status": inc.status,
         "classification": inc.classification, "incident_type": inc.incident_type, "severity": inc.severity,
         "confidence": inc.confidence, "detected_at": inc.detected_at, "source": inc.source,
         "created_at": inc.created_at.isoformat() if inc.created_at else None,
         "detection": inc.detection, "event_count": len(inc.events or [])}
    if with_events:
        d["events"] = (inc.events or [])[:500]
    return d


def report_for(db, inc):
    res = get_result(db, inc.id)
    if not res:
        return None
    return build_report(incident_dict(inc), res, approval_state(db, inc))
