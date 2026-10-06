import io
import json
import logging
from collections import Counter
import pandas as pd
from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile
from sqlalchemy.orm import Session

from backend.api import schemas, service
from backend.config import settings
from backend.database import models as m
from backend.database.db import get_db
from backend.ml.preprocessor import CANONICAL, normalize_columns
from backend.rag import rag_pipeline
from backend.reports.report import to_pdf
from backend.utils import auth
from backend.utils.demo import SCENARIOS, generate_scenario

log = logging.getLogger("rca.api")
router = APIRouter(prefix="/api")


def _inc(db, inc_id):
    inc = db.get(m.Incident, inc_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    return inc


def _res(db, inc_id):
    res = service.get_result(db, inc_id)
    if not res:
        raise HTTPException(409, "Incident has not been investigated yet")
    return res


@router.get("/health")
def health():
    return {"status": "ok", "mode": settings.deploy_mode}


@router.post("/auth/login", response_model=schemas.TokenOut)
def login(body: schemas.LoginIn, db: Session = Depends(get_db)):
    user = db.query(m.User).filter(m.User.username == body.username).first()
    if not user or not auth.verify_password(body.password, user.password_hash):
        service.audit(db, body.username, "login_failed")
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    service.audit(db, user.username, "login_ok")
    db.commit()
    return {"access_token": auth.create_token(user.username)}


@router.post("/incidents")
def create_incident(body: schemas.IncidentIn, db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    events = [e.model_dump() if hasattr(e, "model_dump") else e.dict() for e in body.events]
    return service.incident_dict(service.create_incident(db, body.title, events, user))


@router.post("/incidents/upload")
async def upload_csv(file: UploadFile = File(...), db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    raw = await file.read()
    if len(raw) > 20_000_000:
        raise HTTPException(413, "File too large (20 MB max)")
    try:
        df = normalize_columns(pd.read_csv(io.BytesIO(raw), nrows=20000))
    except Exception:
        raise HTTPException(400, "Could not parse CSV")
    events = []
    if all(c in df.columns for c in CANONICAL):                      # flow-feature CSV (CIC-style)
        for i, row in enumerate(df.to_dict("records")):
            events.append({"id": f"E{i + 1:05d}", "timestamp": str(row.get("timestamp", "2026-01-01T00:00:00")),
                           "event_type": "flow", "src_ip": str(row.get("src_ip", "unknown")),
                           "dst_ip": str(row.get("dst_ip", "unknown")), "dst_port": int(row["dst_port"]),
                           "flow": {c: float(row[c]) for c in CANONICAL}, "message": "uploaded flow"})
    elif {"timestamp", "event_type"} <= set(df.columns):               # log-event CSV
        for i, row in enumerate(df.fillna("").to_dict("records")):
            events.append({"id": f"E{i + 1:05d}", "timestamp": str(row["timestamp"]), "event_type": str(row["event_type"]),
                           "src_ip": str(row.get("src_ip", "")), "dst_ip": str(row.get("dst_ip", "")),
                           "user": str(row.get("user", "")) or None, "message": str(row.get("message", ""))[:500],
                           "dst_port": int(row["dst_port"]) if str(row.get("dst_port", "")).isdigit() else None})
    else:
        raise HTTPException(400, f"CSV needs columns {CANONICAL} (flows) or timestamp,event_type[,src_ip,user,message] (logs)")
    return service.incident_dict(service.create_incident(db, f"Uploaded: {file.filename}", events, user, "csv_upload"))


@router.get("/incidents")
def list_incidents(db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    return [service.incident_dict(i) for i in db.query(m.Incident).order_by(m.Incident.id.desc()).limit(500).all()]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    inc = _inc(db, incident_id)
    d = service.incident_dict(inc, with_events=True)
    d["approval"] = service.approval_state(db, inc)
    res = service.get_result(db, inc.id)
    d["investigated"] = res is not None
    if res:
        d.update(rca=res["rca"], risk=res["risk"], ai=res["ai"], rag=res["rag"])
    return d


@router.post("/incidents/{incident_id}/investigate")
def investigate(incident_id: int, db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    inc = _inc(db, incident_id)
    try:
        res = service.investigate(db, inc, user)
    except Exception as exc:
        log.exception("investigation failed")
        raise HTTPException(500, f"Investigation failed: {exc}")
    return {"incident": service.incident_dict(inc), "rca": res["rca"], "risk": res["risk"], "duration_s": res["duration_s"]}


@router.get("/incidents/{incident_id}/investigation")
def investigation(incident_id: int, db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    _inc(db, incident_id)
    res = _res(db, incident_id)
    return {"trace": res["trace"], "duration_s": res["duration_s"], "findings": res["findings"]}


@router.get("/incidents/{incident_id}/evidence")
def evidence(incident_id: int, db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    _inc(db, incident_id)
    res = _res(db, incident_id)
    return {"evidence": res["correlation"]["evidence"], "groups": res["correlation"]["groups"],
            "strength": res["correlation"]["strength"], "summary": res["correlation"]["summary"]}


@router.get("/incidents/{incident_id}/rca")
def rca(incident_id: int, db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    _inc(db, incident_id)
    res = _res(db, incident_id)
    return {"rca": res["rca"], "ai": res["ai"], "rag": res["rag"]}


@router.get("/incidents/{incident_id}/risk")
def risk(incident_id: int, db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    _inc(db, incident_id)
    return _res(db, incident_id)["risk"]


@router.get("/incidents/{incident_id}/report")
def report(incident_id: int, format: str = "json", db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    inc = _inc(db, incident_id)
    _res(db, incident_id)
    rep = service.report_for(db, inc)
    if format == "pdf":
        return Response(to_pdf(rep), media_type="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename={rep['1_incident_id']}.pdf"})
    return rep


def _decision(incident_id, body, db, user, approve):
    inc = _inc(db, incident_id)
    _res(db, incident_id)
    service.decide(db, inc, user, approve, body.comment)
    return {"status": inc.status, "approval": service.approval_state(db, inc)}


@router.post("/incidents/{incident_id}/approve")
def approve(incident_id: int, body: schemas.DecisionIn, db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    return _decision(incident_id, body, db, user, True)


@router.post("/incidents/{incident_id}/reject")
def reject(incident_id: int, body: schemas.DecisionIn, db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    return _decision(incident_id, body, db, user, False)


@router.post("/rag/search")
def rag_search(body: schemas.RagQuery, user: str = Depends(auth.current_user)):
    return {"backend": getattr(rag_pipeline.get_retriever(), "backend", "?"),
            "results": rag_pipeline.search(body.query, body.k)}


@router.get("/demo/scenarios")
def scenarios(user: str = Depends(auth.current_user)):
    return SCENARIOS


@router.post("/demo/run")
def demo_run(body: schemas.DemoIn, db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    if body.scenario not in SCENARIOS:
        raise HTTPException(400, f"Unknown scenario. Choose from {list(SCENARIOS)}")
    events = generate_scenario(body.scenario, body.seed)
    inc = service.create_incident(db, f"Demo: {SCENARIOS[body.scenario]}", events, user, "demo")
    service.investigate(db, inc, user)
    return get_incident(inc.id, db, user)


@router.get("/dashboard/statistics")
def stats(db: Session = Depends(get_db), user: str = Depends(auth.current_user)):
    incs = db.query(m.Incident).all()
    risks = {r.incident_id: r.level for r in db.query(m.RiskAssessment).all()}
    by_day = Counter((i.created_at.date().isoformat() if i.created_at else "n/a") for i in incs)
    return {
        "total": len(incs),
        "active": sum(i.status in ("DETECTED", "INVESTIGATED") for i in incs),
        "high_risk": sum(v == "HIGH" for v in risks.values()),
        "critical": sum(v == "CRITICAL" for v in risks.values()),
        "resolved": sum(i.status == "APPROVED" for i in incs),
        "over_time": [{"date": k, "count": v} for k, v in sorted(by_day.items())],
        "severity": [{"name": k, "value": v} for k, v in Counter(i.severity for i in incs).items()],
        "types": [{"name": k, "value": v} for k, v in Counter(i.incident_type for i in incs).items()],
        "status": [{"name": k, "value": v} for k, v in Counter(i.status for i in incs).items()],
    }


@router.get("/ml/metrics")
def ml_metrics(user: str = Depends(auth.current_user)):
    from backend.ml.detector import get_model
    get_model()
    return json.loads((settings.model_dir / "metrics.json").read_text())


@router.get("/evaluation/results")
def eval_results(user: str = Depends(auth.current_user)):
    f = settings.results_dir / "investigation_eval.json"
    if not f.exists():
        raise HTTPException(404, "Run: python scripts/evaluate_investigation.py")
    return json.loads(f.read_text())
