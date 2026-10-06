"""API integration tests (need requirements installed). Uses a temp SQLite DB."""
import os, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/t.db"
os.environ["ADMIN_PASSWORD"] = "TestPass123!"
from fastapi.testclient import TestClient
from backend.main import app


def client():
    c = TestClient(app).__enter__()
    tok = c.post("/api/auth/login", json={"username": "admin", "password": "TestPass123!"}).json()["access_token"]
    c.headers["Authorization"] = f"Bearer {tok}"
    return c


def test_auth_required_and_bad_login():
    with TestClient(app) as c:
        assert c.get("/api/incidents").status_code == 401
        assert c.post("/api/auth/login", json={"username": "admin", "password": "x"}).status_code == 401


def test_demo_flow_approve_and_report():
    c = client()
    inc = c.post("/api/demo/run", json={"scenario": "failed_logins", "seed": 1}).json()
    i = inc["id"]
    assert inc["rca"]["root_cause_key"] == "brute_force"
    assert c.get(f"/api/incidents/{i}/evidence").json()["evidence"]
    assert c.get(f"/api/incidents/{i}/risk").json()["level"]
    assert c.get(f"/api/incidents/{i}/report?format=pdf").content[:4] == b"%PDF"
    assert c.post(f"/api/incidents/{i}/approve", json={"comment": "ok"}).json()["status"] == "APPROVED"
    assert c.get("/api/dashboard/statistics").json()["resolved"] == 1


def test_validation_errors():
    c = client()
    assert c.post("/api/incidents", json={"title": "x", "events": []}).status_code == 422
    assert c.get("/api/incidents/9999").status_code == 404
    assert c.post("/api/rag/search", json={"query": "brute force"}).json()["results"]
