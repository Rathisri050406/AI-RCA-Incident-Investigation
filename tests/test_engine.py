"""Engine tests (no web server needed). Run: pytest -q"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pytest
from backend.agents import correlation, log_analysis
from backend.agents.orchestrator import run_investigation
from backend.ml.data_loader import generate_synthetic_flows
from backend.ml.detector import detect
from backend.ml.preprocessor import clean
from backend.rag import rag_pipeline
from backend.reports.report import build_report, to_pdf
from backend.risk.risk import assess
from backend.utils.demo import EXPECTED_ROOT_CAUSE, SCENARIOS, generate_scenario
from backend.utils import llm


def test_preprocessing_removes_duplicates_and_inf():
    df = generate_synthetic_flows(500)
    df = df._append(df.iloc[:10]) if hasattr(df, "_append") else df
    df.loc[0, "flow_duration"] = float("inf")
    X, y = clean(df)
    assert len(X) == len(y) and X.isna().sum().sum() == 0 and not X.duplicated().any()


def test_cic_style_column_names_are_mapped():
    df = generate_synthetic_flows(200).rename(columns={"flow_duration": " Flow Duration", "dst_port": " Destination Port",
                                                       "label": " Label"})
    X, _ = clean(df)
    assert "flow_duration" in X.columns


def test_normal_scenario_not_flagged():
    assert detect(generate_scenario("normal", 3))["classification"] == "NORMAL"


@pytest.mark.parametrize("name", [s for s in SCENARIOS if s != "normal"])
def test_incident_scenarios_detected(name):
    d = detect(generate_scenario(name, 3))
    assert d["incident_detected"] and d["evidence_ids"]


def test_log_analysis_finds_auth_failures():
    f = log_analysis.analyze(generate_scenario("failed_logins", 1))
    assert f[0]["category"] == "auth_failures" and f[0]["count"] >= 300


def test_correlation_evidence_fields():
    ev = generate_scenario("multi_stage", 1)
    r = run_investigation(ev, detect(ev), "INC-T")
    e = r["correlation"]["evidence"][0]
    assert {"id", "source", "description", "timestamp", "severity", "confidence", "related_incident"} <= set(e)


@pytest.mark.parametrize("name", [s for s in SCENARIOS if s != "normal"])
def test_end_to_end_root_cause(name):
    ev = generate_scenario(name, 5)
    r = run_investigation(ev, detect(ev))
    assert r["rca"]["root_cause_key"] == EXPECTED_ROOT_CAUSE[name]
    assert 0 < r["rca"]["confidence"] <= 0.95
    assert all(t["status"] in ("completed", "pending") for t in r["trace"])
    assert r["rag"] and all(x["source"].endswith((".md", ".txt", ".pdf")) for x in r["rag"])
    assert r["risk"]["level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_rag_returns_real_source_names():
    res = rag_pipeline.search("failed logins brute force", 3)
    assert res and res[0]["source"] == "01_brute_force_authentication.md"


def test_risk_deterministic_and_bounded():
    ev = generate_scenario("failed_logins", 2)
    d = detect(ev); r = run_investigation(ev, d)
    a, b = assess(d, r["rca"], r["correlation"], ev), assess(d, r["rca"], r["correlation"], ev)
    assert a == b and 0 <= a["score"] <= 100


def test_llm_template_tags_and_approval():
    ev = generate_scenario("db_failure", 1)
    r = run_investigation(ev, detect(ev))
    assert all(x.startswith("[RECOMMENDATION]") for x in r["ai"]["recommended_response"])
    assert all(x["requires_approval"] for x in r["recommendations"])


def test_report_has_16_sections_and_pdf():
    ev = generate_scenario("multi_stage", 1); d = detect(ev); r = run_investigation(ev, d)
    rep = build_report({"code": "INC-001", "detected_at": d["timestamp"], "detection": d}, r, {"status": "PENDING"})
    assert sum(k[0].isdigit() for k in rep) == 16
    assert to_pdf(rep)[:4] == b"%PDF"
