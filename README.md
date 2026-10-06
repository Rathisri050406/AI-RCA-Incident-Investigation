# AI-Based Autonomous Root-Cause Analysis and Cybersecurity Incident Investigation

Final-year B.Tech (CSE - AI & ML) project. A software-only platform that **detects** an abnormal event and investigates **why** it happened:
ML detection → log + network/security analysis → evidence correlation → root-cause analysis → risk scoring → RAG retrieval → generative-AI
explanation → incident report (PDF) → **human approve/reject** → dashboard.

## Abstract
Security teams are flooded with alerts and lack the time to find root causes. This system combines an ML flow detector (XGBoost, with Random Forest and
Logistic Regression baselines), rule-based log analysis, evidence correlation, a transparent weighted RCA engine, a deterministic risk score, a RAG
knowledge base, and an LLM layer that separates FACT / INFERENCE / RECOMMENDATION. No response is executed automatically; every recommended action needs
analyst approval. All demos use synthetic data.

## Objectives
1. Detect incidents and separate NORMAL / SUSPICIOUS / INCIDENT. 2. Collect and correlate evidence from several analysis modules.
3. Produce a ranked, explainable root cause with confidence and alternatives. 4. Score risk 0-100 with documented logic.
5. Ground explanations in a knowledge base (RAG) with real source names. 6. Keep a human in control of response actions.

## Architecture
```
DATA SOURCES (CIC-IDS2017 / HDFS-BGL / CSV upload / demo scenarios)
  → Incident Detection (backend/ml)        → Investigation Orchestrator (backend/agents/orchestrator.py)
  → Log Analysis → Network/Security Analysis → Evidence Correlation → RCA (backend/rca)
  → Risk (backend/risk) → RAG (backend/rag) → Generative AI (backend/utils/llm.py)
  → Incident Report (backend/reports) → Human Approval → React Dashboard (frontend)
```
Workflow engine: a fixed-topology, traceable pipeline (an allowed "equivalent controlled workflow" to LangGraph). Every step stores module, input,
output, timestamp, evidence used and status.

## Tech stack
Python 3.11+, FastAPI, SQLAlchemy (SQLite default, PostgreSQL supported), Pandas/NumPy/scikit-learn/XGBoost/Joblib, scikit-learn TF-IDF or
Sentence-Transformers + FAISS (optional) for RAG, ReportLab (PDF), JWT + bcrypt auth, React + Vite + Recharts.

## Installation
```bash
python -m venv venv
venv\Scripts\activate            # Windows   (Linux/macOS: source venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env           # Linux/macOS: cp .env.example .env  - then edit SECRET_KEY and ADMIN_PASSWORD
```

## Database
Default `DATABASE_URL` is empty → SQLite file `incident_rca.db` (zero setup). For PostgreSQL:
```bash
psql -U postgres -c "CREATE DATABASE incident_rca;"
# in .env:  DATABASE_URL=postgresql+psycopg2://postgres:PASSWORD@localhost:5432/incident_rca
```
Tables are created automatically on startup (users, incidents, investigations, agent_findings, evidence, risk_assessments, rag_sources, reports,
response_recommendations, audit_logs). The admin user is created from `ADMIN_USERNAME` / `ADMIN_PASSWORD` (bcrypt-hashed).

## Datasets and ML training
Download CIC-IDS2017 "MachineLearningCVE" CSVs into `datasets/raw/cic-ids2017/`, then:
```bash
python scripts/train_detector.py --cic datasets/raw/cic-ids2017 --max-rows 300000
python scripts/evaluate_detector.py
```
Output: `backend/models/detector.pkl`, `metrics.json`, and plots (confusion matrix, class distribution, feature importance, metrics).
Pipeline: clean → NaN/inf handling → duplicate removal (before the split, to prevent leakage) → feature engineering → stratified train/test split →
fit on train only → metrics on test only (accuracy, precision, recall, F1, ROC-AUC, FPR, confusion matrix).
Without a dataset, `python scripts/train_detector.py --synthetic` trains on synthetic flows. **Those metrics are labelled synthetic and do not
indicate real-world performance.** If you skip training, the server auto-trains on synthetic data the first time it is needed.
`backend/ml/data_loader.py` also contains `load_bgl` / `load_hdfs` log loaders; log anomaly detection in this prototype is rule-based
(`backend/agents/log_analysis.py`), so BGL/HDFS are supported for loading/exploration, not for a trained log model (see Future enhancements).
Custom CSVs: upload flow-feature CSVs (CIC-style column names are mapped automatically) or log-event CSVs (`timestamp,event_type,src_ip,user,message`).

## RAG
Put `.md`, `.txt` or `.pdf` files in `knowledge_base/` (7 project-authored notes are included; they summarise common guidance in original wording and
cite MITRE ATT&CK technique IDs and NIST SP 800-61 by name only). Replace/extend them with real NIST/MITRE documents you are licensed to use.
Install `sentence-transformers` and `faiss-cpu` for neural embeddings; otherwise TF-IDF + numpy cosine search is used. Retrieved results always carry the real file name.

## LLM configuration
`LLM_PROVIDER=none` (default): deterministic template narrative, tags every line FACT / INFERENCE / RECOMMENDATION.
`LLM_PROVIDER=openai_compatible` + `LLM_MODEL`, `LLM_API_KEY`, `LLM_BASE_URL` in `.env`: sends only the structured evidence context. On any failure it falls back to the template.

## Run
```bash
uvicorn backend.main:app --reload --port 8000        # API docs: http://localhost:8000/docs
cd frontend && npm install && npm run dev            # http://localhost:5173  (copy frontend/.env.example to .env if the API URL differs)
```
Login with `ADMIN_USERNAME` / `ADMIN_PASSWORD` from `.env`.

## Demo
Dashboard → **Demo Mode** → pick a scenario (Normal, Repeated failed logins, Suspicious network, Application/DB failure, Multi-stage). The system generates
synthetic events and runs the whole pipeline, then opens the incident (Overview, Timeline, Evidence, Root Cause, Risk, RAG, AI Report/PDF, Approval).

## Distributed mode (optional)
Local mode needs one laptop. For three machines: **Computer 2 (server)** set `DEPLOY_MODE=distributed`, `BACKEND_HOST=0.0.0.0`, `FRONTEND_ORIGIN=http://<dashboard-ip>:5173`
and run `uvicorn backend.main:app --host 0.0.0.0 --port 8000`. **Computer 3 (dashboard)** set `VITE_API_URL=http://<server-ip>:8000` in `frontend/.env`, run `npm run dev -- --host`.
**Computer 1 (target)**: `python scripts/target_simulator.py --server http://<server-ip>:8000 --scenario failed_logins --password '<admin password>'`.
Use a trusted lab network; add HTTPS before any real deployment.

## API (all except /api/health and /api/auth/login need `Authorization: Bearer <token>`)
`POST /api/auth/login` · `POST /api/incidents` · `POST /api/incidents/upload` · `GET /api/incidents` · `GET /api/incidents/{id}` ·
`POST /api/incidents/{id}/investigate` · `GET /api/incidents/{id}/investigation|evidence|rca|risk|report[?format=pdf]` ·
`POST /api/incidents/{id}/approve|reject` · `POST /api/rag/search` · `GET /api/dashboard/statistics` ·
`POST /api/demo/run` · `GET /api/demo/scenarios` · `GET /api/ml/metrics` · `GET /api/evaluation/results`

## Testing and evaluation
```bash
pytest -q                                           # engine tests + API integration tests
python scripts/evaluate_investigation.py 20         # 20 seeds x 5 scenarios, compares A/B/C systems
```
`evaluate_investigation.py` writes `results/investigation_eval.json` (shown on the Model Performance page): detection accuracy, false-positive rate,
RCA accuracy, evidence coverage, report completeness (sections actually populated out of 16) and average time for
A) ML-only, B) detection + rule-based investigation, C) proposed system. Every number is computed from the runs; nothing is hard-coded.

## Risk scoring
`score = 100·(0.30·severity + 0.20·RCA confidence + 0.20·impact + 0.15·evidence strength + 0.15·incident-type weight)`; LOW <25, MEDIUM <50, HIGH <75, else CRITICAL.
Impact = min(1, affected sources+users+hosts / 10). Details in `backend/risk/risk.py`.

## Limitations (be honest in your viva)
- The investigation scenarios are synthetic and written by the same author as the rules, so near-perfect RCA/coverage there shows the pipeline works,
  **not** that it generalises to real attacks. Test with real logs and report the failures too.
- The RCA is a transparent weighted-rule engine over a fixed hypothesis set, not a learned model; unknown incident types return "undetermined".
- The ML detector uses 7 flow features (+4 derived). With CIC-IDS2017 expect some attack classes to be harder; report the real numbers.
- Log anomaly detection is rule/count based; no trained BGL/HDFS model yet.
- Auth is a single-admin prototype (no login rate limiting, no HTTPS, JWT in sessionStorage).
- LLM output depends on the configured model; the template provider is deterministic but generic.

## Future enhancements
Trained log-sequence model on HDFS/BGL (e.g. DeepLog-style), learned RCA ranking, LangGraph graph with conditional edges, role-based access, live log ingestion
(syslog/Kafka), Alembic migrations, SOAR integration with approval gates.
