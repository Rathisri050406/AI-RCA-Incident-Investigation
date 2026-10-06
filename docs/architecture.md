# Architecture
Flow: data → `ml/detector.detect()` → `agents/orchestrator.run_investigation()` → log analysis → security analysis → `agents/correlation` → `rag` → `rca/rca` → `risk/risk` → `utils/llm` → `reports/report` → human approval (`api/service.decide`) → dashboard.
The orchestrator picks modules by incident type (`PLANS`) and records a trace entry per step. Persistence: `api/service.py`; tables in `database/models.py`.
Modes: local (one laptop, SQLite or PostgreSQL) and distributed (see README).
