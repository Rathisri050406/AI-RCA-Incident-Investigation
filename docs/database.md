# Database
Tables: users, incidents, investigations (steps trace + full result JSON), agent_findings, evidence, risk_assessments, rag_sources, reports, response_recommendations (PENDING/APPROVED/REJECTED + decider), audit_logs.
All access through the SQLAlchemy ORM (parameterised). Passwords: bcrypt hashes. Add Alembic (`alembic init`) if you need migrations beyond `create_all`.
