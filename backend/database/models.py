"""SQLAlchemy models. All queries go through the ORM (parameterized)."""
from datetime import datetime
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text, Boolean
from backend.database.db import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(16), default="admin")
    created_at = Column(DateTime, default=datetime.utcnow)


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    title = Column(String(200), nullable=False)
    source = Column(String(32), default="api")
    status = Column(String(24), default="DETECTED", index=True)  # DETECTED|INVESTIGATED|APPROVED|REJECTED|NORMAL
    classification = Column(String(16))
    incident_type = Column(String(40))
    severity = Column(String(12))
    confidence = Column(Float)
    detection = Column(JSON)
    events = Column(JSON)
    detected_at = Column(String(32))
    created_at = Column(DateTime, default=datetime.utcnow)


class Investigation(Base):
    __tablename__ = "investigations"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True)
    status = Column(String(16), default="completed")
    steps = Column(JSON)      # agent/module trace: name, input, output, timestamp, evidence, status
    result = Column(JSON)     # full structured result
    duration_s = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)


class AgentFinding(Base):
    __tablename__ = "agent_findings"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True)
    module = Column(String(40))
    category = Column(String(40))
    finding = Column(Text)
    confidence = Column(Float)
    data = Column(JSON)


class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True)
    code = Column(String(16))
    source = Column(String(40))
    description = Column(Text)
    timestamp = Column(String(32))
    severity = Column(String(12))
    confidence = Column(Float)


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True)
    score = Column(Float)
    level = Column(String(12))
    components = Column(JSON)


class RagSource(Base):
    __tablename__ = "rag_sources"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True)
    source = Column(String(120))
    score = Column(Float)
    excerpt = Column(Text)


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True)
    ai = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)


class ResponseRecommendation(Base):
    __tablename__ = "response_recommendations"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True)
    action = Column(Text)
    rationale = Column(Text)
    status = Column(String(12), default="PENDING")  # PENDING|APPROVED|REJECTED
    decided_by = Column(String(64))
    decided_at = Column(DateTime)
    comment = Column(Text)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    username = Column(String(64))
    action = Column(String(64))
    detail = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
