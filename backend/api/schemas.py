from typing import List, Optional
from pydantic import BaseModel, Field


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class EventIn(BaseModel):
    timestamp: str
    event_type: str = Field(max_length=32)
    src_ip: Optional[str] = Field(default=None, max_length=45)
    dst_ip: Optional[str] = Field(default=None, max_length=45)
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)
    user: Optional[str] = Field(default=None, max_length=64)
    message: Optional[str] = Field(default="", max_length=500)
    latency_ms: Optional[int] = None
    flow: Optional[dict] = None


class IncidentIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    events: List[EventIn] = Field(min_length=1, max_length=20000)


class DemoIn(BaseModel):
    scenario: str
    seed: int = 0


class DecisionIn(BaseModel):
    comment: str = Field(default="", max_length=500)


class RagQuery(BaseModel):
    query: str = Field(min_length=2, max_length=300)
    k: int = Field(default=4, ge=1, le=10)
