import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router
from backend.config import settings
from backend.database import models
from backend.database.db import Base, SessionLocal, engine
from backend.utils.auth import hash_password

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine)
    db = SessionLocal()
    try:
        if not db.query(models.User).filter_by(username=settings.admin_username).first():
            db.add(models.User(username=settings.admin_username, password_hash=hash_password(settings.admin_password)))
            db.commit()
    finally:
        db.close()
    (settings.model_dir / "plots").mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title="AI-Based Autonomous Root-Cause Analysis and Cybersecurity Incident Investigation",
              version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[settings.frontend_origin, "http://127.0.0.1:5173"],
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(router)
app.mount("/static/plots", StaticFiles(directory=str(settings.model_dir / "plots"), check_dir=False), name="plots")
