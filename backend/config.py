"""Central configuration. All secrets come from environment variables / .env."""
import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def _get(name, default=""):
    return os.getenv(name) or default


class Settings:
    app_env = _get("APP_ENV", "local")
    deploy_mode = _get("DEPLOY_MODE", "local")  # local | distributed
    secret_key = _get("SECRET_KEY", "dev-only-change-me")
    token_minutes = int(_get("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    database_url = _get("DATABASE_URL", f"sqlite:///{(ROOT / 'incident_rca.db').as_posix()}")
    admin_username = _get("ADMIN_USERNAME", "admin")
    admin_password = _get("ADMIN_PASSWORD", "ChangeMe123!")
    llm_provider = _get("LLM_PROVIDER", "none")  # none | openai_compatible
    llm_model = _get("LLM_MODEL", "")
    llm_api_key = _get("LLM_API_KEY", "")
    llm_base_url = _get("LLM_BASE_URL", "https://api.openai.com/v1")
    embedding_backend = _get("EMBEDDING_BACKEND", "auto")  # auto | sbert | tfidf
    backend_host = _get("BACKEND_HOST", "127.0.0.1")
    backend_port = int(_get("BACKEND_PORT", "8000"))
    frontend_origin = _get("FRONTEND_ORIGIN", "http://localhost:5173")
    model_dir = ROOT / "backend" / "models"
    knowledge_dir = ROOT / "knowledge_base"
    results_dir = ROOT / "results"


settings = Settings()