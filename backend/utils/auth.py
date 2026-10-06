from datetime import datetime, timedelta
import bcrypt
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from backend.config import settings

bearer = HTTPBearer(auto_error=False)


def hash_password(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def verify_password(pw, hashed):
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except ValueError:
        return False


def create_token(username):
    exp = datetime.utcnow() + timedelta(minutes=settings.token_minutes)
    return jwt.encode({"sub": username, "exp": exp}, settings.secret_key, algorithm="HS256")


def current_user(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    if cred is None:
        raise HTTPException(401, "Not authenticated")
    try:
        return jwt.decode(cred.credentials, settings.secret_key, algorithms=["HS256"])["sub"]
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
