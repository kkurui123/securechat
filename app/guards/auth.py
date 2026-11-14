from datetime import datetime, timezone, timedelta
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pwdlib import PasswordHash
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.models.entities import User

passwords = PasswordHash.recommended()
dummy_hash = passwords.hash("not-a-real-user-password")
bearer = HTTPBearer()

def token(user, kind="access", seconds=1800):
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": user.id, "type": kind, "iat": now,
                       "exp": now + timedelta(seconds=seconds), "iss": "securechat"},
                      settings().jwt_secret.get_secret_value(), algorithm="HS256")

def resolve(encoded, db, kind="access"):
    try:
        claims = jwt.decode(encoded, settings().jwt_secret.get_secret_value(),
                            algorithms=["HS256"], issuer="securechat",
                            options={"require": ["sub", "exp", "iat", "type"]})
        if claims["type"] != kind:
            raise ValueError()
        user = db.get(User, claims["sub"])
        if not user or not user.active:
            raise ValueError()
        return user, claims
    except (jwt.InvalidTokenError, ValueError):
        raise HTTPException(401, "Invalid or expired credentials") from None

def current(creds: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)):
    return resolve(creds.credentials, db)[0]

def admin(user: User = Depends(current)):
    if user.role != "ADMIN":
        raise HTTPException(403, "Admin access required")
    return user

def guard(user: User = Depends(current)):
    if user.role != "GUARD":
        raise HTTPException(403, "Guard access required")
    return user
