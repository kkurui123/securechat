from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.entities import User
from app.schemas.auth import Registration, Login
from app.guards.auth import passwords, dummy_hash, current, token

router = APIRouter(prefix="/auth", tags=["Authentication"])

def public_user(u):
    return {"id": u.id, "email": u.email, "phone": u.phone, "role": u.role, "active": u.active}

@router.post("/register", status_code=201)
def register(data: Registration, db: Session = Depends(get_db)):
    u = User(email=str(data.email).lower(), phone=data.phone,
             password_hash=passwords.hash(data.password), role="GUARD")
    db.add(u)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Registration unavailable with these details") from None
    return public_user(u)

@router.post("/login")
def login(data: Login, db: Session = Depends(get_db)):
    identifier = data.identifier.strip().lower()
    u = db.scalar(select(User).where(or_(User.email == identifier, User.phone == identifier)))
    valid = passwords.verify(data.password, u.password_hash if u else dummy_hash)
    if not u or not valid or not u.active:
        raise HTTPException(401, "Invalid email/phone or password")
    return {"access_token": token(u), "token_type": "bearer", "expires_in": 1800, "user": public_user(u)}

@router.get("/me")
def me(user: User = Depends(current)):
    return public_user(user)
