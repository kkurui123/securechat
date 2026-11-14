from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.guards.auth import (
    current,
    dummy_hash,
    passwords,
    token,
)
from app.models.entities import User
from app.schemas.auth import Login, Registration


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


def public_user(user):
    return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "zone": user.zone,
        "role": user.role,
        "active": user.active,
    }


@router.post("/register", status_code=201)
def register(
    data: Registration,
    db: Session = Depends(get_db),
):
    user = User(
        full_name=data.full_name,
        email=str(data.email).lower(),
        phone=data.phone,
        zone=data.zone,
        password_hash=passwords.hash(data.password),
        role="GUARD",
    )

    db.add(user)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="Registration unavailable with these details",
        ) from None

    return public_user(user)


@router.post("/login")
def login(
    data: Login,
    db: Session = Depends(get_db),
):
    identifier = data.identifier.strip().lower()

    user = db.scalar(
        select(User).where(
            or_(
                User.email == identifier,
                User.phone == identifier,
            )
        )
    )

    valid = passwords.verify(
        data.password,
        user.password_hash if user else dummy_hash,
    )

    if not user or not valid or not user.active:
        raise HTTPException(
            status_code=401,
            detail="Invalid email/phone or password",
        )

    return {
        "access_token": token(user),
        "token_type": "bearer",
        "expires_in": 1800,
        "user": public_user(user),
    }


@router.get("/me")
def me(
    user: User = Depends(current),
):
    return public_user(user)