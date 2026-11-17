import hashlib
import logging
import random
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.guards.auth import (
    current,
    dummy_hash,
    passwords,
    token,
)
from app.models.entities import PasswordResetCode, User
from app.schemas.auth import Login, Registration


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


logger = logging.getLogger("uvicorn.error")


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


def hash_reset_code(code):
    return hashlib.sha256(
        code.encode("utf-8")
    ).hexdigest()


def generate_reset_code():
    return f"{random.randint(100000, 999999)}"


def send_reset_code_email(
    recipient_email,
    reset_code,
):
    current_settings = settings()

    resend_api_key = current_settings.resend_api_key
    email_from = current_settings.email_from

    reset_code_ttl_minutes = (
        current_settings.password_reset_code_ttl_minutes
    )

    resend_api_key_value = (
        resend_api_key.get_secret_value()
        if resend_api_key is not None
        else ""
    )

    if not resend_api_key_value or not email_from:
        logger.error(
            "Password reset email is not configured. "
            "Check RESEND_API_KEY and EMAIL_FROM "
            "environment variables."
        )

        raise HTTPException(
            status_code=503,
            detail=(
                "Password reset email is not configured. "
                "Contact an Administrator."
            ),
        )

    try:
        response = httpx.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": (
                    f"Bearer {resend_api_key_value}"
                ),
                "Content-Type": "application/json",
            },
            json={
                "from": email_from,
                "to": [recipient_email],
                "subject": "SecureChat password reset code",
                "text": (
                    "Hello,\n\n"
                    "Your SecureChat password reset code is:\n\n"
                    f"{reset_code}\n\n"
                    "This code expires in "
                    f"{reset_code_ttl_minutes} minutes.\n\n"
                    "If you did not request a password reset, "
                    "ignore this email.\n\n"
                    "SecureChat"
                ),
            },
            timeout=30,
        )

    except Exception as error:
        logger.error(
            "Password reset email request failed: %s",
            error,
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Unable to send the password reset email. "
                "Please try again later."
            ),
        ) from None

    if response.status_code < 200 or response.status_code >= 300:
        logger.error(
            "Resend returned status %s: %s",
            response.status_code,
            response.text,
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Unable to send the password reset email. "
                "Please try again later."
            ),
        )


class ForgotPasswordInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(
        min_length=5,
        max_length=254,
    )


class ResetPasswordInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(
        min_length=5,
        max_length=254,
    )

    code: str = Field(
        min_length=6,
        max_length=6,
    )

    new_password: str = Field(
        min_length=8,
        max_length=128,
    )

    confirm_password: str = Field(
        min_length=8,
        max_length=128,
    )


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


@router.post("/forgot-password")
def forgot_password(
    data: ForgotPasswordInput,
    db: Session = Depends(get_db),
):
    email = data.email.strip().lower()

    user = db.scalar(
        select(User).where(
            User.email == email,
        )
    )

    if user is None or not user.active:
        return {
            "message": (
                "If this email is registered, a reset code "
                "has been sent."
            ),
        }

    reset_code = generate_reset_code()

    code_hash = hash_reset_code(reset_code)

    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings().password_reset_code_ttl_minutes
    )

    db.query(PasswordResetCode).filter(
        PasswordResetCode.email == email,
        PasswordResetCode.used_at.is_(None),
    ).update(
        {
            "used_at": datetime.now(timezone.utc),
        }
    )

    db.add(
        PasswordResetCode(
            email=email,
            code_hash=code_hash,
            expires_at=expires_at,
        )
    )

    db.commit()

    send_reset_code_email(
        email,
        reset_code,
    )

    return {
        "message": (
            "If this email is registered, a reset code "
            "has been sent."
        ),
    }


@router.post("/reset-password")
def reset_password(
    data: ResetPasswordInput,
    db: Session = Depends(get_db),
):
    if data.new_password != data.confirm_password:
        raise HTTPException(
            status_code=422,
            detail="Passwords do not match",
        )

    email = data.email.strip().lower()
    code = data.code.strip()

    if not code.isdigit():
        raise HTTPException(
            status_code=422,
            detail="Enter the 6-digit reset code",
        )

    user = db.scalar(
        select(User).where(
            User.email == email,
        )
    )

    if user is None or not user.active:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset code",
        )

    code_hash = hash_reset_code(code)

    reset_record = db.scalar(
        select(PasswordResetCode)
        .where(
            PasswordResetCode.email == email,
            PasswordResetCode.code_hash == code_hash,
            PasswordResetCode.used_at.is_(None),
        )
        .order_by(
            PasswordResetCode.created_at.desc(),
        )
    )

    if reset_record is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset code",
        )

    expires_at = reset_record.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(
            tzinfo=timezone.utc
        )

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset code",
        )

    user.password_hash = passwords.hash(
        data.new_password
    )

    reset_record.used_at = datetime.now(timezone.utc)

    db.commit()

    return {
        "message": (
            "Password reset successfully. "
            "You can now log in with your new password."
        ),
    }
