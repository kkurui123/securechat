import hashlib
import hmac
import random
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
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
from app.models.entities import PasswordResetCode, User
from app.schemas.auth import Login, Registration


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


import os


SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "")
RESET_CODE_TTL_MINUTES = int(
    os.getenv("PASSWORD_RESET_CODE_TTL_MINUTES", "10")
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


def hash_reset_code(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def generate_reset_code():
    return f"{random.randint(100000, 999999)}"


def send_reset_code_email(
    recipient_email,
    reset_code,
):
    if (
        not SMTP_HOST
        or not SMTP_USERNAME
        or not SMTP_PASSWORD
        or not SMTP_FROM_EMAIL
    ):
        raise HTTPException(
            status_code=503,
            detail=(
                "Password reset email is not configured. "
                "Contact an Administrator."
            ),
        )


    message = EmailMessage()


    message["Subject"] = "SecureChat password reset code"
    message["From"] = SMTP_FROM_EMAIL
    message["To"] = recipient_email


    message.set_content(
        f"""
Hello,


Your SecureChat password reset code is:


{reset_code}


This code expires in {RESET_CODE_TTL_MINUTES} minutes.


If you did not request a password reset, ignore this email.


SecureChat
"""
    )


    try:
        with smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT,
        ) as server:
            server.starttls()
            server.login(
                SMTP_USERNAME,
                SMTP_PASSWORD,
            )
            server.send_message(message)
    except Exception:
        raise HTTPException(
            status_code=502,
            detail=(
                "Unable to send the password reset email. "
                "Please try again later."
            ),
        ) from None


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
        minutes=RESET_CODE_TTL_MINUTES
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
