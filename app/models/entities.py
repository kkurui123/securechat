import uuid
from datetime import datetime, timezone


from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column


from app.core.database import Base


def uid() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(timezone.utc)


# =========================================================
# USERS
# =========================================================


class User(Base):
    __tablename__ = "users"


    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=uid,
    )


    full_name: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
    )


    email: Mapped[str] = mapped_column(
        String(320),
        unique=True,
        nullable=False,
    )


    phone: Mapped[str | None] = mapped_column(
        String(10),
        unique=True,
        nullable=True,
    )


    zone: Mapped[str | None] = mapped_column(
        String(10),
        nullable=True,
    )


    password_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )


    role: Mapped[str] = mapped_column(
        String(10),
        default="GUARD",
        nullable=False,
    )


    active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )


    is_suspended: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        server_default=text("false"),
    )


    # Public X25519 key only.
    # Private keys remain on the Guard's device.
    encryption_public_key: Mapped[str | None] = mapped_column(
        String(44),
        nullable=True,
    )


    profile_photo_url: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )


# =========================================================
# CONVERSATIONS
# =========================================================


class Conversation(Base):
    __tablename__ = "conversations"


    __table_args__ = (
        UniqueConstraint(
            "guard_a",
            "guard_b",
            name="uq_conversations_guard_pair",
        ),
    )


    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=uid,
    )


    guard_a: Mapped[str] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )


    guard_b: Mapped[str] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )


    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=now,
        nullable=False,
    )


# =========================================================
# MESSAGES
# =========================================================


class Message(Base):
    __tablename__ = "messages"


    __table_args__ = (
        UniqueConstraint(
            "sender_id",
            "client_message_id",
            name="uq_messages_sender_client_id",
        ),
    )


    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=uid,
    )


    conversation_id: Mapped[str] = mapped_column(
        ForeignKey("conversations.id"),
        index=True,
        nullable=False,
    )


    sender_id: Mapped[str] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )


    client_message_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
    )


    # Current Flutter code uses TEXT as the outer transport
    # kind for text, photos, and files. The actual content type
    # is inside the encrypted JSON payload.
    kind: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
    )


    ciphertext: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )


    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=now,
        nullable=False,
    )


    # NULL means the recipient has not read the message yet.
    read_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


# =========================================================
# INCIDENTS
# =========================================================


class Incident(Base):
    __tablename__ = "incidents"


    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=uid,
    )


    reported_by: Mapped[str] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )


    report_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )


    conversation_id: Mapped[str | None] = mapped_column(
        ForeignKey("conversations.id"),
        nullable=True,
    )


    reported_guard_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
    )


    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )


    status: Mapped[str] = mapped_column(
        String(20),
        default="PENDING",
        nullable=False,
    )


    reviewed_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
    )


    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=now,
        nullable=False,
    )


# =========================================================
# RECOVERY REQUESTS
# =========================================================


class RecoveryRequest(Base):
    __tablename__ = "recovery_requests"


    __table_args__ = (
        UniqueConstraint(
            "incident_id",
            name="uq_recovery_requests_incident",
        ),
    )


    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=uid,
    )


    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id"),
        unique=True,
        nullable=False,
    )


    requested_by: Mapped[str] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )


    status: Mapped[str] = mapped_column(
        String(20),
        default="PENDING",
        nullable=False,
    )


    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )


    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=now,
        nullable=False,
    )


    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )