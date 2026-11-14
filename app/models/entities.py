import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base

def uid():
    return str(uuid.uuid4())
def now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    phone: Mapped[str | None] = mapped_column(String(10), unique=True, nullable=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(10), default="GUARD")
    active: Mapped[bool] = mapped_column(Boolean, default=True)

class Conversation(Base):
    __tablename__ = "conversations"
    __table_args__ = (UniqueConstraint("guard_a", "guard_b"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    guard_a: Mapped[str] = mapped_column(ForeignKey("users.id"))
    guard_b: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (UniqueConstraint("sender_id", "client_message_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    conversation_id: Mapped[str] = mapped_column(ForeignKey("conversations.id"), index=True)
    sender_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    client_message_id: Mapped[str] = mapped_column(String(36))
    kind: Mapped[str] = mapped_column(String(10))
    ciphertext: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    reported_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    report_type: Mapped[str] = mapped_column(String(20))
    conversation_id: Mapped[str | None] = mapped_column(ForeignKey("conversations.id"), nullable=True)
    reported_guard_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="PENDING")
    reviewed_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
