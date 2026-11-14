from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)


# =========================================================
# GUARD REGISTRATION
# =========================================================

class Registration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str = Field(
        min_length=2,
        max_length=120,
    )

    email: EmailStr

    phone: str = Field(
        pattern=r"^[0-9]{10}$",
    )

    zone: Literal[
        "Gate A",
        "Gate B",
        "Gate C",
        "Gate D",
        "Gate E",
    ]

    password: str = Field(
        min_length=12,
        max_length=128,
    )

    confirm_password: str = Field(
        min_length=12,
        max_length=128,
    )

    @field_validator("full_name", mode="before")
    @classmethod
    def clean_full_name(cls, value):
        if isinstance(value, str):
            return " ".join(value.split())

        return value

    @model_validator(mode="after")
    def passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError(
                "Passwords do not match"
            )

        return self


# =========================================================
# GUARD / ADMIN LOGIN
# =========================================================

class Login(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Guard: email or phone.
    # Admin: email.
    identifier: str = Field(
        min_length=1,
        max_length=320,
    )

    password: str = Field(
        min_length=1,
        max_length=128,
    )


# =========================================================
# CREATE OR REOPEN A CONVERSATION
# =========================================================

class ConversationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    guard_id: str = Field(
        min_length=36,
        max_length=36,
    )


# =========================================================
# ENCRYPTED MESSAGE
# =========================================================

class MessageInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_message_id: str = Field(
        pattern=(
            r"^[0-9a-fA-F]{8}-"
            r"[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{12}$"
        ),
    )

    # Current Flutter code uses TEXT for all encrypted payloads.
    # The actual type—text, photo, or file—is inside the
    # encrypted JSON content.
    # PHOTO remains accepted for compatibility.
    kind: Literal[
        "TEXT",
        "PHOTO",
    ]

    # Base64-encoded encrypted envelope.
    # The service also checks its decoded size.
    ciphertext: str = Field(
        min_length=1,
        max_length=2800000,
    )


# =========================================================
# GUARD INCIDENT REPORT
# =========================================================

class IncidentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_type: Literal[
        "CONVERSATION",
        "GUARD",
    ]

    conversation_id: str | None = Field(
        default=None,
        min_length=36,
        max_length=36,
    )

    reported_guard_id: str | None = Field(
        default=None,
        min_length=36,
        max_length=36,
    )

    reason: str = Field(
        min_length=5,
        max_length=4000,
    )


# =========================================================
# ADMIN INCIDENT DECISION
# =========================================================

class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal[
        "APPROVED",
        "REJECTED",
    ]


# =========================================================
# ADMIN GUARD ACCOUNT STATUS
# =========================================================

class StatusInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    active: bool