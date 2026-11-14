from typing import Literal
from pydantic import BaseModel, EmailStr, Field, ConfigDict, model_validator

class Registration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    phone: str = Field(pattern=r"^[0-9]{10}$")
    password: str = Field(min_length=12, max_length=128)
    confirm_password: str
    @model_validator(mode="after")
    def passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self

class Login(BaseModel):
    identifier: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=128)

class ConversationInput(BaseModel):
    guard_id: str

class MessageInput(BaseModel):
    client_message_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    kind: Literal["TEXT", "PHOTO"]
    ciphertext: str = Field(min_length=1, max_length=2800000)

class IncidentInput(BaseModel):
    report_type: Literal["CONVERSATION", "GUARD"]
    conversation_id: str | None = None
    reported_guard_id: str | None = None
    reason: str = Field(min_length=5, max_length=4000)

class Decision(BaseModel):
    decision: Literal["APPROVED", "REJECTED"]

class StatusInput(BaseModel):
    active: bool
