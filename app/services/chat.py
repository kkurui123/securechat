import base64
import binascii
import uuid


from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


from app.models.entities import Conversation, Message, User



# Limit the decoded encrypted envelope, not the plaintext.
MAX_ENCRYPTED_BYTES = 2_000_000


# Match the existing MessageInput ciphertext limit.
MAX_BASE64_CHARACTERS = 2_800_000


# AES-GCM envelope used by the Flutter client:
# 12-byte nonce + ciphertext + 16-byte authentication tag.
MIN_ENCRYPTED_BYTES = 28



# =========================================================
# CONVERSATION ACCESS
# =========================================================


def member(
    db: Session,
    conversation_id: str,
    user: User,
) -> Conversation:
    conversation = db.get(
        Conversation,
        conversation_id,
    )


    if (
        conversation is None
        or user.id not in (
            conversation.guard_a,
            conversation.guard_b,
        )
    ):
        raise HTTPException(
            status_code=404,
            detail="Conversation not found",
        )


    return conversation



# =========================================================
# MESSAGE SERIALIZATION
# =========================================================


def message_dict(
    message: Message,
) -> dict:
    return {
        "id": message.id,
        "conversation_id": message.conversation_id,
        "sender_id": message.sender_id,
        "client_message_id": message.client_message_id,
        "kind": message.kind,
        "ciphertext": message.ciphertext,
        "created_at": message.created_at.isoformat(),
        "read_at": (
            message.read_at.isoformat()
            if message.read_at is not None
            else None
        ),
    }



# =========================================================
# VALIDATION
# =========================================================


def validate_client_message_id(
    client_message_id: str,
) -> None:
    try:
        parsed = uuid.UUID(client_message_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=422,
            detail="client_message_id must be a valid UUID",
        ) from None


    if str(parsed) != client_message_id.lower():
        raise HTTPException(
            status_code=422,
            detail=(
                "client_message_id must use the standard "
                "hyphenated UUID format"
            ),
        )



def validate_ciphertext(
    ciphertext: str,
) -> None:
    if not isinstance(ciphertext, str) or not ciphertext:
        raise HTTPException(
            status_code=422,
            detail="ciphertext must be a nonempty Base64 string",
        )


    if len(ciphertext) > MAX_BASE64_CHARACTERS:
        raise HTTPException(
            status_code=413,
            detail="Encrypted message exceeds the size limit",
        )


    try:
        payload = base64.b64decode(
            ciphertext,
            validate=True,
        )
    except (ValueError, binascii.Error):
        raise HTTPException(
            status_code=422,
            detail="ciphertext must be valid Base64",
        ) from None


    if len(payload) < MIN_ENCRYPTED_BYTES:
        raise HTTPException(
            status_code=422,
            detail="Encrypted message envelope is incomplete",
        )


    if len(payload) > MAX_ENCRYPTED_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Encrypted message exceeds the size limit",
        )



# =========================================================
# IDEMPOTENT MESSAGE LOOKUP
# =========================================================


def find_existing_message(
    db: Session,
    sender_id: str,
    client_message_id: str,
) -> Message | None:
    return db.scalar(
        select(Message).where(
            Message.sender_id == sender_id,
            Message.client_message_id == client_message_id,
        )
    )



def verify_duplicate_content(
    existing: Message,
    conversation_id: str,
    kind: str,
    ciphertext: str,
) -> None:
    same_content = (
        existing.conversation_id == conversation_id
        and existing.kind == kind
        and existing.ciphertext == ciphertext
    )


    if not same_content:
        raise HTTPException(
            status_code=409,
            detail=(
                "This client_message_id has already been "
                "used for different content"
            ),
        )



# =========================================================
# SAVE ENCRYPTED MESSAGE
# =========================================================


def save_message(
    db: Session,
    conversation_id: str,
    user: User,
    data,
) -> tuple[dict, list[str]]:
    if not user.active:
        raise HTTPException(
            status_code=401,
            detail="Inactive account",
        )


    if user.role != "GUARD":
        raise HTTPException(
            status_code=403,
            detail="Guard access required",
        )


    conversation = member(
        db,
        conversation_id,
        user,
    )


    # Copy recipient IDs before a possible rollback.
    recipients = [
        conversation.guard_a,
        conversation.guard_b,
    ]


    # Keep PHOTO accepted for compatibility with the original
    # schema. The current Flutter client sends all inner
    # content types using the outer TEXT kind.
    if data.kind not in {"TEXT", "PHOTO"}:
        raise HTTPException(
            status_code=422,
            detail="Unsupported message kind",
        )


    validate_client_message_id(
        data.client_message_id,
    )


    validate_ciphertext(
        data.ciphertext,
    )


    sender_id = user.id


    existing = find_existing_message(
        db,
        sender_id,
        data.client_message_id,
    )


    if existing is not None:
        verify_duplicate_content(
            existing,
            conversation_id,
            data.kind,
            data.ciphertext,
        )


        return message_dict(existing), recipients


    message = Message(
        conversation_id=conversation_id,
        sender_id=sender_id,
        client_message_id=data.client_message_id,
        kind=data.kind,
        ciphertext=data.ciphertext,
    )


    db.add(message)


    try:
        db.commit()
    except IntegrityError:
        db.rollback()


        # A simultaneous retry may already have inserted
        # the same sender/client-message pair.
        existing = find_existing_message(
            db,
            sender_id,
            data.client_message_id,
        )


        if existing is None:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Unable to save the message. "
                    "Synchronize conversation history before retrying."
                ),
            ) from None


        verify_duplicate_content(
            existing,
            conversation_id,
            data.kind,
            data.ciphertext,
        )


        return message_dict(existing), recipients


    return message_dict(message), recipients