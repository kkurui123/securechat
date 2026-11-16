import base64
import binascii


from datetime import datetime, timezone


from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool


from app.core.database import SessionLocal, get_db
from app.guards.auth import current, guard
from app.models.entities import Conversation, Message, User
from app.routes.realtime import publish
from app.schemas.auth import ConversationInput, MessageInput
from app.services.chat import member, message_dict, save_message



router = APIRouter(
    tags=["Chat"],
)



# =========================================================
# ENCRYPTION KEY SCHEMA
# =========================================================



class EncryptionKeyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


    public_key: str = Field(
        min_length=44,
        max_length=44,
    )



# =========================================================
# GUARD DIRECTORY AND SEARCH
# =========================================================



@router.get("/guards")
def list_guards(
    q: str = Query(
        default="",
        max_length=120,
    ),
    user: User = Depends(current),
    db: Session = Depends(get_db),
):
    if user.role not in {"GUARD", "ADMIN"}:
        raise HTTPException(
            status_code=403,
            detail="Guard or Administrator access required",
        )


    statement = select(User).where(
        User.role == "GUARD",
        User.active.is_(True),
        User.id != user.id,
    )


    search = q.strip()


    if search:
        statement = statement.where(
            or_(
                User.full_name.icontains(
                    search,
                    autoescape=True,
                ),
                User.zone.icontains(
                    search,
                    autoescape=True,
                ),
                User.email.icontains(
                    search,
                    autoescape=True,
                ),
                User.phone.icontains(
                    search,
                    autoescape=True,
                ),
            )
        )


    statement = statement.order_by(
        User.full_name.asc().nulls_last(),
        User.email.asc(),
    ).limit(100)


    users = db.scalars(statement)


    return [
        {
            "id": item.id,
            "full_name": item.full_name,
            "email": item.email,
            "phone": item.phone,
            "zone": item.zone,
            "profile_photo_url": item.profile_photo_url,
        }
        for item in users
    ]



# =========================================================
# REGISTER THE CURRENT GUARD'S PUBLIC KEY
# =========================================================



@router.post("/encryption-key")
def register_encryption_key(
    data: EncryptionKeyInput,
    user: User = Depends(guard),
    db: Session = Depends(get_db),
):
    try:
        decoded = base64.b64decode(
            data.public_key,
            validate=True,
        )
    except (ValueError, binascii.Error):
        raise HTTPException(
            status_code=422,
            detail="Invalid public key",
        ) from None


    if len(decoded) != 32 or decoded == bytes(32):
        raise HTTPException(
            status_code=422,
            detail="Invalid public key",
        )


    canonical_key = base64.b64encode(
        decoded
    ).decode("ascii")


    account = db.scalar(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
    )


    if (
        account is None
        or not account.active
        or account.role != "GUARD"
    ):
        raise HTTPException(
            status_code=403,
            detail="Active Guard account required",
        )


    if (
        account.encryption_public_key is not None
        and account.encryption_public_key != canonical_key
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "This account already has a different encryption "
                "identity. Use the original device. "
                "Automatic key replacement is disabled."
            ),
        )


    account.encryption_public_key = canonical_key


    db.commit()


    return {
        "public_key": canonical_key,
    }



# =========================================================
# GET A GUARD'S PUBLIC KEY
# =========================================================



@router.get("/guards/{guard_id}/encryption-key")
def get_encryption_key(
    guard_id: str,
    user: User = Depends(guard),
    db: Session = Depends(get_db),
):
    account = db.get(
        User,
        guard_id,
    )


    if (
        account is None
        or account.role != "GUARD"
        or not account.active
    ):
        raise HTTPException(
            status_code=404,
            detail="Guard not found",
        )


    return {
        "public_key": account.encryption_public_key,
    }



# =========================================================
# CREATE OR REOPEN A DIRECT CONVERSATION
# =========================================================



@router.post("/conversations")
def create_conversation(
    data: ConversationInput,
    user: User = Depends(guard),
    db: Session = Depends(get_db),
):
    other = db.get(
        User,
        data.guard_id,
    )


    if (
        other is None
        or other.role != "GUARD"
        or not other.active
        or other.id == user.id
    ):
        raise HTTPException(
            status_code=400,
            detail="Choose another active Guard",
        )


    guard_a, guard_b = sorted(
        [user.id, other.id]
    )


    def find_conversation():
        return db.scalar(
            select(Conversation).where(
                Conversation.guard_a == guard_a,
                Conversation.guard_b == guard_b,
            )
        )


    conversation = find_conversation()


    if conversation is None:
        conversation = Conversation(
            guard_a=guard_a,
            guard_b=guard_b,
        )


        db.add(conversation)


        try:
            db.commit()
        except IntegrityError:
            db.rollback()


            conversation = find_conversation()


            if conversation is None:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Unable to create the conversation. "
                        "Please try again."
                    ),
                ) from None


    return {
        "id": conversation.id,
        "guard_a": conversation.guard_a,
        "guard_b": conversation.guard_b,
    }



# =========================================================
# LIST THE CURRENT GUARD'S CONVERSATIONS
# =========================================================



@router.get("/conversations")
def list_conversations(
    user: User = Depends(guard),
    db: Session = Depends(get_db),
):
    statement = (
        select(Conversation)
        .where(
            or_(
                Conversation.guard_a == user.id,
                Conversation.guard_b == user.id,
            )
        )
        .order_by(
            Conversation.created_at.desc(),
            Conversation.id.desc(),
        )
        .limit(200)
    )


    conversations = db.scalars(statement)


    return [
        {
            "id": conversation.id,
            "guard_a": conversation.guard_a,
            "guard_b": conversation.guard_b,
        }
        for conversation in conversations
    ]



# =========================================================
# UNREAD MESSAGE COUNTS
# =========================================================



@router.get("/conversations/unread-counts")
def unread_counts(
    user: User = Depends(guard),
    db: Session = Depends(get_db),
):
    conversations = db.scalars(
        select(Conversation).where(
            or_(
                Conversation.guard_a == user.id,
                Conversation.guard_b == user.id,
            )
        )
    )


    results = []


    for conversation in conversations:
        unread_count = db.scalar(
            select(func.count(Message.id)).where(
                Message.conversation_id == conversation.id,
                Message.sender_id != user.id,
                Message.read_at.is_(None),
            )
        )


        results.append(
            {
                "conversation_id": conversation.id,
                "unread_count": int(unread_count or 0),
            }
        )


    return results



# =========================================================
# MARK A CONVERSATION AS READ
# =========================================================



@router.post("/conversations/{conversation_id}/mark-read")
def mark_read(
    conversation_id: str,
    user: User = Depends(guard),
    db: Session = Depends(get_db),
):
    conversation = member(
        db,
        conversation_id,
        user,
    )


    unread_messages = db.scalars(
        select(Message)
        .where(
            Message.conversation_id == conversation_id,
            Message.sender_id != user.id,
            Message.read_at.is_(None),
        )
        .with_for_update()
    )


    messages = list(unread_messages)


    read_at = None


    if messages:
        read_at = datetime.now(timezone.utc)


        for message in messages:
            message.read_at = read_at


        db.commit()


    recipients = [
        conversation.guard_a,
        conversation.guard_b,
    ]


    return {
        "conversation_id": conversation_id,
        "marked_count": len(messages),
        "read_at": (
            read_at.isoformat()
            if read_at is not None
            else None
        ),
    }



# =========================================================
# CONVERSATION MESSAGE HISTORY
# =========================================================



@router.get("/conversations/{conversation_id}/messages")
def get_messages(
    conversation_id: str,
    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    user: User = Depends(guard),
    db: Session = Depends(get_db),
):
    member(
        db,
        conversation_id,
        user,
    )


    statement = (
        select(Message)
        .where(
            Message.conversation_id == conversation_id
        )
        .order_by(
            Message.created_at.desc(),
            Message.id.desc(),
        )
        .offset(offset)
        .limit(limit)
    )


    messages = db.scalars(statement)


    return [
        message_dict(message)
        for message in messages
    ]



# =========================================================
# SEND AN ENCRYPTED MESSAGE
# =========================================================



@router.post(
    "/conversations/{conversation_id}/messages",
    status_code=201,
)
async def send_message(
    conversation_id: str,
    data: MessageInput,
    user: User = Depends(guard),
):
    sender_id = user.id


    def persist_message():
        with SessionLocal() as db:
            sender = db.get(
                User,
                sender_id,
            )


            if sender is None or not sender.active:
                raise HTTPException(
                    status_code=401,
                    detail="Inactive account",
                )


            if sender.role != "GUARD":
                raise HTTPException(
                    status_code=403,
                    detail="Guard access required",
                )


            return save_message(
                db,
                conversation_id,
                sender,
                data,
            )


    message, recipients = await run_in_threadpool(
        persist_message
    )


    await publish(
        recipients,
        {
            "type": "message",
            "message": message,
        },
    )


    return message