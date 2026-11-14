import base64
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from app.models.entities import Conversation, Message

def member(db, cid, user):
    c = db.get(Conversation, cid)
    if not c or user.id not in (c.guard_a, c.guard_b):
        raise HTTPException(404, "Conversation not found")
    return c

def message_dict(m):
    return {"id": m.id, "conversation_id": m.conversation_id,
            "sender_id": m.sender_id, "client_message_id": m.client_message_id,
            "kind": m.kind, "ciphertext": m.ciphertext, "created_at": m.created_at.isoformat()}

def save_message(db, cid, user, data):
    c = member(db, cid, user)
    try:
        payload = base64.b64decode(data.ciphertext, validate=True)
        if not payload:
            raise ValueError()
    except (ValueError, base64.binascii.Error):
        raise HTTPException(422, "ciphertext must be nonempty base64") from None
    if data.kind == "TEXT" and len(payload) > 65536:
        raise HTTPException(413, "Text envelope too large")
    existing = db.scalar(select(Message).where(Message.sender_id == user.id,
                                               Message.client_message_id == data.client_message_id))
    if existing:
        if (existing.conversation_id, existing.kind, existing.ciphertext) != (cid, data.kind, data.ciphertext):
            raise HTTPException(409, "Message ID already used for different content")
        return message_dict(existing), [c.guard_a, c.guard_b]
    m = Message(conversation_id=cid, sender_id=user.id, **data.model_dump())
    db.add(m)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Duplicate message; retrieve history") from None
    return message_dict(m), [c.guard_a, c.guard_b]
