from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.entities import User, Conversation, Message
from app.schemas.auth import ConversationInput, MessageInput
from app.guards.auth import guard
from app.services.chat import member, message_dict, save_message
from app.routes.realtime import publish
from starlette.concurrency import run_in_threadpool

router = APIRouter(tags=["Chat"])

@router.get("/guards")
def guards(
    user: User = Depends(guard),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(User)
        .where(
            User.role == "GUARD",
            User.active == True,
            User.id != user.id,
        )
        .limit(200)
    )

    return [
        {
            "id": item.id,
            "full_name": item.full_name,
            "email": item.email,
            "zone": item.zone,
        }
        for item in rows
    ]
@router.post("/conversations")
def create(data: ConversationInput, user: User = Depends(guard), db: Session = Depends(get_db)):
    other = db.get(User, data.guard_id)
    if not other or other.role != "GUARD" or not other.active or other.id == user.id:
        raise HTTPException(400, "Choose another active Guard")
    a, b = sorted([user.id, other.id])
    c = db.scalar(select(Conversation).where(Conversation.guard_a == a, Conversation.guard_b == b))
    if not c:
        c = Conversation(guard_a=a, guard_b=b)
        db.add(c)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            c = db.scalar(select(Conversation).where(Conversation.guard_a == a, Conversation.guard_b == b))
    return {"id": c.id, "guard_a": c.guard_a, "guard_b": c.guard_b}

@router.get("/conversations")
def conversations(user: User = Depends(guard), db: Session = Depends(get_db)):
    rows = db.scalars(select(Conversation).where(or_(Conversation.guard_a == user.id, Conversation.guard_b == user.id)).order_by(Conversation.created_at.desc()).limit(200))
    return [{"id": c.id, "guard_a": c.guard_a, "guard_b": c.guard_b} for c in rows]

@router.get("/conversations/{cid}/messages")
def history(cid: str, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), user: User = Depends(guard), db: Session = Depends(get_db)):
    member(db, cid, user)
    rows = db.scalars(select(Message).where(Message.conversation_id == cid).order_by(Message.created_at.desc(), Message.id.desc()).offset(offset).limit(limit))
    return [message_dict(m) for m in rows]

@router.post("/conversations/{cid}/messages", status_code=201)
async def send(cid: str, data: MessageInput, user: User = Depends(guard)):
    from app.core.database import SessionLocal
    def work():
        with SessionLocal() as db:
            from app.models.entities import User
            fresh = db.get(User, user.id)
            if not fresh or not fresh.active:
                raise HTTPException(401, "Inactive account")
            return save_message(db, cid, fresh, data)
    message, recipients = await run_in_threadpool(work)
    await publish(recipients, {"type": "message", "message": message})
    return message
