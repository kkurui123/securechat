from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.entities import User, Incident, now
from app.schemas.auth import IncidentInput, Decision, StatusInput
from app.guards.auth import guard, admin
from app.services.chat import member
from app.routes.auth import public_user

router = APIRouter(tags=["Incidents and Admin"])

def output(i):
    return {"id": i.id, "reported_by": i.reported_by, "report_type": i.report_type,
            "conversation_id": i.conversation_id, "reported_guard_id": i.reported_guard_id,
            "reason": i.reason, "status": i.status, "reviewed_by": i.reviewed_by,
            "created_at": i.created_at, "reviewed_at": i.reviewed_at}

@router.post("/incidents", status_code=201)
def report(data: IncidentInput, user: User = Depends(guard), db: Session = Depends(get_db)):
    if data.report_type == "CONVERSATION":
        if not data.conversation_id or data.reported_guard_id:
            raise HTTPException(422, "Select only a conversation")
        member(db, data.conversation_id, user)
    else:
        target = db.get(User, data.reported_guard_id) if data.reported_guard_id else None
        if data.conversation_id or not target or target.role != "GUARD" or target.id == user.id:
            raise HTTPException(422, "Select another Guard only")
    i = Incident(reported_by=user.id, **data.model_dump())
    db.add(i)
    db.commit()
    return output(i)

@router.get("/incidents/mine")
def mine(user: User = Depends(guard), db: Session = Depends(get_db)):
    return [output(i) for i in db.scalars(select(Incident).where(Incident.reported_by == user.id).order_by(Incident.created_at.desc()).limit(200))]

@router.get("/admin/incidents")
def all_incidents(user: User = Depends(admin), db: Session = Depends(get_db)):
    return [output(i) for i in db.scalars(select(Incident).order_by(Incident.created_at.desc()).limit(200))]

@router.post("/admin/incidents/{iid}/decision")
def decide(iid: str, data: Decision, user: User = Depends(admin), db: Session = Depends(get_db)):
    i = db.scalar(select(Incident).where(Incident.id == iid).with_for_update())
    if not i:
        raise HTTPException(404, "Incident not found")
    if i.status != "PENDING":
        raise HTTPException(409, "Incident already reviewed")
    i.status, i.reviewed_by, i.reviewed_at = data.decision, user.id, now()
    db.commit()
    return output(i)

@router.get("/admin/guards")
def list_guards(user: User = Depends(admin), db: Session = Depends(get_db)):
    return [public_user(u) for u in db.scalars(select(User).where(User.role == "GUARD").limit(200))]

@router.patch("/admin/guards/{uid}/status")
def status(uid: str, data: StatusInput, user: User = Depends(admin), db: Session = Depends(get_db)):
    u = db.get(User, uid)
    if not u or u.role != "GUARD":
        raise HTTPException(404, "Guard not found")
    u.active = data.active
    db.commit()
    return public_user(u)

@router.post("/admin/incidents/{iid}/reconstruct")
def reconstruct(iid: str, user: User = Depends(admin), db: Session = Depends(get_db)):
    i = db.get(Incident, iid)
    if not i:
        raise HTTPException(404, "Incident not found")
    if i.status != "APPROVED":
        raise HTTPException(409, "Incident must be approved")
    raise HTTPException(501, "Recovery cryptography is not configured. Approval cannot decrypt end-to-end encrypted content.")
