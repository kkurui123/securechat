from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session


from app.core.database import get_db
from app.models.entities import User, Incident, RecoveryRequest, now
from app.schemas.auth import IncidentInput, Decision, StatusInput
from app.guards.auth import guard, admin
from app.services.chat import member
from app.routes.auth import public_user


router = APIRouter(tags=["Incidents and Admin"])


class IncidentReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


    status: str = Field(
        min_length=8,
        max_length=8,
    )


class RecoveryRequestInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


    reason: str = Field(
        min_length=10,
        max_length=2000,
    )


def output(incident: Incident) -> dict:
    return {
        "id": incident.id,
        "reported_by": incident.reported_by,
        "report_type": incident.report_type,
        "conversation_id": incident.conversation_id,
        "reported_guard_id": incident.reported_guard_id,
        "reason": incident.reason,
        "status": incident.status,
        "reviewed_by": incident.reviewed_by,
        "created_at": incident.created_at,
        "reviewed_at": incident.reviewed_at,
    }


def recovery_output(request: RecoveryRequest) -> dict:
    return {
        "id": request.id,
        "incident_id": request.incident_id,
        "requested_by": request.requested_by,
        "status": request.status,
        "reason": request.reason,
        "created_at": request.created_at,
        "reviewed_at": request.reviewed_at,
    }


@router.post("/incidents", status_code=201)
def report(
    data: IncidentInput,
    user: User = Depends(guard),
    db: Session = Depends(get_db),
):
    if data.report_type == "CONVERSATION":
        if not data.conversation_id or data.reported_guard_id:
            raise HTTPException(
                status_code=422,
                detail="Select only a conversation",
            )


        member(
            db,
            data.conversation_id,
            user,
        )
    else:
        target = (
            db.get(User, data.reported_guard_id)
            if data.reported_guard_id
            else None
        )


        if (
            data.conversation_id
            or not target
            or target.role != "GUARD"
            or target.id == user.id
        ):
            raise HTTPException(
                status_code=422,
                detail="Select another Guard only",
            )


    incident = Incident(
        reported_by=user.id,
        **data.model_dump(),
    )


    db.add(incident)
    db.commit()


    return output(incident)


@router.get("/incidents/mine")
def mine(
    user: User = Depends(guard),
    db: Session = Depends(get_db),
):
    incidents = db.scalars(
        select(Incident)
        .where(Incident.reported_by == user.id)
        .order_by(Incident.created_at.desc())
        .limit(200)
    )


    return [output(incident) for incident in incidents]


@router.get("/admin/incidents")
def all_incidents(
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    incidents = db.scalars(
        select(Incident)
        .order_by(Incident.created_at.desc())
        .limit(200)
    )


    return [output(incident) for incident in incidents]


@router.post("/admin/incidents/{incident_id}/decision")
def decide(
    incident_id: str,
    data: Decision,
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    incident = db.scalar(
        select(Incident)
        .where(Incident.id == incident_id)
        .with_for_update()
    )


    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )


    if incident.status != "PENDING":
        raise HTTPException(
            status_code=409,
            detail="Incident already reviewed",
        )


    incident.status = data.decision
    incident.reviewed_by = user.id
    incident.reviewed_at = now()


    db.commit()


    return output(incident)


@router.patch("/admin/incidents/{incident_id}/review")
def review_incident(
    incident_id: str,
    data: IncidentReviewInput,
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    incident = db.scalar(
        select(Incident)
        .where(Incident.id == incident_id)
        .with_for_update()
    )


    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )


    status = data.status.strip().upper()


    if status not in {"APPROVED", "REJECTED"}:
        raise HTTPException(
            status_code=422,
            detail="Status must be APPROVED or REJECTED",
        )


    if incident.status != "PENDING":
        raise HTTPException(
            status_code=409,
            detail="Incident already reviewed",
        )


    incident.status = status
    incident.reviewed_by = user.id
    incident.reviewed_at = now()


    db.commit()


    return output(incident)


@router.post(
    "/admin/incidents/{incident_id}/recovery-request",
    status_code=201,
)
def request_recovery(
    incident_id: str,
    data: RecoveryRequestInput,
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    incident = db.get(Incident, incident_id)


    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )


    if incident.status != "APPROVED":
        raise HTTPException(
            status_code=409,
            detail="Only approved incidents can be selected for recovery",
        )


    if not incident.conversation_id:
        raise HTTPException(
            status_code=409,
            detail="This incident is not linked to a conversation",
        )


    existing = db.scalar(
        select(RecoveryRequest)
        .where(RecoveryRequest.incident_id == incident_id)
    )


    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="A recovery request already exists for this incident",
        )


    recovery_request = RecoveryRequest(
        incident_id=incident_id,
        requested_by=user.id,
        reason=data.reason.strip(),
    )


    db.add(recovery_request)
    db.commit()


    return recovery_output(recovery_request)


@router.get("/admin/recovery-requests")
def list_recovery_requests(
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    requests = db.scalars(
        select(RecoveryRequest)
        .order_by(RecoveryRequest.created_at.desc())
        .limit(200)
    )


    return [recovery_output(request) for request in requests]


@router.get("/admin/guards")
def list_guards(
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    users = db.scalars(
        select(User)
        .where(User.role == "GUARD")
        .limit(200)
    )


    return [public_user(user) for user in users]


@router.patch("/admin/guards/{user_id}/status")
def status(
    user_id: str,
    data: StatusInput,
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)


    if target is None or target.role != "GUARD":
        raise HTTPException(
            status_code=404,
            detail="Guard not found",
        )


    target.active = data.active
    db.commit()


    return public_user(target)


@router.post("/admin/incidents/{incident_id}/reconstruct")
def reconstruct(
    incident_id: str,
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    incident = db.get(Incident, incident_id)


    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )


    if incident.status != "APPROVED":
        raise HTTPException(
            status_code=409,
            detail="Incident must be approved",
        )


    raise HTTPException(
        status_code=501,
        detail=(
            "Recovery cryptography is not configured. Approval cannot "
            "decrypt end-to-end encrypted content."
        ),
    )