from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session


from app.core.database import get_db
from app.guards.auth import admin
from app.models.entities import User


router = APIRouter(
    prefix="/admin",
    tags=["Admin"],
)


class UserRoleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


    role: str = Field(
        min_length=4,
        max_length=10,
    )


def user_dict(user: User) -> dict:
    return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "zone": user.zone,
        "role": user.role,
        "active": user.active,
        "is_suspended": user.is_suspended,
        "profile_photo_url": user.profile_photo_url,
    }


@router.get("/users")
def list_users(
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    statement = (
        select(User)
        .order_by(
            User.full_name.asc().nulls_last(),
            User.email.asc(),
        )
        .limit(200)
    )


    users = db.scalars(statement)


    return [user_dict(item) for item in users]


@router.patch("/users/{user_id}/suspend")
def suspend_user(
    user_id: str,
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)


    if target is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )


    if target.id == user.id:
        raise HTTPException(
            status_code=400,
            detail="You cannot suspend your own account",
        )


    target.is_suspended = True
    db.commit()


    return user_dict(target)


@router.patch("/users/{user_id}/activate")
def activate_user(
    user_id: str,
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)


    if target is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )


    target.is_suspended = False
    db.commit()


    return user_dict(target)


@router.patch("/users/{user_id}/role")
def change_user_role(
    user_id: str,
    data: UserRoleInput,
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    role = data.role.strip().upper()


    if role not in {"GUARD", "ADMIN"}:
        raise HTTPException(
            status_code=422,
            detail="Role must be GUARD or ADMIN",
        )


    target = db.get(User, user_id)


    if target is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )


    if target.id == user.id and role != "ADMIN":
        raise HTTPException(
            status_code=400,
            detail="You cannot remove your own administrator access",
        )


    target.role = role
    db.commit()


    return user_dict(target)


@router.delete("/users/{user_id}")
def delete_user(
    user_id: str,
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)


    if target is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )


    if target.id == user.id:
        raise HTTPException(
            status_code=400,
            detail="You cannot delete your own account",
        )


    db.delete(target)
    db.commit()


    return {
        "detail": "User deleted",
    }