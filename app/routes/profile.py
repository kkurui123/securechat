import os
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.guards.auth import guard
from app.models.entities import User


router = APIRouter(
    tags=["Profile"],
)


ALLOWED_PHOTO_TYPES = {
    "image/jpeg",
    "image/png",
    "image/webp",
}

MAXIMUM_PHOTO_BYTES = 2 * 1024 * 1024

UPLOAD_DIRECTORY = "uploads/profile_photos"


os.makedirs(
    UPLOAD_DIRECTORY,
    exist_ok=True,
)


@router.post("/me/profile-photo")
async def upload_profile_photo(
    photo: UploadFile = File(...),
    user: User = Depends(guard),
    db: Session = Depends(get_db),
):
    if photo.content_type not in ALLOWED_PHOTO_TYPES:
        raise HTTPException(
            status_code=415,
            detail="Use a JPG, PNG, or WebP photo.",
        )

    contents = await photo.read()

    if len(contents) == 0:
        raise HTTPException(
            status_code=422,
            detail="Choose a photo.",
        )

    if len(contents) > MAXIMUM_PHOTO_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Photo must be 2 MB or smaller.",
        )

    extension = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
    }[photo.content_type]

    filename = f"{uuid.uuid4().hex}{extension}"
    file_path = os.path.join(
        UPLOAD_DIRECTORY,
        filename,
    )

    with open(
        file_path,
        "wb",
    ) as output:
        output.write(contents)

    account = db.scalar(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
    )

    if account is None or not account.active:
        raise HTTPException(
            status_code=403,
            detail="Active account required.",
        )

    previous_url = account.profile_photo_url

    if previous_url and previous_url.startswith(
        "/api/v1/profile-photos/",
    ):
        previous_filename = previous_url.rsplit(
            "/",
            1,
        )[-1]

        previous_path = os.path.join(
            UPLOAD_DIRECTORY,
            previous_filename,
        )

        if os.path.isfile(previous_path):
            try:
                os.remove(previous_path)
            except OSError:
                pass

    photo_url = f"/api/v1/profile-photos/{filename}"
    account.profile_photo_url = photo_url

    db.commit()

    return {
        "profile_photo_url": photo_url,
    }


@router.get("/profile-photos/{filename}")
def get_profile_photo(
    filename: str,
):
    safe_filename = os.path.basename(filename)

    file_path = os.path.join(
        UPLOAD_DIRECTORY,
        safe_filename,
    )

    if not os.path.isfile(file_path):
        raise HTTPException(
            status_code=404,
            detail="Profile photo not found.",
        )

    return FileResponse(
        file_path,
        media_type="image/jpeg",
    )
