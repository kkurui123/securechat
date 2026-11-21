import os
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

import cloudinary
import cloudinary.uploader

from app.core.database import get_db
from app.guards.auth import guard
from app.models.entities import User


router = APIRouter(
    tags=["Profile"],
)


MAXIMUM_PHOTO_BYTES = 2 * 1024 * 1024


cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True,
)


def detect_image_type(contents: bytes) -> tuple[str, str] | None:
    if contents.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", "jpg"

    if contents.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", "png"

    if (
        len(contents) >= 12
        and contents[:4] == b"RIFF"
        and contents[8:12] == b"WEBP"
    ):
        return "image/webp", "webp"

    return None


@router.post("/me/profile-photo")
async def upload_profile_photo(
    photo: UploadFile = File(...),
    user: User = Depends(guard),
    db: Session = Depends(get_db),
):
    contents = await photo.read()

    print(
        "PROFILE PHOTO UPLOAD: "
        f"declared_content_type={photo.content_type}, "
        f"size={len(contents)}, "
        f"first_bytes={contents[:12].hex()}"
    )

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

    detected = detect_image_type(contents)

    if detected is None:
        raise HTTPException(
            status_code=415,
            detail=(
                "Unsupported photo format. "
                "Use a JPG, PNG, or WebP photo."
            ),
        )

    content_type, extension = detected

    public_id = (
        "securechat/profile_photos/"
        f"{uuid.uuid4().hex}"
    )

    try:
        upload_result = cloudinary.uploader.upload(
            contents,
            public_id=public_id,
            overwrite=True,
            resource_type="image",
            format=extension,
        )
    except Exception as error:
        print(f"CLOUDINARY UPLOAD ERROR: {error}")

        raise HTTPException(
            status_code=502,
            detail="Could not save your profile photo. Please try again.",
        ) from None

    secure_url = upload_result.get("secure_url")

    if not secure_url:
        raise HTTPException(
            status_code=502,
            detail="Could not save your profile photo. Please try again.",
        )

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

    account.profile_photo_url = secure_url

    db.commit()

    return {
        "profile_photo_url": secure_url,
    }
