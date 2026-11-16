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



MAXIMUM_PHOTO_BYTES = 2 * 1024 * 1024


UPLOAD_DIRECTORY = "uploads/profile_photos"



os.makedirs(
    UPLOAD_DIRECTORY,
    exist_ok=True,
)



def detect_image_type(contents: bytes) -> tuple[str, str] | None:
    if contents.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", ".jpg"


    if contents.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", ".png"


    if (
        len(contents) >= 12
        and contents[:4] == b"RIFF"
        and contents[8:12] == b"WEBP"
    ):
        return "image/webp", ".webp"


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


    if safe_filename.lower().endswith(".png"):
        media_type = "image/png"
    elif safe_filename.lower().endswith(".webp"):
        media_type = "image/webp"
    else:
        media_type = "image/jpeg"


    return FileResponse(
        file_path,
        media_type=media_type,
    )