from fastapi import APIRouter, Depends

from routes.dependencies import get_current_user


router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"]
)


@router.get("/me")
def get_me(
    user=Depends(get_current_user)
):

    metadata = user.user_metadata or {}
    app_metadata = user.app_metadata or {}

    return {
        "user_id": user.id,
        "email": user.email,
        "name": (
            metadata.get("full_name")
            or metadata.get("name")
        ),
        "avatar_url": (
            metadata.get("avatar_url")
            or metadata.get("picture")
        ),
        "provider": app_metadata.get("provider")
    }