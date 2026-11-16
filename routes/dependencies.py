from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from supabase_client import get_supabase_admin


security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Dependency untuk endpoint yang butuh login.

    Pemakaian:
        @router.get("/contoh")
        def contoh(user=Depends(get_current_user)):
            return {"email": user.email}
    """

    token = credentials.credentials

    if not token:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token tidak ditemukan."
        )

    try:

        result = get_supabase_admin().auth.get_user(token)

    except Exception:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token tidak valid atau sudah kedaluwarsa."
        )

    if not result or not result.user:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token tidak valid atau sudah kedaluwarsa."
        )

    return result.user