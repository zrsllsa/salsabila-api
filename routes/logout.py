from fastapi import APIRouter, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from supabase_client import get_supabase_admin


router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"]
)

security = HTTPBearer()


@router.post("/logout")
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):

    token = credentials.credentials

    supabase_admin = get_supabase_admin()

    user_id = None

    # -----------------------------------------------------
    # AMBIL USER DARI TOKEN (OPSIONAL, HANYA UNTUK RESPONSE)
    # -----------------------------------------------------

    try:

        result = supabase_admin.auth.get_user(token)

        if result and result.user:

            user_id = result.user.id

    except Exception as e:

        # Token sudah kedaluwarsa / tidak valid:
        # tetap dianggap logout berhasil.
        print("LOGOUT - TOKEN TIDAK VALID:", repr(e))

    # -----------------------------------------------------
    # CABUT SESSION DI SUPABASE (HANYA PERANGKAT INI)
    # -----------------------------------------------------

    if user_id:

        try:

            supabase_admin.auth.admin.sign_out(
                token,
                "local"
            )

        except Exception as e:

            print("LOGOUT - SIGN OUT ERROR:", repr(e))

    # -----------------------------------------------------
    # RESPONSE
    # -----------------------------------------------------

    response = {
        "message": "Logout berhasil!"
    }

    if user_id:

        response["user_id"] = user_id

    return response