from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from supabase_client import get_supabase_admin


router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"]
)


class ResetPasswordRequest(BaseModel):
    access_token: str
    new_password: str


@router.post("/reset-password")
def reset_password(
    data: ResetPasswordRequest
):

    try:

        # =================================================
        # 1. AMBIL ADMIN CLIENT
        # =================================================

        admin = get_supabase_admin()


        # =================================================
        # 2. VALIDASI PASSWORD BARU
        # =================================================

        if len(data.new_password) < 8:

            raise HTTPException(
                status_code=400,
                detail="Password minimal 8 karakter."
            )


        # =================================================
        # 3. VALIDASI ACCESS TOKEN
        # =================================================

        try:

            result = admin.auth.get_user(
                data.access_token
            )

        except Exception:

            raise HTTPException(
                status_code=401,
                detail=(
                    "Token reset password "
                    "tidak valid atau sudah expired."
                )
            )


        if not result or not result.user:

            raise HTTPException(
                status_code=401,
                detail=(
                    "Token reset password "
                    "tidak valid atau sudah expired."
                )
            )


        user_id = result.user.id

        print("====================================")
        print("🔐 RESET PASSWORD")
        print("====================================")


        # =================================================
        # 4. UPDATE PASSWORD USER
        # =================================================

        admin.auth.admin.update_user_by_id(
            user_id,
            {
                "password": data.new_password
            }
        )


        print(
            "✅ PASSWORD BERHASIL DIUBAH"
        )


        # =================================================
        # 5. RESPONSE
        # =================================================

        return {
            "success": True,
            "message": "Password berhasil diubah."
        }


    except HTTPException:

        raise


    except Exception as e:

        print(
            "❌ ERROR RESET PASSWORD:",
            repr(e)
        )

        raise HTTPException(
            status_code=400,
            detail=(
                "Reset password gagal. Silakan coba lagi."
            )
        )