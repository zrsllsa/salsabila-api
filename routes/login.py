from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr

from supabase_client import get_supabase_anon

router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"]
)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@router.post("/login")
def login(data: LoginRequest):

    try:

        email = str(data.email).lower().strip()

        print("====================================")
        print("LOGIN")
        print("====================================")

        # Client baru di setiap login, supaya session satu user
        # tidak tersimpan di client yang dipakai bersama.
        supabase = get_supabase_anon()

        auth_result = supabase.auth.sign_in_with_password({
            "email": email,
            "password": data.password
        })

        if not auth_result.user or not auth_result.session:
            raise HTTPException(
                status_code=401,
                detail="Email atau password salah."
            )

        user = auth_result.user
        session = auth_result.session
        metadata = user.user_metadata or {}


        return {
            "message": "Login berhasil!",
            "user_id": user.id,
            "name": (
                metadata.get("full_name")
                or metadata.get("name")
                or ""
            ),
            "email": user.email,
            "token_type": "bearer",
            "access_token": session.access_token,
            "refresh_token": session.refresh_token
        }

    except HTTPException:
        raise

    except Exception as e:
        print("ERROR LOGIN:", repr(e))

        # Akun sudah dibuat tapi OTP belum diverifikasi
        if "not confirmed" in str(e).lower():
            raise HTTPException(
                status_code=403,
                detail="Email belum diverifikasi. Silakan verifikasi OTP terlebih dahulu."
            )

        raise HTTPException(
            status_code=401,
            detail="Login gagal. Periksa email dan password."
        )