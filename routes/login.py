from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr

from supabase_client import get_supabase_admin, get_supabase_anon

router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"]
)


def find_user(email: str):
    """Cari user Supabase berdasarkan email. shortcut: scan list_users, ganti kalau user > ribuan."""

    admin = get_supabase_admin()
    page = 1

    while True:
        users = admin.auth.admin.list_users(page=page, per_page=200)

        for u in users:
            if (u.email or "").lower() == email:
                return u

        if len(users) < 200:
            return None

        page += 1


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

        # Bedakan penyebab supaya user tahu harus berbuat apa
        user = find_user(str(data.email).lower().strip())

        if user is None:
            raise HTTPException(
                status_code=404,
                detail="Akun tidak terdaftar. Silakan daftar terlebih dahulu."
            )

        if "email" not in (user.app_metadata or {}).get("providers", []):
            raise HTTPException(
                status_code=400,
                detail="Akun ini terdaftar lewat Google. Silakan login dengan Google."
            )

        raise HTTPException(
            status_code=401,
            detail="Email atau password salah."
        )