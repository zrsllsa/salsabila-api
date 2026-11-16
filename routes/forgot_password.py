import os

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter
from pydantic import BaseModel, EmailStr

from supabase_client import SUPABASE_URL, SUPABASE_ANON_KEY

load_dotenv()


router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"]
)


FRONTEND_URL = os.getenv(
    "FRONTEND_URL",
    "http://localhost:5173"
).rstrip("/")

# Halaman di FRONTEND tempat user mengisi password baru.
# Halaman itu membaca access_token dari URL (#access_token=...)
# lalu mengirimnya ke POST /api/auth/reset-password.
RESET_PASSWORD_REDIRECT = os.getenv(
    "RESET_PASSWORD_REDIRECT",
    f"{FRONTEND_URL}/reset-password"
)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


@router.post("/forgot-password")
def forgot_password(
    data: ForgotPasswordRequest
):

    email = str(data.email).lower().strip()

    try:

        # Memanggil endpoint recover Supabase langsung (tanpa PKCE),
        # supaya link di email membawa access_token di URL
        # sehingga cocok dengan reset_password.py.

        response = httpx.post(
            f"{SUPABASE_URL.rstrip('/')}/auth/v1/recover",
            params={
                "redirect_to": RESET_PASSWORD_REDIRECT
            },
            headers={
                "apikey": SUPABASE_ANON_KEY,
                "Content-Type": "application/json"
            },
            json={
                "email": email
            },
            timeout=30
        )

        if response.status_code >= 400:

            print(
                "ERROR FORGOT PASSWORD:",
                response.status_code,
                response.text
            )

    except Exception as e:

        print(
            "ERROR FORGOT PASSWORD:",
            repr(e)
        )

    # Selalu beri jawaban yang sama, supaya orang lain tidak bisa
    # mengecek email mana saja yang terdaftar.

    return {
        "message": (
            "Jika email terdaftar, "
            "link reset password telah dikirim."
        )
    }