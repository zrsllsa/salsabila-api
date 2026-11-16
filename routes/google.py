import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from dotenv import load_dotenv
from fastapi import APIRouter, Cookie, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, EmailStr

from routes.register import (
    OTP_EXPIRE_MINUTES,
    generate_otp,
    hash_otp,
    send_verification_email,
)
from supabase_client import SUPABASE_URL, get_supabase_admin, get_supabase_anon

load_dotenv()

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")

# Cookie untuk menyimpan PKCE code_verifier selama proses login Google.
# Lokal (localhost)      : biarkan default (lax, tidak secure).
# Production beda domain : COOKIE_SAMESITE=none dan COOKIE_SECURE=true (wajib HTTPS).
COOKIE_NAME = "oauth_code_verifier"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").lower()


def make_pkce_pair():
    """
    Buat pasangan PKCE (code_verifier, code_challenge).
    Dibuat per-login supaya beberapa user bisa login Google bersamaan
    tanpa saling menimpa verifier.
    """

    verifier = secrets.token_urlsafe(64)

    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("utf-8")).digest()
    ).rstrip(b"=").decode("utf-8")

    return verifier, challenge


MAX_OTP_ATTEMPTS = 5


def needs_otp(user) -> bool:
    """
    Butuh OTP kalau belum pernah diverifikasi dan belum punya login email+password
    (akun email+password sudah diverifikasi OTP saat register).
    """

    if (user.app_metadata or {}).get("otp_verified"):
        return False

    return not any(i.provider == "email" for i in (user.identities or []))


def send_google_otp(email: str, user_id: str, name: str):
    admin = get_supabase_admin()
    otp = generate_otp()
    now = datetime.now(timezone.utc)

    admin.table("pending_registrations").delete().eq("email", email).execute()
    admin.table("pending_registrations").insert({
        "name": name,
        "email": email,
        "user_id": user_id,
        "otp_hash": hash_otp(otp),
        "attempts": 0,
        "expires_at": (now + timedelta(minutes=OTP_EXPIRE_MINUTES)).isoformat(),
        "last_sent_at": now.isoformat(),
    }).execute()

    send_verification_email(email=email, otp=otp)


class GoogleOtpRequest(BaseModel):
    email: EmailStr
    otp: str


@router.post("/google/verify-otp")
def google_verify_otp(data: GoogleOtpRequest):

    email = str(data.email).lower().strip()
    otp = data.otp.strip()

    if not (otp.isdigit() and len(otp) == 6):
        raise HTTPException(status_code=400, detail="OTP harus 6 digit angka.")

    admin = get_supabase_admin()

    rows = (
        admin.table("pending_registrations")
        .select("*").eq("email", email).limit(1).execute().data
    )

    if not rows:
        raise HTTPException(
            status_code=400,
            detail="OTP tidak ditemukan. Silakan login dengan Google lagi.",
        )

    pending = rows[0]
    expires_at = datetime.fromisoformat(str(pending["expires_at"]).replace("Z", "+00:00"))
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at or (pending.get("attempts") or 0) >= MAX_OTP_ATTEMPTS:
        admin.table("pending_registrations").delete().eq("email", email).execute()
        raise HTTPException(
            status_code=400,
            detail="OTP kedaluwarsa atau terlalu banyak percobaan. Silakan login dengan Google lagi.",
        )

    if not secrets.compare_digest(str(pending["otp_hash"]).strip(), hash_otp(otp)):
        admin.table("pending_registrations").update(
            {"attempts": (pending.get("attempts") or 0) + 1}
        ).eq("email", email).execute()
        raise HTTPException(status_code=400, detail="OTP salah.")

    try:
        admin.auth.admin.update_user_by_id(
            pending["user_id"], {"app_metadata": {"otp_verified": True}}
        )
        admin.table("pending_registrations").delete().eq("email", email).execute()

        # Buat session lewat magic link, karena token Google tidak disimpan.
        link = admin.auth.admin.generate_link({"type": "magiclink", "email": email})
        auth_result = get_supabase_anon().auth.verify_otp({
            "token_hash": link.properties.hashed_token,
            "type": "magiclink",
        })

        user, session = auth_result.user, auth_result.session
        metadata = user.user_metadata or {}

        return {
            "message": "Login berhasil!",
            "user_id": user.id,
            "name": metadata.get("full_name") or metadata.get("name") or "",
            "email": user.email,
            "picture": metadata.get("avatar_url") or metadata.get("picture") or "",
            "token_type": "bearer",
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
        }

    except Exception as e:
        print("ERROR GOOGLE VERIFY OTP:", repr(e))
        raise HTTPException(status_code=400, detail="Verifikasi gagal. Silakan coba lagi.")


@router.get("/google")
def google_login(mode: str = "login"):

    try:

        if not SUPABASE_URL:
            raise HTTPException(
                status_code=500,
                detail="SUPABASE_URL belum diisi di .env",
            )

        verifier, challenge = make_pkce_pair()

        query = urlencode({
            "provider": "google",
            "redirect_to": f"{BACKEND_URL}/api/auth/google/callback",
            "code_challenge": challenge,
            "code_challenge_method": "s256",
        })

        url = f"{SUPABASE_URL.rstrip('/')}/auth/v1/authorize?{query}"

        response = JSONResponse({"url": url})

        response.set_cookie(
            key=COOKIE_NAME,
            value=verifier,
            max_age=600,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite=COOKIE_SAMESITE,
        )

        # Halaman register: akun yang sudah terdaftar ditolak (tidak langsung login).
        response.set_cookie(
            key="oauth_mode",
            value="register" if mode == "register" else "login",
            max_age=600,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite=COOKIE_SAMESITE,
        )

        return response

    except HTTPException:
        raise
    except Exception as e:
        print("ERROR GOOGLE LOGIN:", repr(e))
        raise HTTPException(status_code=400, detail="Login Google gagal. Silakan coba lagi.")


@router.get("/google/callback")
def google_callback(
    code: str | None = None,
    error: str | None = None,
    oauth_code_verifier: str | None = Cookie(default=None),
    oauth_mode: str | None = Cookie(default=None),
):
    print("GOOGLE CALLBACK DIPANGGIL, code ada:", bool(code), "error:", error)

    error_redirect = RedirectResponse(
        url=f"{FRONTEND_URL}/#error=Login%20Google%20gagal",
        status_code=302,
    )

    if error or not code or not oauth_code_verifier:
        print("GOOGLE CALLBACK DITOLAK. error:", error, "| ada code:", bool(code), "| ada cookie verifier:", bool(oauth_code_verifier))
        error_redirect.delete_cookie(COOKIE_NAME)
        return error_redirect

    try:
        result = get_supabase_anon().auth.exchange_code_for_session({
            "auth_code": code,
            "code_verifier": oauth_code_verifier,
        })

        if not result.user or not result.session:
            raise HTTPException(status_code=401, detail="Login Google gagal")

        user = result.user
        session = result.session
        metadata = user.user_metadata or {}

        # Akun Google baru (belum pernah verifikasi OTP) tidak langsung
        # login: kirim OTP ke email, token baru diberikan setelah OTP benar.
        if needs_otp(user):
            email = (user.email or "").lower().strip()
            send_google_otp(
                email,
                user.id,
                metadata.get("full_name") or metadata.get("name") or email,
            )
            response = RedirectResponse(
                url=f"{FRONTEND_URL}/#{urlencode({'otp_required': 'true', 'email': email})}",
                status_code=302,
            )
            response.delete_cookie(COOKIE_NAME)
            return response

        if oauth_mode == "register":
            response = RedirectResponse(
                url=f"{FRONTEND_URL}/#{urlencode({'error': 'Akun anda sudah terdaftar. Silakan login.'})}",
                status_code=302,
            )
            response.delete_cookie(COOKIE_NAME)
            response.delete_cookie("oauth_mode")
            return response

        params = urlencode({
            "access_token": session.access_token,
            "refresh_token": session.refresh_token or "",
            "email": user.email or "",
            "name": metadata.get("full_name") or metadata.get("name") or "",
            "picture": metadata.get("avatar_url") or metadata.get("picture") or "",
        })

        response = RedirectResponse(url=f"{FRONTEND_URL}/#{params}", status_code=302)
        response.delete_cookie(COOKIE_NAME)
        return response

    except Exception as e:
        print("ERROR GOOGLE CALLBACK:", repr(e))
        error_redirect.delete_cookie(COOKIE_NAME)
        return error_redirect