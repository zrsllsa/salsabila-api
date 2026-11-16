import base64
import hashlib
import os
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode

from dotenv import load_dotenv
from fastapi import APIRouter, Cookie, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
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


def is_new_google_user(user) -> bool:
    """
    Akun Google yang belum pernah diaktifkan (bukan akun email+password
    dan belum ditandai terdaftar oleh register Google).
    """

    meta = user.app_metadata or {}

    # otp_verified: akun Google lama dari versi sebelum OTP dihapus
    if meta.get("registered") or meta.get("otp_verified"):
        return False

    return not any(i.provider == "email" for i in (user.identities or []))


@router.get("/google")
def google_login(mode: str = "login", redirect: bool = False):

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

        # redirect=true: browser membuka endpoint ini langsung (navigasi biasa), sehingga
        # cookie dianggap first-party dan tidak diblokir browser walau FE & BE beda domain.
        response = RedirectResponse(url=url, status_code=302) if redirect else JSONResponse({"url": url})

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

        # Akun Google belum terdaftar: dari halaman login ditolak,
        # dari halaman register langsung dibuat (email sudah diverifikasi Google, tanpa OTP).
        if is_new_google_user(user):
            admin = get_supabase_admin()

            if oauth_mode != "register":
                created = user.created_at
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                # hapus akun yang baru saja dibuat otomatis oleh Google; akun lama dibiarkan
                if (datetime.now(timezone.utc) - created).total_seconds() < 120:
                    admin.auth.admin.delete_user(user.id)
                response = RedirectResponse(
                    url=f"{FRONTEND_URL}/#{urlencode({'error': 'Akun tidak terdaftar. Silakan daftar terlebih dahulu.'})}",
                    status_code=302,
                )
                response.delete_cookie(COOKIE_NAME)
                response.delete_cookie("oauth_mode")
                return response

            admin.auth.admin.update_user_by_id(user.id, {"app_metadata": {"registered": True}})
        elif oauth_mode == "register":
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