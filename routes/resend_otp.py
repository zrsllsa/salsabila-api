from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr

from routes.register import (
    OTP_EXPIRE_MINUTES,
    generate_otp,
    hash_otp,
    send_verification_email,
)
from supabase_client import get_supabase_admin

router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"]
)

# Jeda minimum antar pengiriman OTP untuk email yang sama
RESEND_COOLDOWN_SECONDS = 60


class ResendOtpRequest(BaseModel):
    email: EmailStr


@router.post("/resend-otp")
def resend_otp(data: ResendOtpRequest):
    """
    Kirim ulang OTP untuk pendaftaran yang masih pending.
    Dipakai oleh alur register (verify-email) maupun login Google (google/verify-otp),
    karena keduanya menyimpan OTP di tabel pending_registrations.
    """

    email = str(data.email).lower().strip()
    admin = get_supabase_admin()

    rows = (
        admin.table("pending_registrations")
        .select("*").eq("email", email).limit(1).execute().data
    )

    if not rows:
        raise HTTPException(
            status_code=400,
            detail="Data registrasi tidak ditemukan. Silakan daftar atau login dengan Google lagi.",
        )

    pending = rows[0]
    now = datetime.now(timezone.utc)

    # Batasi kirim ulang supaya email tidak bisa dipakai untuk spam
    last_raw = pending.get("last_sent_at")
    if last_raw:
        last = datetime.fromisoformat(str(last_raw).replace("Z", "+00:00"))
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        wait = RESEND_COOLDOWN_SECONDS - (now - last).total_seconds()
        if wait > 0:
            raise HTTPException(
                status_code=429,
                detail=f"Tunggu {int(wait) + 1} detik sebelum meminta kode lagi.",
            )

    otp = generate_otp()

    admin.table("pending_registrations").update({
        "otp_hash": hash_otp(otp),
        "attempts": 0,
        "expires_at": (now + timedelta(minutes=OTP_EXPIRE_MINUTES)).isoformat(),
        "last_sent_at": now.isoformat(),
    }).eq("email", email).execute()

    try:
        send_verification_email(email=email, otp=otp)
    except Exception as e:
        print("ERROR RESEND OTP SMTP:", repr(e))
        raise HTTPException(status_code=400, detail="Email OTP tidak dapat dikirim.")

    return {"success": True, "message": "Kode baru sudah dikirim ke emailmu."}
