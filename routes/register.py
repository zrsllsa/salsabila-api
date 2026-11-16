import os

import secrets

import hashlib

import smtplib

import logging


from datetime import datetime, timedelta, timezone

from email.message import EmailMessage


from fastapi import APIRouter, HTTPException

from pydantic import BaseModel, EmailStr

from routes.login import find_user

from supabase_client import get_supabase_admin


logger = logging.getLogger("register")


router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"]
)


APP_NAME = "About Salsabila"

OTP_EXPIRE_MINUTES = 30


# =========================================================
# REQUEST MODEL
# =========================================================

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


# =========================================================
# GENERATE & HASH OTP
# =========================================================
# Dipakai juga oleh verify_email.py:
#   from routes.register import hash_otp

def generate_otp() -> str:
    """
    Buat OTP 6 digit.
    """

    return str(
        secrets.randbelow(1_000_000)
    ).zfill(6)


def hash_otp(otp: str) -> str:
    """
    Hash OTP dengan SHA-256.
    OTP asli tidak pernah disimpan di database.
    """

    return hashlib.sha256(
        otp.encode("utf-8")
    ).hexdigest()


# =========================================================
# SEND OTP EMAIL
# =========================================================

def send_verification_email(
    email: str,
    otp: str
):

    smtp_email = os.getenv("SMTP_EMAIL")

    smtp_password = os.getenv("SMTP_PASSWORD")


    # -----------------------------------------------------
    # CHECK ENV
    # -----------------------------------------------------

    if not smtp_email:

        raise Exception(
            "SMTP_EMAIL tidak ditemukan di .env"
        )

    if not smtp_password:

        raise Exception(
            "SMTP_PASSWORD tidak ditemukan di .env"
        )


    # -----------------------------------------------------
    # EMAIL
    # -----------------------------------------------------

    message = EmailMessage()

    message["From"] = smtp_email

    message["To"] = email

    message["Subject"] = "Your verification code for About Salsabila"

    message.set_content(
        f"""Hello!

Thank you for joining About Salsabila.

I'm happy to welcome you! To complete your registration, please use the verification code below:

{otp}

This code is valid for {OTP_EXPIRE_MINUTES} minutes. Please make sure to enter it before it expires.

If you didn't request this registration, you can safely ignore this email. For your security, please do not share this verification code with anyone.

Warm regards,
Salsabila
"""
    )


    # -----------------------------------------------------
    # CONNECT GMAIL SMTP
    # -----------------------------------------------------

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        timeout=30
    ) as server:

        server.login(
            smtp_email,
            smtp_password
        )

        server.send_message(message)


# =========================================================
# HAPUS PENDING (+ AKUN AUTH YANG BELUM DIVERIFIKASI)
# =========================================================

def cleanup_pending(admin, email: str):

    result = (

        admin

        .table("pending_registrations")

        .select("user_id")

        .eq("email", email)

        .limit(1)

        .execute()

    )


    for row in result.data or []:

        try:

            admin.auth.admin.delete_user(
                row["user_id"]
            )

        except Exception as e:

            print(
                "❌ ERROR DELETE AUTH USER:",
                repr(e)
            )


    admin.table(
        "pending_registrations"
    ).delete().eq(
        "email",
        email
    ).execute()


# =========================================================
# REGISTER
# =========================================================
# Alur:
#   1. Buat akun di Supabase Auth (email_confirm = False)
#      -> password di-hash oleh Supabase, tidak disimpan manual.
#   2. Simpan hash OTP + user_id ke pending_registrations.
#   3. Kirim OTP ke email.
#   4. Akun dikonfirmasi di verify_email.py setelah OTP benar.

@router.post("/register")

def register(data: RegisterRequest):

    print("====================================")

    print("🔥 REGISTER BARU")


    print("====================================")


    try:

        admin = get_supabase_admin()


        # =================================================
        # 1. NORMALISASI DATA
        # =================================================

        name = data.name.strip()

        email = str(data.email).lower().strip()

        password = data.password


        # -------------------------------------------------
        # Validasi nama
        # -------------------------------------------------

        if not name:

            raise HTTPException(
                status_code=400,
                detail="Nama tidak boleh kosong."
            )


        # -------------------------------------------------
        # Validasi password
        # -------------------------------------------------

        if len(password) < 8:

            raise HTTPException(
                status_code=400,
                detail="Password minimal 8 karakter."
            )


        # =================================================
        # 2. HAPUS PENDING LAMA (JIKA ADA)
        # =================================================

        # Akun yang sudah terverifikasi tidak boleh dihapus/ditimpa oleh register
        existing = find_user(email)

        if existing and (
            existing.email_confirmed_at
            or (existing.app_metadata or {}).get("otp_verified")
        ):
            raise HTTPException(
                status_code=400,
                detail="Akun anda sudah terdaftar. Silakan login."
            )

        cleanup_pending(admin, email)


        # =================================================
        # 3. BUAT AKUN DI SUPABASE AUTH (BELUM AKTIF)
        # =================================================

        try:

            created = admin.auth.admin.create_user({

                "email": email,

                "password": password,

                "email_confirm": False,

                "user_metadata": {

                    "full_name": name

                }

            })

        except Exception as e:

            error_text = str(e).lower()

            print(
                "❌ ERROR CREATE USER:",
                repr(e)
            )

            if (
                "already" in error_text
                or "registered" in error_text
                or "exists" in error_text
            ):

                raise HTTPException(
                    status_code=400,
                    detail="Akun anda sudah terdaftar. Silakan login."
                )

            raise HTTPException(
                status_code=500,
                detail="Gagal membuat akun."
            )


        if not created.user:

            raise HTTPException(
                status_code=400,
                detail="Gagal membuat akun di Supabase Auth."
            )


        user_id = created.user.id


        print(
            "✅ Akun dibuat (belum diverifikasi):",
            user_id
        )


        # =================================================
        # 4. BUAT OTP 6 DIGIT
        # =================================================

        otp = generate_otp()



        # =================================================
        # 5. HASH OTP
        # =================================================

        otp_hash = hash_otp(otp)


        # =================================================
        # 6. WAKTU EXPIRED
        # =================================================

        now = datetime.now(timezone.utc)

        expires_at = now + timedelta(
            minutes=OTP_EXPIRE_MINUTES
        )


        # =================================================
        # 7. SIMPAN KE PENDING
        # =================================================

        pending_data = {

            "name": name,

            "email": email,

            "user_id": user_id,

            "otp_hash": otp_hash,

            "attempts": 0,

            "expires_at": expires_at.isoformat(),

            "last_sent_at": now.isoformat()

        }


        try:

            admin.table(
                "pending_registrations"
            ).insert(
                pending_data
            ).execute()

        except Exception as e:

            print(
                "❌ ERROR SIMPAN PENDING:",
                repr(e)
            )

            # Batalkan akun Auth yang sudah terlanjur dibuat

            try:

                admin.auth.admin.delete_user(user_id)

            except Exception as delete_error:

                print(
                    "❌ ERROR DELETE AUTH USER:",
                    repr(delete_error)
                )

            raise HTTPException(
                status_code=500,
                detail="Gagal menyimpan data pendaftaran."
            )


        print(
            "✅ Data pending berhasil disimpan"
        )


        # =================================================
        # 8. KIRIM OTP KE GMAIL
        # =================================================

        try:

            send_verification_email(
                email=email,
                otp=otp
            )


            print(
                "✅ OTP berhasil dikirim ke:",
                email
            )


        except Exception as e:

            print(
                "❌ ERROR SMTP:",
                repr(e)
            )


            # ---------------------------------------------
            # HAPUS PENDING + AKUN JIKA EMAIL GAGAL
            # ---------------------------------------------

            try:

                cleanup_pending(admin, email)


                print(
                    "✅ Pending registration dihapus"
                )


            except Exception as delete_error:

                print(
                    "❌ ERROR DELETE PENDING:",
                    repr(delete_error)
                )


            raise HTTPException(
                status_code=400,
                detail=(
                    "Registrasi gagal. "
                    "Email OTP tidak dapat dikirim."
                )
            )


        # =================================================
        # 9. RESPONSE
        # =================================================

        return {

            "success": True,

            "message": (
                "OTP berhasil dikirim. "
                "Silakan cek email kamu."
            ),

            "email": email

        }


    # =====================================================
    # HTTP ERROR
    # =====================================================

    except HTTPException:

        raise


    # =====================================================
    # ERROR LAIN
    # =====================================================

    except Exception as e:

        print(
            "❌ ERROR REGISTER:",
            repr(e)
        )


        raise HTTPException(
            status_code=500,
            detail="Register gagal. Silakan coba lagi."
        )
