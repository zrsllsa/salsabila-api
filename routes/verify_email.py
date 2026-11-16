import hashlib
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr

from supabase_client import get_supabase_admin


router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"]
)


MAX_OTP_ATTEMPTS = 5


class VerifyEmailRequest(BaseModel):
    email: EmailStr
    otp: str


def delete_pending_and_auth_user(admin, pending: dict):
    """
    Hapus data pending beserta akun Auth yang belum diverifikasi,
    supaya email tersebut bisa dipakai mendaftar ulang.
    """

    user_id = pending.get("user_id")

    if user_id:

        try:

            admin.auth.admin.delete_user(user_id)

        except Exception as e:

            print("ERROR DELETE AUTH USER:", repr(e))

    admin.table(
        "pending_registrations"
    ).delete().eq(
        "email",
        pending["email"]
    ).execute()


@router.post("/verify-email")
def verify_email(data: VerifyEmailRequest):

    try:
        # =========================================================
        # 1. NORMALISASI DATA
        # =========================================================

        email = str(data.email).lower().strip()
        otp = str(data.otp).strip()

        print("======================================")
        print("VERIFY EMAIL")
        print("======================================")


        # =========================================================
        # 2. VALIDASI OTP
        # =========================================================

        if not otp.isdigit():
            raise HTTPException(
                status_code=400,
                detail="OTP harus berupa angka."
            )

        if len(otp) != 6:
            raise HTTPException(
                status_code=400,
                detail="OTP harus terdiri dari 6 digit."
            )


        # =========================================================
        # 3. HASH OTP
        # =========================================================

        otp_hash = hashlib.sha256(
            otp.encode("utf-8")
        ).hexdigest()


        # =========================================================
        # 4. CARI DATA PENDING REGISTRATION
        # =========================================================

        admin = get_supabase_admin()

        result = (
            admin
            .table("pending_registrations")
            .select("*")
            .eq("email", email)
            .limit(1)
            .execute()
        )


        if not result.data:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Data registrasi tidak ditemukan. "
                    "Silakan daftar kembali."
                )
            )


        pending = result.data[0]


        # =========================================================
        # 5. CEK EXPIRED
        # =========================================================

        expires_at_raw = pending.get("expires_at")

        if not expires_at_raw:
            raise HTTPException(
                status_code=400,
                detail="Waktu kedaluwarsa OTP tidak ditemukan."
            )


        try:
            expires_at = datetime.fromisoformat(
                str(expires_at_raw).replace(
                    "Z",
                    "+00:00"
                )
            )

        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Format waktu OTP tidak valid."
            )


        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(
                tzinfo=timezone.utc
            )


        if datetime.now(timezone.utc) > expires_at:

            delete_pending_and_auth_user(admin, pending)

            raise HTTPException(
                status_code=400,
                detail=(
                    "OTP sudah kedaluwarsa. "
                    "Silakan daftar kembali."
                )
            )


        # =========================================================
        # 6. CEK BATAS PERCOBAAN
        # =========================================================

        attempts = pending.get("attempts") or 0

        if attempts >= MAX_OTP_ATTEMPTS:

            delete_pending_and_auth_user(admin, pending)

            raise HTTPException(
                status_code=400,
                detail=(
                    "Terlalu banyak percobaan. "
                    "Silakan daftar kembali."
                )
            )


        # =========================================================
        # 7. VALIDASI OTP
        # =========================================================

        stored_otp_hash = pending.get("otp_hash")

        if not stored_otp_hash:
            raise HTTPException(
                status_code=400,
                detail="OTP belum tersimpan pada data registrasi."
            )


        if not secrets.compare_digest(
            str(stored_otp_hash).strip(),
            otp_hash
        ):

            admin.table(
                "pending_registrations"
            ).update({
                "attempts": attempts + 1
            }).eq(
                "email",
                email
            ).execute()

            raise HTTPException(
                status_code=400,
                detail="OTP tidak valid."
            )

        print("✅ OTP BENAR")


        # =========================================================
        # 8. AKTIFKAN AKUN DI SUPABASE AUTH
        # =========================================================
        # Akun sudah dibuat di register.py (email_confirm = False),
        # jadi di sini cukup dikonfirmasi.

        user_id = pending.get("user_id")

        if not user_id:
            raise HTTPException(
                status_code=400,
                detail="Data akun registrasi tidak lengkap."
            )


        print("======================================")
        print("MENGAKTIFKAN USER DI SUPABASE AUTH")
        print("======================================")


        user_result = admin.auth.admin.update_user_by_id(
            user_id,
            {
                "email_confirm": True
            }
        )


        if not user_result or not user_result.user:
            raise HTTPException(
                status_code=400,
                detail="Gagal mengaktifkan akun di Supabase Auth."
            )


        print("✅ USER BERHASIL DIAKTIFKAN")


        # =========================================================
        # 9. HAPUS DATA PENDING
        # =========================================================

        admin.table(
            "pending_registrations"
        ).delete().eq(
            "email",
            email
        ).execute()


        print("✅ PENDING REGISTRATION DIHAPUS")


        # =========================================================
        # 10. BERHASIL
        # =========================================================

        return {
            "success": True,
            "message": (
                "OTP berhasil diverifikasi. "
                "Registrasi berhasil."
            ),
            "email": email,
            "redirect": "/login"
        }


    # =============================================================
    # HTTP EXCEPTION
    # =============================================================

    except HTTPException:
        raise


    # =============================================================
    # ERROR LAINNYA
    # =============================================================

    except Exception as e:

        print("======================================")
        print("ERROR VERIFY EMAIL")
        print(repr(e))
        print("======================================")


        raise HTTPException(
            status_code=400,
            detail="Verifikasi OTP gagal. Silakan coba lagi."
        )