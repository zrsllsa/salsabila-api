import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.register import router as register_router
from routes.verify_email import router as verify_email_router
from routes.resend_otp import router as resend_otp_router
from routes.login import router as login_router
from routes.google import router as google_router
from routes.me import router as me_router
from routes.logout import router as logout_router
from routes.forgot_password import router as forgot_password_router
from routes.reset_password import router as reset_password_router
from routes.delete_account import router as delete_account_router

load_dotenv()


# =========================================================
# CREATE APP
# =========================================================

app = FastAPI(
    title="About Salsabila API",
    version="1.0.0"
)


# =========================================================
# CORS CONFIGURATION
# =========================================================
# Atur lewat .env, pisahkan dengan koma. Contoh:
# CORS_ORIGINS=http://localhost:5173,https://aboutsalsabila.vercel.app

origins = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# REGISTER AUTH ROUTERS
# =========================================================

app.include_router(register_router)
app.include_router(verify_email_router)
app.include_router(resend_otp_router)
app.include_router(login_router)
app.include_router(google_router)
app.include_router(me_router)
app.include_router(logout_router)
app.include_router(forgot_password_router)
app.include_router(reset_password_router)
app.include_router(delete_account_router)


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():
    return {"message": "About Salsabila API is running"}