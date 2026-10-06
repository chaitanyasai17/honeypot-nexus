"""
Honeypot Nexus - Multi-Factor Authentication (TOTP / PyOTP)
Implements RFC 6238 TOTP enrolment, replay protection, and QR code rendering.
"""

import io
import base64
import time
import pyotp
import qrcode
from app.config import Config
from app.models.models import User
from app.extensions import db


def generate_totp_secret() -> str:
    """Generates random base32 TOTP secret."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    """Generates standard otpauth:// URI."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=Config.TOTP_ISSUER)


def generate_qr_base64(secret: str, username: str) -> str:
    """Renders QR code as base64 data URI for inline display."""
    uri = get_totp_uri(secret, username)
    qr = qrcode.QRCode(box_size=4, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    b64_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64_str}"


def verify_totp_code(user: User, code: str) -> bool:
    """
    Verifies 6-digit TOTP code with drift window=1 and strict replay guard.
    In DEMO_MODE, allows '000000' or '123456' for immediate operator evaluation.
    """
    if not code:
        return False

    code_clean = code.strip()
    if Config.DEMO_MODE and code_clean in ("000000", "123456"):
        return True

    if not user.totp_secret_enc:
        return False

    totp = pyotp.TOTP(user.totp_secret_enc)
    # Check current time step
    now_step = int(time.time() / 30)

    # Replay protection: Must be newer than last successfully used step
    if now_step <= user.last_totp_step:
        return False

    is_valid = totp.verify(code_clean, valid_window=1)
    if is_valid:
        user.last_totp_step = now_step
        db.session.commit()
        return True

    return False
