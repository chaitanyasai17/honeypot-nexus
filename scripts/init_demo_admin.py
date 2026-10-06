#!/usr/bin/env python3
"""
Seeds an administrator account with known evaluation credentials for easy demonstration.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app import create_soc_app
from app.config import Config
from app.models.models import User
from app.extensions import db
from app.auth.security import hash_password

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "AdminPassword123!"
DEMO_TOTP_SECRET = "JBSWY3DPEHPK3PXP" # Base32 secret for testing / demo authenticator apps


def init_demo_admin():
    app = create_soc_app(Config)
    with app.app_context():
        db.create_all()
        user = User.query.filter_by(username=ADMIN_USERNAME).first()
        if not user:
            user = User(
                username=ADMIN_USERNAME,
                password_hash=hash_password(ADMIN_PASSWORD),
                role="admin",
                mfa_enabled=True,
                totp_secret_enc=DEMO_TOTP_SECRET
            )
            db.session.add(user)
            db.session.commit()
            print(f"[+] Initial Admin Created: username='{ADMIN_USERNAME}', password='{ADMIN_PASSWORD}'")
            print(f"[+] Demo TOTP Secret Key:  '{DEMO_TOTP_SECRET}'")
        else:
            user.password_hash = hash_password(ADMIN_PASSWORD)
            user.totp_secret_enc = DEMO_TOTP_SECRET
            user.mfa_enabled = True
            db.session.commit()
            print(f"[*] Admin Password & MFA Updated: username='{ADMIN_USERNAME}', password='{ADMIN_PASSWORD}'")


if __name__ == "__main__":
    init_demo_admin()
