#!/usr/bin/env python3
"""
Seeds an administrator account with known evaluation credentials for easy demonstration.
"""

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app import create_soc_app
from app.config import Config
from app.models.models import User
from app.extensions import db
from app.auth.security import hash_password

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "AdminPassword123!"
DEFAULT_TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # Base32 secret for testing / demo authenticator apps


def init_demo_admin():
    admin_username = os.getenv("BOOTSTRAP_ADMIN_USER", DEFAULT_ADMIN_USERNAME)
    admin_password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
    totp_secret = os.getenv("BOOTSTRAP_TOTP_SECRET", DEFAULT_TOTP_SECRET)

    app = create_soc_app(Config)
    with app.app_context():
        db.create_all()
        existing_admin = User.query.filter((User.username == admin_username) | (User.role == "admin")).first()
        if existing_admin:
            print(f"[*] Administrator account already configured (user='{existing_admin.username}'). Preserving existing credentials.")
            return

        user = User(
            username=admin_username,
            password_hash=hash_password(admin_password),
            role="admin",
            mfa_enabled=True,
            totp_secret_enc=totp_secret
        )
        db.session.add(user)
        db.session.commit()
        if Config.FLASK_ENV == "production":
            print(f"[+] Initial administrator provisioned: username='{admin_username}'")
        else:
            print(f"[+] Initial Admin Created: username='{admin_username}', password='{admin_password}'")
            print(f"[+] Demo TOTP Secret Key:  '{totp_secret}'")


if __name__ == "__main__":
    init_demo_admin()
