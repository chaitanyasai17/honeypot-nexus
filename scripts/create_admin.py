#!/usr/bin/env python3
"""
Honeypot Nexus - Initial Admin Account Creator
CLI tool to provision administrative users securely with Argon2id and TOTP.
"""

import sys
import os
import getpass
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app import create_soc_app
from app.config import Config
from app.models.models import User
from app.extensions import db
from app.auth.security import hash_password
from app.auth.mfa import generate_totp_secret, get_totp_uri, generate_qr_base64


def main():
    print("=" * 60)
    print("  HONEYPOT NEXUS — ADMIN USER PROVISIONING")
    print("=" * 60)

    app = create_soc_app(Config)
    with app.app_context():
        # Ensure tables exist
        db.create_all()

        default_user = Config.ADMIN_USERNAME or "admin"
        username = input(f"Enter administrator username [{default_user}]: ").strip() or default_user

        existing = User.query.filter_by(username=username).first()
        if existing:
            print(f"[!] User '{username}' already exists. Updating password...")

        pwd = ""
        while not pwd or len(pwd) < 12:
            pwd = getpass.getpass("Enter secure password (min 12 characters): ")
            if len(pwd) < 12:
                print("[-] Password must be at least 12 characters long.")

        pwd_confirm = getpass.getpass("Confirm password: ")
        if pwd != pwd_confirm:
            print("[-] Passwords do not match. Aborting.")
            sys.exit(1)

        secret = generate_totp_secret()
        pwd_hash = hash_password(pwd)

        if existing:
            existing.password_hash = pwd_hash
            existing.totp_secret_enc = secret
            existing.mfa_enabled = True
            existing.role = "admin"
            existing.failed_logins = 0
            existing.locked_until = None
        else:
            user = User(
                username=username,
                password_hash=pwd_hash,
                role="admin",
                mfa_enabled=True,
                totp_secret_enc=secret
            )
            db.session.add(user)

        db.session.commit()
        uri = get_totp_uri(secret, username)

        print("\n[+] Administrator provisioned successfully!")
        print(f"    Username: {username}")
        print(f"    Role:     admin")
        print(f"    TOTP Secret Key (Base32): {secret}")
        print(f"    Authenticator Setup URI:  {uri}")
        print("\nScan this into Google Authenticator or Microsoft Authenticator.")
        print("=" * 60)


if __name__ == "__main__":
    main()
