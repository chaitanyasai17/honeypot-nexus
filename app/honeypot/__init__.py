"""
Honeypot Blueprint Registration.
Registers all deception surfaces onto the untrusted honeypot application.
"""

from app.honeypot.routes import honeypot_bp
from app.honeypot.login import login_bp
from app.honeypot.admin import admin_bp
from app.honeypot.api import api_bp
from app.honeypot.files import files_bp
from app.honeypot.database import database_bp
from app.honeypot.shell import shell_bp


def register_honeypot_blueprints(app):
    """Registers all public deceptive surfaces."""
    app.register_blueprint(honeypot_bp)
    app.register_blueprint(login_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(database_bp)
    app.register_blueprint(shell_bp)
