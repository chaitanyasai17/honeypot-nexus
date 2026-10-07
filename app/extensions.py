"""
Honeypot Nexus - Extensions Registry
Initializes Flask extensions avoiding circular dependencies.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate

db = SQLAlchemy()
socketio = SocketIO(
    async_mode="threading",
    cors_allowed_origins="*"
)
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["120 per minute"]
)
csrf = CSRFProtect()
migrate = Migrate()
