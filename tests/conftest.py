"""
Honeypot Nexus - Pytest Global Fixtures
Provides isolated test clients, memory databases, and test publishers.
"""

import pytest
from app import create_soc_app, create_honeypot_app
from app.config import TestConfig
from app.extensions import db
from app.events.event_bus import EventBus
from app.events.processor import EventProcessor
from app.events.publisher import ListPublisher
from app.models.models import User
from app.auth.security import hash_password


@pytest.fixture(scope="session")
def test_config():
    return TestConfig


@pytest.fixture
def soc_app(test_config):
    app = create_soc_app(test_config)
    event_bus = EventBus(hmac_key=test_config.EVENTBUS_HMAC_KEY)
    app.extensions["event_bus"] = event_bus

    processor = EventProcessor(app, event_bus)
    event_bus.subscribe(processor.process_envelope, name="test_pipeline")
    event_bus.start()

    with app.app_context():
        db.create_all()

        # Seed test admin user
        admin_user = User(
            username="admin_test",
            password_hash=hash_password("AdminSecurePassword123!"),
            role="admin",
            mfa_enabled=False
        )
        db.session.add(admin_user)
        db.session.commit()

        yield app

        db.session.remove()
        db.drop_all()

    event_bus.stop(drain=True)


@pytest.fixture
def soc_client(soc_app):
    return soc_app.test_client()


@pytest.fixture
def honeypot_app(test_config):
    test_pub = ListPublisher()
    app = create_honeypot_app(test_config, publisher=test_pub)
    app.extensions["test_publisher"] = test_pub
    return app


@pytest.fixture
def honeypot_client(honeypot_app):
    return honeypot_app.test_client()
