"""
Honeypot Nexus - Event Publisher Facade
The ONLY outbound interface from the untrusted Honeypot layer.
Contains zero database, ORM, or OS execution dependencies.
"""

from typing import Protocol, List
from dataclasses import dataclass
from app.events.schemas import HoneypotEvent


@dataclass(frozen=True)
class PublishResult:
    accepted: bool
    reason: str = ""


class EventPublisher(Protocol):
    """Protocol that all event publishers must satisfy."""
    def publish(self, event: HoneypotEvent) -> PublishResult:
        ...


class NullPublisher:
    """Null publisher that discards events (e.g. for isolated testing)."""
    def publish(self, event: HoneypotEvent) -> PublishResult:
        return PublishResult(accepted=True)


class ListPublisher:
    """Test publisher that collects events in-memory."""
    def __init__(self):
        self.events: List[HoneypotEvent] = []

    def publish(self, event: HoneypotEvent) -> PublishResult:
        self.events.append(event)
        return PublishResult(accepted=True)

    def clear(self):
        self.events.clear()


class InProcessEventPublisher:
    """Publisher implementation backed by the trusted EventBus."""
    def __init__(self, bus):
        self._bus = bus

    def publish(self, event: HoneypotEvent) -> PublishResult:
        return self._bus.publish(event)
