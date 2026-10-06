"""
Honeypot Nexus - Secure EventBus
Implements in-process, bounded, HMAC-signed event queue with backpressure and stats.
"""

import hmac
import hashlib
import json
import queue
import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Callable, List, Optional
from pydantic import ValidationError

from app.events.schemas import HoneypotEvent, BusEnvelope
from app.events.publisher import PublishResult, EventPublisher
from app.logging_config import get_logger

logger = get_logger("security")
app_logger = get_logger("app")


@dataclass
class BusStats:
    queue_depth: int
    published: int
    processed: int
    rejected: int
    dropped: int
    last_error: Optional[str]
    lag_ms: float
    status: str # operational, degraded


class EventBus:
    """Thread-safe, signed, bounded EventBus."""

    def __init__(self, hmac_key: str, maxsize: int = 5000, num_workers: int = 1):
        self.hmac_key = hmac_key.encode("utf-8") if isinstance(hmac_key, str) else hmac_key
        self.queue: queue.Queue = queue.Queue(maxsize=maxsize)
        self.num_workers = num_workers
        self._seq = 0
        self._published = 0
        self._processed = 0
        self._rejected = 0
        self._dropped = 0
        self._last_error = None
        self._last_processed_time = time.time()
        self._lock = threading.Lock()
        self._subscribers: List[tuple[str, Callable[[BusEnvelope], None]]] = []
        self._workers: List[threading.Thread] = []
        self._running = False

    def publisher(self) -> EventPublisher:
        """Returns the publisher facade handed to the untrusted honeypot."""
        from app.events.publisher import InProcessEventPublisher
        return InProcessEventPublisher(self)

    def subscribe(self, handler: Callable[[BusEnvelope], None], name: str = "handler"):
        """Subscribes a pipeline stage to receive envelopes."""
        self._subscribers.append((name, handler))

    def _canonical_json(self, data: dict) -> str:
        """Produces canonical deterministic JSON string."""
        return json.dumps(data, sort_keys=True, separators=(',', ':'), default=str)

    def _sign_payload(self, canonical_payload: str) -> str:
        """Computes HMAC-SHA256 signature for envelope payload."""
        return hmac.new(self.hmac_key, canonical_payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_envelope(self, envelope: BusEnvelope) -> bool:
        """Verifies envelope HMAC signature."""
        expected = self._sign_payload(envelope.payload_json)
        return hmac.compare_digest(expected, envelope.signature)

    def publish(self, event: HoneypotEvent) -> PublishResult:
        """
        Validates event, signs envelope, and enqueues it.
        Guaranteed to never raise an exception into the honeypot request path.
        """
        try:
            # Pydantic validation check
            if not isinstance(event, HoneypotEvent):
                try:
                    event = HoneypotEvent(**dict(event))
                except Exception as val_err:
                    with self._lock:
                        self._rejected += 1
                    logger.warning(f"Rejected invalid event: {val_err}")
                    return PublishResult(accepted=False, reason=str(val_err))

            # Serialize payload to canonical json
            payload_dict = event.model_dump(mode="json")
            canonical_payload = self._canonical_json(payload_dict)
            signature = self._sign_payload(canonical_payload)

            with self._lock:
                self._seq += 1
                curr_seq = self._seq

            envelope = BusEnvelope(
                seq=curr_seq,
                schema_version=event.schema_version,
                payload_json=canonical_payload,
                signature=signature
            )

            # Try enqueuing with backpressure
            try:
                self.queue.put_nowait(envelope)
                with self._lock:
                    self._published += 1
                return PublishResult(accepted=True)
            except queue.Full:
                with self._lock:
                    self._dropped += 1
                logger.warning("EventBus queue full; dropped incoming event")
                return PublishResult(accepted=False, reason="Queue is full")

        except Exception as e:
            with self._lock:
                self._rejected += 1
                self._last_error = str(e)
            logger.error(f"Unexpected error in publish: {e}", exc_info=True)
            return PublishResult(accepted=False, reason=str(e))

    def _worker_loop(self):
        """Worker loop processing envelopes sequentially."""
        while self._running:
            try:
                envelope = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                start_t = time.time()
                # Verify HMAC signature
                if not self.verify_envelope(envelope):
                    with self._lock:
                        self._rejected += 1
                    logger.error(f"Envelope {envelope.envelope_id} failed HMAC signature verification! Dropping.")
                    self.queue.task_done()
                    continue

                # Run each subscriber stage sequentially
                for name, handler in self._subscribers:
                    try:
                        handler(envelope)
                    except Exception as stage_err:
                        with self._lock:
                            self._last_error = f"{name}: {stage_err}"
                        app_logger.error(f"Stage '{name}' failed on envelope {envelope.envelope_id}: {stage_err}", exc_info=True)

                with self._lock:
                    self._processed += 1
                    self._last_processed_time = time.time()
            except Exception as e:
                with self._lock:
                    self._last_error = str(e)
                app_logger.error(f"Worker unhandled error on envelope: {e}", exc_info=True)
            finally:
                self.queue.task_done()

    def start(self):
        """Starts worker threads."""
        if self._running:
            return
        self._running = True
        for i in range(self.num_workers):
            t = threading.Thread(target=self._worker_loop, daemon=True, name=f"EventBusWorker-{i+1}")
            t.start()
            self._workers.append(t)
        app_logger.info(f"EventBus started with {self.num_workers} worker(s)")

    def stop(self, drain: bool = True):
        """Stops worker threads."""
        if drain:
            try:
                self.queue.join()
            except Exception:
                pass
        self._running = False
        for t in self._workers:
            t.join(timeout=2.0)
        self._workers.clear()
        app_logger.info("EventBus stopped")

    def stats(self) -> BusStats:
        """Returns real-time bus telemetry."""
        q_depth = self.queue.qsize()
        lag = max(0.0, (time.time() - self._last_processed_time) * 1000.0) if q_depth > 0 else 0.0
        status = "degraded" if (q_depth > (self.queue.maxsize * 0.8) or self._dropped > 0) else "operational"
        with self._lock:
            return BusStats(
                queue_depth=q_depth,
                published=self._published,
                processed=self._processed,
                rejected=self._rejected,
                dropped=self._dropped,
                last_error=self._last_error,
                lag_ms=round(lag, 2),
                status=status
            )
