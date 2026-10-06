"""
Honeypot Nexus - Detection Engine Base Classes
Defines BaseDetectionRule, Detection result structure, and RuleContext.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from app.events.schemas import AttackType, Severity


@dataclass(frozen=True)
class Detection:
    rule_id: str
    attack_type: AttackType
    severity: Severity
    points: int
    reason: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0


@dataclass
class RuleContext:
    raw_event: Dict[str, Any]
    meta: Dict[str, Any]
    transient: Dict[str, Any]
    session: Any
    windows: Any


class BaseDetectionRule(ABC):
    rule_id: str
    name: str
    attack_type: AttackType
    severity: Severity
    points: int
    stateful: bool
    enabled: bool = True
    description: str = ""
    mitre: List[str] = field(default_factory=list)

    @abstractmethod
    def evaluate(self, ctx: RuleContext) -> List[Detection]:
        ...
