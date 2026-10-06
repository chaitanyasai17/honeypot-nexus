"""
Honeypot Nexus - Detection Engine
Manages rule execution, error isolation, rule toggles and execution statistics.
"""

from typing import List, Dict, Any
import time
from app.detection.base import BaseDetectionRule, Detection, RuleContext
from app.detection.rules import (
    BruteForceRule,
    CredentialAttackRule,
    SQLInjectionRule,
    DirectoryTraversalRule,
    ScannerRule,
    ReconRule,
    SuspiciousAPIRule,
    AutomatedEnumerationRule,
    ShellCommandRule,
    SensitiveFileRule,
)
from app.services.config_service import get_config_value
from app.logging_config import get_logger

logger = get_logger("detection")


class DetectionEngine:
    def __init__(self):
        self.rules: List[BaseDetectionRule] = [
            BruteForceRule(),
            CredentialAttackRule(),
            SQLInjectionRule(),
            DirectoryTraversalRule(),
            ScannerRule(),
            ReconRule(),
            SuspiciousAPIRule(),
            AutomatedEnumerationRule(),
            ShellCommandRule(),
            SensitiveFileRule(),
        ]
        self.stats: Dict[str, dict] = {
            r.rule_id: {"triggered_count": 0, "last_triggered": None, "errors": 0}
            for r in self.rules
        }

    def run(self, ctx: RuleContext) -> List[Detection]:
        """Runs all enabled rules sequentially with strict exception isolation."""
        detections: List[Detection] = []

        for rule in self.rules:
            enabled = get_config_value(f"rule.{rule.rule_id}.enabled", True)
            if not enabled:
                continue

            try:
                hits = rule.evaluate(ctx)
                if hits:
                    detections.extend(hits)
                    self.stats[rule.rule_id]["triggered_count"] += len(hits)
                    self.stats[rule.rule_id]["last_triggered"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            except Exception as e:
                self.stats[rule.rule_id]["errors"] += 1
                logger.error(f"Rule {rule.rule_id} crashed during evaluation: {e}", exc_info=True)

        return detections

    def get_rules_info(self) -> List[dict]:
        """Returns catalogue information for the Detection page."""
        res = []
        for r in self.rules:
            enabled = get_config_value(f"rule.{r.rule_id}.enabled", True)
            st = self.stats[r.rule_id]
            res.append({
                "rule_id": r.rule_id,
                "name": r.name,
                "attack_type": r.attack_type.value,
                "severity": r.severity.value,
                "points": r.points,
                "enabled": enabled,
                "description": r.description,
                "mitre": r.mitre,
                "triggered_count": st["triggered_count"],
                "last_triggered": st["last_triggered"]
            })
        return res


_engine_instance = None


def get_detection_engine() -> DetectionEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = DetectionEngine()
    return _engine_instance
