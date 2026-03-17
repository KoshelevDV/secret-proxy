"""
Policy Engine — evaluates scan audit against configured profile.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class Action(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    SANITIZE = "sanitize"


@dataclass
class PolicyDecision:
    action: Action
    reason: str
    secrets_count: int
    layers_fired: list[str]


class PolicyEngine:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.default_profile = cfg.get("default_profile", "standard")
        self.profiles = cfg.get("profiles", {})

    def get_profile(self, name: Optional[str] = None) -> dict:
        profile_name = name or self.default_profile
        return self.profiles.get(profile_name, self._default_standard_profile())

    def _default_standard_profile(self) -> dict:
        return {
            "policy": {
                "default_action": "sanitize",
                "max_secrets": 10,
                "rules": [],
            }
        }

    def evaluate(self, audit: list[dict], profile_name: Optional[str] = None) -> PolicyDecision:
        """
        Evaluate audit log against profile policy.
        Returns PolicyDecision with action to take.
        """
        profile = self.get_profile(profile_name)
        policy = profile.get("policy", {})

        default_action = Action(policy.get("default_action", "sanitize"))
        max_secrets = policy.get("max_secrets")
        rules = policy.get("rules", [])

        secrets_count = len(audit)
        layers_fired = list({e["layer"] for e in audit})

        # Quality gate: max_secrets threshold (but not for max_secrets=0, handled separately)
        if max_secrets is not None and max_secrets > 0 and secrets_count > max_secrets:
            return PolicyDecision(
                action=Action.BLOCK,
                reason=f"Too many secrets detected: {secrets_count} > max {max_secrets}",
                secrets_count=secrets_count,
                layers_fired=layers_fired,
            )

        # strict profile with max_secrets=0: any secret → block
        if max_secrets == 0 and secrets_count > 0:
            return PolicyDecision(
                action=Action.BLOCK,
                reason=f"Strict profile: {secrets_count} secret(s) detected",
                secrets_count=secrets_count,
                layers_fired=layers_fired,
            )

        # Per-layer rules (first match wins)
        for entry in audit:
            for rule in rules:
                if rule.get("layer") == entry.get("layer"):
                    rule_action = Action(rule.get("action", default_action.value))
                    if rule_action == Action.BLOCK:
                        return PolicyDecision(
                            action=Action.BLOCK,
                            reason=f"Blocked by rule: layer={entry['layer']}",
                            secrets_count=secrets_count,
                            layers_fired=layers_fired,
                        )

        return PolicyDecision(
            action=default_action,
            reason="ok",
            secrets_count=secrets_count,
            layers_fired=layers_fired,
        )

    def get_scanners_config(self, profile_name: Optional[str] = None) -> dict:
        """Return scanner toggles for this profile."""
        profile = self.get_profile(profile_name)
        return profile.get("scanners", {})
