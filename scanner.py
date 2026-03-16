"""
Сканирует текст через detect-secrets + кастомные regex из config.yaml.
Возвращает замаскированный текст + vault для восстановления.
"""
import re
import yaml
from pathlib import Path


class Scanner:
    def __init__(self, config_path: str = "config.yaml"):
        self.custom_patterns = []
        self._load_config(config_path)
        self._init_detect_secrets()

    def _load_config(self, path: str):
        if Path(path).exists():
            with open(path) as f:
                cfg = yaml.safe_load(f) or {}
            for p in cfg.get("patterns", []):
                self.custom_patterns.append({
                    "name": p["name"],
                    "regex": re.compile(p["regex"]),
                    "placeholder": p.get("placeholder", f"[{p['name'].upper()}]"),
                })

    def _init_detect_secrets(self):
        """Pre-initialize detect-secrets to avoid per-call overhead."""
        try:
            from detect_secrets.settings import default_settings
            from detect_secrets.core.scan import scan_line as _scan_line
            self._scan_line = _scan_line
            self._default_settings = default_settings
            self._ds_available = True
        except ImportError:
            self._ds_available = False

    def mask(self, text: str) -> tuple[str, dict]:
        """
        Returns (masked_text, vault)
        vault = {"[SECRET_1]": "actual_value", ...}
        """
        vault: dict[str, str] = {}
        counter = [0]

        def next_placeholder(category: str) -> str:
            counter[0] += 1
            return f"[{category}_{counter[0]}]"

        masked = text

        # 1. detect-secrets — collect all found secret values, sort longest first
        #    to avoid partial-match collisions (e.g. mask 'KEY=val' before 'val')
        if self._ds_available:
            found_values: list[str] = []
            try:
                with self._default_settings():
                    for line in text.split("\n"):
                        for secret in self._scan_line(line):
                            value = secret.secret_value
                            if value and len(value) >= 10:  # skip short false-positive words
                                found_values.append(value)
            except Exception:
                pass

            # Sort longest first, deduplicate
            seen: set[str] = set()
            for value in sorted(found_values, key=len, reverse=True):
                if value in seen or value in vault.values():
                    continue
                seen.add(value)
                if value in masked:
                    ph = next_placeholder("SECRET")
                    vault[ph] = value
                    masked = masked.replace(value, ph)

        # 2. Custom regex patterns from config.yaml
        for pattern in self.custom_patterns:
            for match in pattern["regex"].finditer(masked):
                value = match.group(0)
                if value not in vault.values():
                    ph = next_placeholder(pattern["name"].upper())
                    vault[ph] = value
                    masked = masked.replace(value, ph)

        return masked, vault

    def restore(self, text: str, vault: dict) -> str:
        """Restore placeholders back to original values."""
        result = text
        for placeholder, value in vault.items():
            result = result.replace(placeholder, value)
        return result
