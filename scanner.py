"""
Three-layer secrets scanner:
1. gitleaks  — 700+ named rules, precise values
2. detect-secrets — hex entropy + specific detectors (no Base64 false positives)
3. custom patterns — from config.yaml (domains, IPs, etc.)
"""
import json
import os
import re
import subprocess
import tempfile
import yaml
from pathlib import Path


class Scanner:
    def __init__(self, config_path: str = "config.yaml"):
        self.custom_patterns = []
        self.gitleaks_available = False
        self.ds_available = False
        self._load_config(config_path)
        self._init_tools()

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

    def _init_tools(self):
        # Check gitleaks
        try:
            r = subprocess.run(['gitleaks', 'version'], capture_output=True, timeout=5)
            self.gitleaks_available = r.returncode == 0
        except Exception:
            self.gitleaks_available = False

        # Check detect-secrets (only specific detectors)
        try:
            from detect_secrets.settings import transient_settings
            self._transient_settings = transient_settings
            self.ds_available = True
        except ImportError:
            self.ds_available = False

        # Verified plugin names for this detect-secrets version
        self._ds_plugins = [
            {"name": "HexHighEntropyString", "limit": 3.5},
            {"name": "AWSKeyDetector"},
            {"name": "PrivateKeyDetector"},
            {"name": "JwtTokenDetector"},
            {"name": "BasicAuthDetector"},
            {"name": "GitHubTokenDetector"},
            {"name": "GitLabTokenDetector"},
        ]

    def _gitleaks_scan(self, text: str) -> list[str]:
        """Returns list of secret values found by gitleaks."""
        if not self.gitleaks_available:
            return []
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write(text)
            tmp = f.name
        try:
            result = subprocess.run(
                ['gitleaks', 'detect', '--source', tmp, '--no-git',
                 '--report-format', 'json', '--report-path', '/dev/stdout', '--exit-code', '0'],
                capture_output=True, text=True, timeout=15
            )
            findings = json.loads(result.stdout) if result.stdout.strip() and result.stdout.strip() != 'null' else []
            return [f['Secret'] for f in (findings or []) if f.get('Secret')]
        except Exception:
            return []
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    def _detect_secrets_scan(self, text: str) -> list[str]:
        """Returns list of secret values found by detect-secrets (specific detectors only)."""
        if not self.ds_available:
            return []
        found = []
        try:
            from detect_secrets.core.scan import scan_line
            with self._transient_settings({"plugins_used": self._ds_plugins}):
                for line in text.split('\n'):
                    try:
                        for secret in scan_line(line):
                            value = secret.secret_value
                            if value and len(value) >= 8:
                                found.append(value)
                    except Exception:
                        pass
        except Exception:
            pass
        return found

    def mask(self, text: str) -> tuple[str, dict]:
        """Mask secrets. Returns (masked_text, vault)."""
        vault: dict[str, str] = {}
        counter = [0]

        def make_placeholder(category: str) -> str:
            counter[0] += 1
            return f"[{category}_{counter[0]}]"

        masked = text

        # Collect all secret values from all sources
        all_values: list[str] = []
        all_values.extend(self._gitleaks_scan(text))
        all_values.extend(self._detect_secrets_scan(text))

        # Deduplicate, sort longest first (avoid partial replacements)
        seen: set[str] = set()
        unique_values = []
        for v in sorted(all_values, key=len, reverse=True):
            if v not in seen:
                seen.add(v)
                unique_values.append(v)

        # Apply masking
        for value in unique_values:
            if value in masked:
                ph = make_placeholder("SECRET")
                vault[ph] = value
                masked = masked.replace(value, ph)

        # Custom regex patterns
        for pattern in self.custom_patterns:
            for match in pattern["regex"].finditer(masked):
                value = match.group(0)
                if value not in vault.values():
                    ph = make_placeholder(pattern["name"].upper())
                    vault[ph] = value
                    masked = masked.replace(value, ph)

        return masked, vault

    def restore(self, text: str, vault: dict) -> str:
        """Restore placeholders back to original values."""
        result = text
        for placeholder, value in vault.items():
            result = result.replace(placeholder, value)
        return result
