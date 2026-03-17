"""
Four-layer secrets scanner — parallel async execution via asyncio.gather:
1. gitleaks       — 700+ named rules, precise token formats        (subprocess async)
2. detect-secrets — hex entropy + specific detectors, no Base64    (run_in_executor)
3. keyword_regex  — password=xxx, token=xxx, secret=xxx patterns   (sync, instant)
4. llm            — OpenAI-compatible LLM semantic scan            (httpx async)
5. custom_patterns — user-defined regex, applied after dedup       (sync)

Layers 1-4 run concurrently. Total latency = max(slowest_layer), not sum.
"""
import asyncio
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

import httpx
import yaml


class Scanner:
    def __init__(self, config_path: str = "config.yaml"):
        self.cfg: dict = {}
        self.custom_patterns: list = []
        self.keyword_patterns: list = []
        self._transient_settings = None

        self._load_config(config_path)
        self._init_tools()

    def _load_config(self, path: str):
        if Path(path).exists():
            with open(path) as f:
                self.cfg = yaml.safe_load(f) or {}

        scanners = self.cfg.get("scanners", {})
        self.enable_gitleaks = scanners.get("gitleaks", True)
        self.enable_ds = scanners.get("detect_secrets", True)
        self.enable_keyword = scanners.get("keyword_regex", True)
        self.enable_custom = scanners.get("custom_patterns", True)
        self.enable_llm = scanners.get("llm", False)

        for p in self.cfg.get("patterns", []):
            self.custom_patterns.append({
                "name": p["name"],
                "regex": re.compile(p["regex"]),
                "placeholder": p.get("placeholder", f"[{p['name'].upper()}]"),
            })

        self.keyword_patterns = [
            re.compile(
                r'(?i)(?:password|passwd|pwd|secret|api_key|apikey|token|auth|credential|private_key)'
                r'(\s*[=:]\s*)["\'\`]?([^\s\n\r&"\'\`]{6,})["\'\`]?'
            )
        ]

    def _init_tools(self):
        self.gitleaks_available = False
        if self.enable_gitleaks:
            try:
                r = subprocess.run(['gitleaks', 'version'], capture_output=True, timeout=5)
                self.gitleaks_available = r.returncode == 0
            except Exception:
                pass

        self.ds_available = False
        if self.enable_ds:
            try:
                from detect_secrets.settings import transient_settings
                self._transient_settings = transient_settings
                self.ds_available = True
            except ImportError:
                pass

        self._ds_plugins = [
            {"name": "HexHighEntropyString", "limit": 3.5},
            {"name": "AWSKeyDetector"},
            {"name": "PrivateKeyDetector"},
            {"name": "JwtTokenDetector"},
            {"name": "BasicAuthDetector"},
            {"name": "GitHubTokenDetector"},
            {"name": "GitLabTokenDetector"},
            {"name": "KeywordDetector"},
        ]

    # ── Layer 1: gitleaks (async subprocess) ─────────────────────────────────

    async def _gitleaks_scan(self, text: str) -> list[str]:
        if not self.gitleaks_available:
            return []
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as rf:
            report_path = rf.name
        try:
            proc = await asyncio.create_subprocess_exec(
                'gitleaks', 'detect', '--pipe',
                '--report-format', 'json', '--report-path', report_path, '--exit-code', '0',
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(input=text.encode()), timeout=15)
            raw = Path(report_path).read_text().strip()
            findings = json.loads(raw) if raw and raw != 'null' else []
            return [fi['Secret'] for fi in (findings or []) if fi.get('Secret')]
        except Exception:
            return []
        finally:
            try:
                os.unlink(report_path)
            except Exception:
                pass

    # ── Layer 2: detect-secrets (run_in_executor — CPU-bound) ─────────────────

    def _ds_scan_sync(self, text: str) -> list[str]:
        """Synchronous detect-secrets scan — called via run_in_executor."""
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

    async def _ds_scan(self, text: str) -> list[str]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._ds_scan_sync, text)

    # ── Layer 3: keyword regex (sync, instant — wrap as coroutine) ────────────

    async def _keyword_scan(self, text: str) -> list[str]:
        if not self.enable_keyword:
            return []
        results = []
        for pattern in self.keyword_patterns:
            for match in pattern.finditer(text):
                value = match.group(match.lastindex) if match.lastindex else match.group(0)
                if value and len(value) >= 6:
                    results.append(value)
        return results

    # ── Layer 4: LLM (async httpx) ────────────────────────────────────────────

    _LLM_SYSTEM = (
        "You are a security secrets extractor. "
        "Your ONLY task is to output a JSON array of secret values found in user text. "
        "Rules:\n"
        "- Output ONLY a valid JSON array: [\"value1\", \"value2\"] or []\n"
        "- No explanations, no markdown, no code blocks, no commentary\n"
        "- Include: passwords, API keys, tokens, private keys, connection string values\n"
        "- Exclude: variable names, keywords, placeholders like [SECRET_1]\n"
        "- If nothing sensitive found: output exactly []\n"
        "Examples:\n"
        "Input: password=hunter2 → Output: [\"hunter2\"]\n"
        "Input: token: abc123xyz → Output: [\"abc123xyz\"]\n"
        "Input: ordinary text → Output: []"
    )

    async def _llm_scan(self, text: str) -> list[str]:
        if not self.enable_llm:
            return []
        llm_cfg = self.cfg.get("llm", {})
        base_url = llm_cfg.get("base_url", "http://localhost:11434/v1")
        api_key = llm_cfg.get("api_key", "dummy")
        model = llm_cfg.get("model", "local")
        timeout = float(llm_cfg.get("timeout", 30))

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(
                    f"{base_url.rstrip('/')}/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": self._LLM_SYSTEM},
                            {"role": "user", "content": text},
                        ],
                        "temperature": 0,
                        "max_tokens": 256,
                        "enable_thinking": False,
                        "chat_template_kwargs": {"enable_thinking": False},
                    },
                )
                resp.raise_for_status()
                raw = resp.json()["choices"][0]["message"]["content"].strip()
                raw = re.sub(r'<think>.*?</think>', '', raw, flags=re.DOTALL).strip()
                raw = re.sub(r'^```(?:json)?\s*', '', raw).rstrip('`').strip()
                json_match = re.search(r'\[.*?\]', raw, re.DOTALL)
                if json_match:
                    secrets = json.loads(json_match.group(0))
                    return [s for s in secrets if isinstance(s, str) and len(s) >= 4]
        except Exception:
            pass
        return []

    # ── Parallel mask ─────────────────────────────────────────────────────────

    async def mask(self, text: str) -> tuple[str, dict]:
        """
        Run all scanner layers concurrently, merge results, apply masking.
        Returns (masked_text, vault).
        """
        # All 4 layers run in parallel
        results = await asyncio.gather(
            self._gitleaks_scan(text),
            self._ds_scan(text),
            self._keyword_scan(text),
            self._llm_scan(text),
            return_exceptions=True,
        )

        all_values: list[str] = []
        for r in results:
            if isinstance(r, list):
                all_values.extend(r)
            # exceptions are silently ignored (layer failed — others continue)

        vault: dict[str, str] = {}
        counter = [0]

        def make_placeholder(category: str) -> str:
            counter[0] += 1
            return f"[{category}_{counter[0]}]"

        masked = text

        # Deduplicate, longest first (avoid partial replacements)
        seen: set[str] = set()
        for v in sorted(all_values, key=len, reverse=True):
            if v not in seen:
                seen.add(v)
                if v in masked:
                    ph = make_placeholder("SECRET")
                    vault[ph] = v
                    masked = masked.replace(v, ph)

        # Custom regex (applied after dedup — these are structural patterns)
        if self.enable_custom:
            for pattern in self.custom_patterns:
                for match in pattern["regex"].finditer(masked):
                    if match.lastindex and match.lastindex >= 2:
                        value = match.group(match.lastindex)
                    elif match.lastindex:
                        value = match.group(1)
                    else:
                        value = match.group(0)
                    if value and value not in vault.values():
                        ph = make_placeholder(pattern["name"].upper())
                        vault[ph] = value
                        masked = masked.replace(value, ph)

        return masked, vault

    def restore(self, text: str, vault: dict) -> str:
        result = text
        for placeholder, value in vault.items():
            result = result.replace(placeholder, value)
        return result

    def status(self) -> dict:
        return {
            "gitleaks": {"enabled": self.enable_gitleaks, "available": self.gitleaks_available},
            "detect_secrets": {"enabled": self.enable_ds, "available": self.ds_available},
            "keyword_regex": {"enabled": self.enable_keyword},
            "custom_patterns": {"enabled": self.enable_custom, "count": len(self.custom_patterns)},
            "llm": {"enabled": self.enable_llm, "config": self.cfg.get("llm", {})},
        }
