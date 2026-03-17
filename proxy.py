"""
Minimal LLM secrets-masking proxy.
Set ANTHROPIC_BASE_URL=http://localhost:4000 or OPENAI_BASE_URL=http://localhost:4000
"""
import asyncio
import copy
import hashlib
import json
import os
import time
import time as time_module
import uuid
from threading import Lock
from typing import AsyncGenerator

import httpx
import structlog
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse, Response as FastAPIResponse, JSONResponse
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

from scanner import Scanner
from policy import PolicyEngine, Action

# ── Structured logging ────────────────────────────────────────────────────────

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.BoundLogger,
    logger_factory=structlog.PrintLoggerFactory(),
)
logger = structlog.get_logger()

# ── App & scanner ──────────────────────────────────────────────────────────────

app = FastAPI(title="secret-proxy")
scanner = Scanner(os.getenv("CONFIG_PATH", "config.yaml"))
policy_engine = PolicyEngine(scanner.cfg)

UPSTREAM = os.getenv("UPSTREAM_URL", "https://api.anthropic.com")
TIMEOUT = float(os.getenv("TIMEOUT", "120"))

_START_TIME = time_module.time()

# Cache: sha256(text) -> (masked_text, vault, audit)
_mask_cache: dict[str, tuple[str, dict[str, str], list[dict]]] = {}
_CACHE_MAX = 2048

# ── Prometheus Metrics ────────────────────────────────────────────────────────

secrets_masked_total = Counter(
    "secrets_masked_total",
    "Total secrets masked",
    ["layer"],
)
requests_total = Counter(
    "proxy_requests_total",
    "Total proxy requests",
    ["method", "masked"],
)
scan_latency = Histogram(
    "scan_latency_seconds",
    "Scan latency per request",
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)
active_sessions = Gauge(
    "session_vault_active_sessions",
    "Active session vault entries",
)
policy_blocks_total = Counter(
    "policy_blocks_total",
    "Total requests blocked by policy",
    ["profile", "reason"],
)


# ── Session Vault Store ───────────────────────────────────────────────────────

class SessionVaultStore:
    """
    In-memory per-session vault with TTL eviction.
    Session identified by X-Session-ID request header.
    If no header — vault is request-scoped (current behaviour).
    """
    DEFAULT_TTL = 3600  # 1 hour

    def __init__(self, ttl: int = DEFAULT_TTL):
        self._vaults: dict[str, dict] = {}
        self._timestamps: dict[str, float] = {}
        self._lock = Lock()
        self.ttl = ttl

    def get(self, session_id: str) -> dict:
        with self._lock:
            self._evict()
            return dict(self._vaults.get(session_id, {}))

    def update(self, session_id: str, vault: dict):
        with self._lock:
            if session_id not in self._vaults:
                self._vaults[session_id] = {}
            self._vaults[session_id].update(vault)
            self._timestamps[session_id] = time.time()

    def _evict(self):
        now = time.time()
        expired = [sid for sid, ts in self._timestamps.items() if now - ts > self.ttl]
        for sid in expired:
            self._vaults.pop(sid, None)
            self._timestamps.pop(sid, None)

    def count(self) -> int:
        with self._lock:
            return len(self._vaults)


vault_store = SessionVaultStore(ttl=int(os.getenv("SESSION_VAULT_TTL", "3600")))


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "0.4.0",
        "uptime_seconds": int(time_module.time() - _START_TIME),
        **scanner.status(),
        "session_vault": {
            "active_sessions": vault_store.count(),
            "ttl_seconds": vault_store.ttl,
        },
        "policy": {
            "default_profile": policy_engine.default_profile,
            "available_profiles": list(policy_engine.profiles.keys()),
        },
    }


@app.get("/metrics")
async def metrics():
    active_sessions.set(vault_store.count())
    return FastAPIResponse(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


# ── Masking helpers ───────────────────────────────────────────────────────────

async def _cached_mask(text: str) -> tuple[str, dict[str, str], list[dict]]:
    """Mask text with in-memory cache keyed by sha256."""
    key = hashlib.sha256(text.encode()).hexdigest()
    if key in _mask_cache:
        return _mask_cache[key]
    masked_t, vault, audit = await scanner.mask(text)
    if len(_mask_cache) >= _CACHE_MAX:
        # evict oldest quarter
        for old_key in list(_mask_cache)[: _CACHE_MAX // 4]:
            _mask_cache.pop(old_key, None)
    _mask_cache[key] = (masked_t, vault, audit)
    return masked_t, vault, audit


async def _mask_body(body: dict) -> tuple[dict, dict, list[dict]]:
    """Mask text content in the request body.

    Only the last user message is scanned (Claude API resends full history
    every turn — earlier messages were already scanned on previous requests).
    System prompt and the legacy ``prompt`` field are always scanned.
    All message processing runs in parallel via asyncio.gather.
    """
    masked = copy.deepcopy(body)
    combined_vault: dict[str, str] = {}
    combined_audit: list[dict] = []
    vault_lock = asyncio.Lock()

    async def mask_text(text: str) -> str:
        masked_t, vault, audit = await _cached_mask(text)
        async with vault_lock:
            combined_vault.update(vault)
            combined_audit.extend(audit)
        return masked_t

    async def process_content(content):
        if isinstance(content, str):
            return await mask_text(content)
        elif isinstance(content, list):
            async def process_block(block):
                if not isinstance(block, dict):
                    return block
                btype = block.get("type")
                if btype == "text":
                    block["text"] = await mask_text(block.get("text", ""))
                elif btype == "tool_result":
                    inner = block.get("content")
                    if isinstance(inner, str):
                        block["content"] = await mask_text(inner)
                    elif isinstance(inner, list):
                        async def process_sub(sub):
                            if isinstance(sub, dict) and sub.get("type") == "text":
                                sub["text"] = await mask_text(sub.get("text", ""))
                        await asyncio.gather(*[process_sub(s) for s in inner])
                return block

            await asyncio.gather(*[process_block(b) for b in content])
        return content

    # Scan only the last message (new content), not the full history
    tasks = []
    messages = masked.get("messages", [])
    if messages:
        last = messages[-1]

        async def process_last_msg():
            last["content"] = await process_content(last.get("content", ""))

        tasks.append(process_last_msg())

    await asyncio.gather(*tasks)

    if "system" in masked:
        masked["system"] = await process_content(masked["system"])

    if "prompt" in masked and isinstance(masked["prompt"], str):
        masked["prompt"] = await mask_text(masked["prompt"])

    return masked, combined_vault, combined_audit


# ── Main proxy handler ────────────────────────────────────────────────────────

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(request: Request, path: str):
    body_bytes = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)

    vault: dict[str, str] = {}
    request_audit: list[dict] = []

    # Request ID — propagate or generate
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())[:8]
    headers["x-request-id"] = request_id

    # Get session id from header (optional)
    session_id = request.headers.get("x-session-id")

    # Scan profile — from header or default
    profile_name = request.headers.get("x-scan-profile") or None

    scan_start = time_module.perf_counter()

    # Only mask POST requests with JSON body
    if request.method == "POST" and body_bytes:
        try:
            # Check body size limit
            max_body_kb = scanner.cfg.get("limits", {}).get("max_body_size_kb", 500)
            if len(body_bytes) > max_body_kb * 1024:
                logger.warning(
                    "request_too_large",
                    request_id=request_id,
                    size_kb=len(body_bytes) // 1024,
                    limit_kb=max_body_kb,
                    path=path,
                )
                # Pass through unmasked — don't block, just skip masking
            else:
                body = json.loads(body_bytes)
                masked_body, vault, request_audit = await _mask_body(body)
                body_bytes = json.dumps(masked_body).encode()
                headers["content-length"] = str(len(body_bytes))

                # Update session vault and build full_vault for restore
                if session_id and vault:
                    vault_store.update(session_id, vault)
                    full_vault = {**vault_store.get(session_id), **vault}
                elif session_id:
                    full_vault = vault_store.get(session_id)
                else:
                    full_vault = vault

                if vault:
                    logger.info(
                        "request_masked",
                        request_id=request_id,
                        session_id=session_id or "none",
                        secrets_count=len(vault),
                        secret_keys=list(vault.keys()),
                        path=path,
                        method=request.method,
                    )

                vault = full_vault
        except Exception:
            pass  # pass through as-is

    scan_duration = time_module.perf_counter() - scan_start
    scan_latency.observe(scan_duration)

    # Policy evaluation
    if request_audit or (request.method == "POST" and body_bytes):
        decision = policy_engine.evaluate(request_audit, profile_name)
        if decision.action == Action.BLOCK:
            effective_profile = profile_name or policy_engine.default_profile
            policy_blocks_total.labels(
                profile=effective_profile,
                reason=decision.reason[:64],
            ).inc()
            logger.warning(
                "policy_block",
                request_id=request_id,
                profile=effective_profile,
                reason=decision.reason,
                secrets_count=decision.secrets_count,
                layers=decision.layers_fired,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "policy_violation",
                    "reason": decision.reason,
                    "secrets_count": decision.secrets_count,
                    "layers": decision.layers_fired,
                    "profile": effective_profile,
                },
            )
        elif decision.action == Action.WARN:
            logger.warning(
                "policy_warn",
                request_id=request_id,
                reason=decision.reason,
                secrets_count=decision.secrets_count,
                layers=decision.layers_fired,
            )
            # Pass through WITH masking (warn = log but don't block)
    else:
        decision = policy_engine.evaluate([], profile_name)

    requests_total.labels(method=request.method, masked="true" if vault else "false").inc()
    if vault:
        # Count per-layer from audit
        layer_counts: dict[str, int] = {}
        for entry in request_audit:
            layer = entry.get("layer", "unknown")
            layer_counts[layer] = layer_counts.get(layer, 0) + 1
        for layer, count in layer_counts.items():
            secrets_masked_total.labels(layer=layer).inc(count)
        # total counter
        secrets_masked_total.labels(layer="total").inc(len(vault))

    url = f"{UPSTREAM.rstrip('/')}/{path}"
    if request.url.query:
        url += f"?{request.url.query}"

    is_streaming = False
    if vault and body_bytes:
        try:
            is_streaming = bool(json.loads(body_bytes).get("stream", False))
        except Exception:
            pass

    if is_streaming:
        client = httpx.AsyncClient(timeout=TIMEOUT)

        async def stream_gen() -> AsyncGenerator[bytes, None]:
            try:
                async with client.stream(
                    request.method, url, headers=headers, content=body_bytes
                ) as resp:
                    async for chunk in resp.aiter_bytes():
                        try:
                            text = chunk.decode("utf-8")
                            yield scanner.restore(text, vault).encode("utf-8")
                        except Exception:
                            yield chunk
            finally:
                await client.aclose()

        return StreamingResponse(stream_gen(), media_type="text/event-stream")
    else:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.request(
                request.method, url, headers=headers, content=body_bytes
            )
            try:
                restored = scanner.restore(resp.text, vault)
                resp_headers = dict(resp.headers)
                resp_headers.pop("content-encoding", None)  # avoid gzip mismatch
                resp_headers.pop("content-length", None)
                # Observability headers
                resp_headers["x-secrets-masked"] = str(len(vault))
                if vault and request_audit:
                    layers_used = sorted({entry["layer"] for entry in request_audit})
                    resp_headers["x-secrets-layers"] = ",".join(layers_used)
                resp_headers["x-request-id"] = request_id
                resp_headers["x-scan-profile"] = profile_name or policy_engine.default_profile
                resp_headers["x-policy-action"] = decision.action.value
                return Response(
                    content=restored.encode("utf-8"),
                    status_code=resp.status_code,
                    headers=resp_headers,
                )
            except Exception:
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "4000")))
