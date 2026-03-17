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
from threading import Lock
from typing import AsyncGenerator

import httpx
import structlog
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from scanner import Scanner

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

UPSTREAM = os.getenv("UPSTREAM_URL", "https://api.anthropic.com")
TIMEOUT = float(os.getenv("TIMEOUT", "120"))

# Cache: sha256(text) -> (masked_text, vault)
_mask_cache: dict[str, tuple[str, dict[str, str]]] = {}
_CACHE_MAX = 2048


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
        **scanner.status(),
        "session_vault": {
            "active_sessions": vault_store.count(),
            "ttl_seconds": vault_store.ttl,
        },
    }


# ── Masking helpers ───────────────────────────────────────────────────────────

async def _cached_mask(text: str) -> tuple[str, dict[str, str]]:
    """Mask text with in-memory cache keyed by sha256."""
    key = hashlib.sha256(text.encode()).hexdigest()
    if key in _mask_cache:
        return _mask_cache[key]
    masked_t, vault = await scanner.mask(text)
    if len(_mask_cache) >= _CACHE_MAX:
        # evict oldest quarter
        for old_key in list(_mask_cache)[: _CACHE_MAX // 4]:
            _mask_cache.pop(old_key, None)
    _mask_cache[key] = (masked_t, vault)
    return masked_t, vault


async def _mask_body(body: dict) -> tuple[dict, dict]:
    """Mask text content in the request body.

    Only the last user message is scanned (Claude API resends full history
    every turn — earlier messages were already scanned on previous requests).
    System prompt and the legacy ``prompt`` field are always scanned.
    All message processing runs in parallel via asyncio.gather.
    """
    masked = copy.deepcopy(body)
    combined_vault: dict[str, str] = {}
    vault_lock = asyncio.Lock()

    async def mask_text(text: str) -> str:
        masked_t, vault = await _cached_mask(text)
        async with vault_lock:
            combined_vault.update(vault)
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

    return masked, combined_vault


# ── Main proxy handler ────────────────────────────────────────────────────────

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(request: Request, path: str):
    body_bytes = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)

    vault: dict[str, str] = {}

    # Get session id from header (optional)
    session_id = request.headers.get("x-session-id")

    # Only mask POST requests with JSON body
    if request.method == "POST" and body_bytes:
        try:
            # Check body size limit
            max_body_kb = scanner.cfg.get("limits", {}).get("max_body_size_kb", 500)
            if len(body_bytes) > max_body_kb * 1024:
                logger.warning(
                    "request_too_large",
                    size_kb=len(body_bytes) // 1024,
                    limit_kb=max_body_kb,
                    path=path,
                )
                # Pass through unmasked — don't block, just skip masking
            else:
                body = json.loads(body_bytes)
                masked_body, vault = await _mask_body(body)
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
                        request_id=request.headers.get("x-request-id", "-"),
                        session_id=session_id or "none",
                        secrets_count=len(vault),
                        secret_keys=list(vault.keys()),
                        path=path,
                        method=request.method,
                    )

                vault = full_vault
        except Exception:
            pass  # pass through as-is

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
