"""
Minimal LLM secrets-masking proxy.
Set ANTHROPIC_BASE_URL=http://localhost:4000 or OPENAI_BASE_URL=http://localhost:4000
"""
import copy
import hashlib
import json
import logging
import os
from typing import AsyncGenerator

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("secret-proxy")

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from scanner import Scanner

app = FastAPI(title="secret-proxy")
scanner = Scanner(os.getenv("CONFIG_PATH", "config.yaml"))

UPSTREAM = os.getenv("UPSTREAM_URL", "https://api.anthropic.com")
TIMEOUT = float(os.getenv("TIMEOUT", "120"))

# Cache: sha256(text) -> (masked_text, vault)
_mask_cache: dict[str, tuple[str, dict[str, str]]] = {}
_CACHE_MAX = 2048


@app.get("/health")
async def health():
    return {"status": "ok", **scanner.status()}


async def _cached_mask(text: str) -> tuple[str, dict[str, str]]:
    """Mask text with in-memory cache keyed by sha256."""
    key = hashlib.sha256(text.encode()).hexdigest()
    if key in _mask_cache:
        return _mask_cache[key]
    masked_t, vault = await scanner.mask(text)
    if len(_mask_cache) >= _CACHE_MAX:
        # evict oldest quarter
        for old_key in list(_mask_cache)[:_CACHE_MAX // 4]:
            _mask_cache.pop(old_key, None)
    _mask_cache[key] = (masked_t, vault)
    return masked_t, vault


async def _mask_body(body: dict) -> tuple[dict, dict]:
    """Mask text content in the request body.

    Only the last user message is scanned (Claude API resends full history
    every turn — earlier messages were already scanned on previous requests).
    System prompt and the legacy ``prompt`` field are always scanned.
    """
    masked = copy.deepcopy(body)
    combined_vault: dict[str, str] = {}

    async def mask_text(text: str) -> str:
        masked_t, vault = await _cached_mask(text)
        combined_vault.update(vault)
        return masked_t

    async def process_content(content):
        if isinstance(content, str):
            return await mask_text(content)
        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type")
                if btype == "text":
                    block["text"] = await mask_text(block.get("text", ""))
                elif btype == "tool_result":
                    inner = block.get("content")
                    if isinstance(inner, str):
                        block["content"] = await mask_text(inner)
                    elif isinstance(inner, list):
                        for sub in inner:
                            if isinstance(sub, dict) and sub.get("type") == "text":
                                sub["text"] = await mask_text(sub.get("text", ""))
        return content

    # Scan only the last message (new content), not the full history
    messages = masked.get("messages", [])
    if messages:
        last = messages[-1]
        log.debug("scanning last message role=%s", last.get("role"))
        last["content"] = await process_content(last.get("content", ""))

    if "system" in masked:
        masked["system"] = await process_content(masked["system"])

    if "prompt" in masked and isinstance(masked["prompt"], str):
        masked["prompt"] = await mask_text(masked["prompt"])

    return masked, combined_vault


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(request: Request, path: str):
    body_bytes = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)

    vault: dict[str, str] = {}

    # Only mask POST requests with JSON body
    if request.method == "POST" and body_bytes:
        try:
            body = json.loads(body_bytes)
            masked_body, vault = await _mask_body(body)
            body_bytes = json.dumps(masked_body).encode()
            headers["content-length"] = str(len(body_bytes))
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
