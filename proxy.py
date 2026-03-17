"""
Minimal LLM secrets-masking proxy.
Set ANTHROPIC_BASE_URL=http://localhost:4000 or OPENAI_BASE_URL=http://localhost:4000
"""
import copy
import json
import os
from typing import AsyncGenerator

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from scanner import Scanner

app = FastAPI(title="secret-proxy")
scanner = Scanner(os.getenv("CONFIG_PATH", "config.yaml"))

UPSTREAM = os.getenv("UPSTREAM_URL", "https://api.anthropic.com")
TIMEOUT = float(os.getenv("TIMEOUT", "120"))


@app.get("/health")
async def health():
    return {"status": "ok", **scanner.status()}


def _mask_body(body: dict) -> tuple[dict, dict]:
    """Mask all text content in OpenAI/Anthropic request body."""
    masked = copy.deepcopy(body)
    combined_vault: dict[str, str] = {}

    def mask_text(text: str) -> str:
        masked_t, vault = scanner.mask(text)
        combined_vault.update(vault)
        return masked_t

    def process_content(content):
        if isinstance(content, str):
            return mask_text(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    block["text"] = mask_text(block.get("text", ""))
        return content

    for msg in masked.get("messages", []):
        msg["content"] = process_content(msg.get("content", ""))

    if "system" in masked:
        masked["system"] = process_content(masked["system"])

    # OpenAI-style: top-level prompt (completions API)
    if "prompt" in masked and isinstance(masked["prompt"], str):
        masked["prompt"] = mask_text(masked["prompt"])

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
            masked_body, vault = _mask_body(body)
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

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        if is_streaming:
            async def stream_gen() -> AsyncGenerator[bytes, None]:
                async with client.stream(
                    request.method, url, headers=headers, content=body_bytes
                ) as resp:
                    async for chunk in resp.aiter_bytes():
                        try:
                            text = chunk.decode("utf-8")
                            yield scanner.restore(text, vault).encode("utf-8")
                        except Exception:
                            yield chunk

            return StreamingResponse(stream_gen(), media_type="text/event-stream")
        else:
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
