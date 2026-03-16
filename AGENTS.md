# AGENTS.md — secret-proxy

## What is this
Minimal FastAPI proxy that detects and masks secrets in LLM requests (Claude/GPT) before forwarding, then restores them in responses.

## Stack
- Python 3.12
- FastAPI + uvicorn (async HTTP server)
- httpx (async HTTP client for upstream)
- detect-secrets 1.5.0 (Yelp) — rule-based secret detection
- PyYAML — custom pattern config

## Structure
```
proxy.py      — FastAPI app, request routing, mask/restore cycle
scanner.py    — detect-secrets wrapper + custom regex patterns
config.yaml   — user-defined patterns (domains, IPs, connection strings)
Dockerfile    — multi-stage build (python:3.12-slim)
docker-compose.yml
helm/secret-proxy/  — Helm chart
```

## Development Rules
- `scanner.py` must use `default_settings()` context when calling `scan_line()`
- Sort detected secrets by length descending before masking (avoid partial-match collisions)
- Skip trivial matches (len <= 3) to reduce false positives
- `proxy.py` strips `content-encoding` and `content-length` from upstream response headers to avoid gzip mismatch
- No database, no Redis, no global state — vault is per-request local dict
- Health endpoint: `GET /health` → `{"status": "ok"}`

## Status
- ✅ Initial implementation complete
- ✅ detect-secrets integration verified (needs `default_settings()` context)
- ✅ Custom YAML patterns working
- ✅ Docker + Compose + Helm chart
- ⬜ Tests (pytest)
- ⬜ CI/CD

## How to run locally
```bash
pip install -r requirements.txt
python proxy.py
# or
docker compose up -d
```

## Pitfalls
- `detect_secrets.core.scan.scan_line` requires `default_settings()` context manager, otherwise returns 0 results
- `secret_value` on `PotentialSecret` can be the full `KEY=value` string or just the value — always mask what's returned
- Short entropy matches (1-3 chars like 'ec') are filtered out to reduce noise
- Upstream response `content-encoding: gzip` must be removed if we decode+re-encode the body
