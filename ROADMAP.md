# ROADMAP

## v0.2.0 — Core Hardening (2-3 недели)

Фиксы критических проблем из AGENTS.md:

- **Session vault** — multi-turn conversation support. In-memory dict per session_id (X-Session-ID header). Секреты маскированные в запросе N восстанавливаются в ответе N+k.
- **Parallel `_mask_body`** — `asyncio.gather` по всем messages в теле запроса одновременно, а не последовательно
- **`asyncio.get_running_loop()` fix** — устранить предупреждения о создании event loop в неправильном контексте
- **Request body size limit** — 500KB по умолчанию, настраивается в config.yaml
- **Basic structured logging** — JSON-формат логов с полями: timestamp, request_id, layer, masked_count, latency_ms

## v0.3.0 — Observability

- **Prometheus `/metrics` endpoint** — счётчики: secrets_masked_total (by layer), requests_total, scan_latency_seconds (histogram by layer)
- **Audit log** — что было замаскировано: layer, rule_name, secret_type, position в тексте, latency. Не логировать сами секреты.
- **Per-request scan report header** — `X-Secrets-Masked: 3` в ответе прокси
- **Request ID tracking** — `X-Request-ID` сквозной через все layers

## v0.4.0 — Policy Engine

- **Scan profiles** — `strict` / `standard` / `dev` via `X-Scan-Profile` header или config.yaml default
- **Per-category actions** — `block` (403) / `warn` (log only, pass through) / `sanitize` (mask) per secret type
- **Quality gates** — max PII/secret count threshold → 403 с объяснением
- **Allowlist** — пропустить маскировку для trusted patterns (regex или точные строки)
- **Per-profile scanner toggles** — например, `dev` профиль отключает LLM layer

## v0.5.0 — Infrastructure Integration

- **API key auth на management endpoints** — `/health`, `/metrics` требуют `X-Admin-Key`
- **Multi-tenant** — per-key scan profiles из config. API key → profile mapping.
- **Webhook alerts** — HTTP POST при policy violation (configurable URL, JSON payload)
- **LDAP/SSO** — опционально, через reverse proxy pattern (документация как настроить nginx/caddy + LDAP)

## v1.0.0 — Production Ready

- **Redis session vault** — distributed, TTL-based. Vault entries expire после N часов. Горизонтальное масштабирование прокси.
- **Hot-reload config** — inotify на config.yaml, перезагрузка без рестарта контейнера
- **Admin REST API** — CRUD для allowlist, profiles, API keys. GET /admin/stats.
- **Helm chart production-ready** — resource limits, PodDisruptionBudget, HPA, readiness/liveness probes
- **End-to-end tests** — pytest suite: каждый scanner layer, masking+restore round-trip, streaming, edge cases
