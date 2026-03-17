# AGENTS.md — secret-proxy

## What is this

Minimal transparent LLM proxy that masks secrets and PII before requests reach external LLMs (Claude, GPT, etc.), then restores them in responses.

## Stack

- **Python 3.12** + FastAPI + httpx + uvicorn
- **gitleaks v8.30.0** — binary, 700+ named secret rules
- **detect-secrets 1.5+** — Python lib, hex entropy + specific detectors
- **Qwen2.5-Coder-7B-Instruct Q4** — local LLM scanner on port 8081
- **Docker Compose** — single `docker compose up -d` to run

## Structure

```
proxy.py      — FastAPI reverse proxy (~130 lines), async _mask_body
scanner.py    — 4-layer async scanner (asyncio.gather for parallel execution)
config.yaml   — user config: toggles, LLM endpoint, custom patterns
Dockerfile    — multi-stage: gitleaks binary from zricethezav/gitleaks:v8.30.0
```

## How It Works

```
Claude Code / VS Code
  ANTHROPIC_BASE_URL=http://localhost:4000
       ↓
  secret-proxy:4000
       ↓ asyncio.gather (parallel)
  ┌─────────────────────────────────────┐
  │ Layer 1: gitleaks --pipe            │ ~15ms
  │ Layer 2: detect-secrets             │ ~5ms  (run_in_executor)
  │ Layer 3: keyword regex              │ ~0ms  (password=xxx etc.)
  │ Layer 4: LLM (Qwen2.5-Coder-7B)    │ ~650ms (only if enabled)
  └─────────────────────────────────────┘
       ↓ merge + dedup + replace
  masked text → upstream LLM (Anthropic/OpenAI)
       ↓ restore vault
  original values back in response
```

Total latency without LLM: **~24ms**. With LLM: **~650ms**.

## Scanner Layers

| Layer | What it finds | Toggle |
|-------|--------------|--------|
| gitleaks | GitLab/GitHub PATs, AWS keys, JWT, 700+ formats | `scanners.gitleaks` |
| detect-secrets | Hex entropy, AWS, JWT, BasicAuth, PrivateKey | `scanners.detect_secrets` |
| keyword_regex | `password=xxx`, `token=xxx`, `secret=xxx` | `scanners.keyword_regex` |
| LLM | Semantic: anything that looks secret in context | `scanners.llm` |
| custom_patterns | User-defined regex (IPs, domains, conn strings) | `scanners.custom_patterns` |

## Configuration

`config.yaml` — mounted as volume, no rebuild needed:

```yaml
scanners:
  gitleaks: true
  detect_secrets: true
  keyword_regex: true
  custom_patterns: true
  llm: false              # enable when Qwen2.5-Coder-7B is running on 8081

llm:
  base_url: http://10.0.30.18:8081/v1
  api_key: dummy
  model: local
  timeout: 10
```

Add custom patterns in `patterns:` section — no restart needed (config reloads on start).

## Development Rules

- `scanner.mask()` is **async** — always `await` it
- All 4 layers run via `asyncio.gather` — don't make any layer blocking
- gitleaks uses `--pipe` mode (not `--source --no-git`) — this is intentional
- detect-secrets requires `transient_settings()` context — without it returns 0 results
- LLM prompt is hardcoded as `_LLM_SYSTEM` in `Scanner` class — strict JSON-only output
- `<think>` blocks stripped from LLM response (reasoning models)
- Longest secrets replaced first (dedup sorted by len desc) — avoid partial replacements

## How to Run Locally

```bash
docker compose up -d
export ANTHROPIC_BASE_URL=http://localhost:4000
# Done — claude code / any OpenAI-compatible client works as usual
```

Health check:
```bash
curl http://localhost:4000/health
```

## LLM Scanner — Qwen2.5-Coder-7B

Model: `bartowski/Qwen2.5-Coder-7B-Instruct-GGUF` Q4_K_M (~4.5GB)
Path: `~/ai/models/Qwen2.5-Coder-7B/Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf`

Start server:
```bash
toolbox run --container llama-vulkan-radv \
  llama-server \
  -m ~/ai/models/Qwen2.5-Coder-7B/Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf \
  -c 2048 -ngl 999 --no-mmap --host 0.0.0.0 --port 8081
```

Then set `scanners.llm: true` in `config.yaml`.

## Env Vars (docker-compose)

| Var | Default | Description |
|-----|---------|-------------|
| `UPSTREAM_URL` | `https://api.anthropic.com` | Upstream LLM API |
| `PORT` | `4000` | Proxy listen port |
| `CONFIG_PATH` | `/app/config.yaml` | Path to config file |
| `TIMEOUT` | `120` | Upstream request timeout (seconds) |

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Scanner status + availability |
| `ANY /{path}` | Transparent proxy to upstream |

## Pitfalls

- **gitleaks partial match**: GitLab PAT rule matches exactly 20 chars after `glpat-`. Longer tokens (custom formats) — only prefix masked. LLM layer covers the rest.
- **detect-secrets without context**: `transient_settings()` is required — without it the library returns no results (uses empty plugin list).
- **Base64HighEntropyString removed**: was causing false positives on regular English words ("connect", "password"). Not in plugin list.
- **LLM wraps output in markdown**: `_llm_scan` strips ` ``` ` fences before JSON parse.
- **Reasoning models**: `enable_thinking: false` + `<think>` regex strip — handles both GLM and Qwen3 thinking modes.
- **config.yaml is volume-mounted**: changes take effect on container restart, not hot-reload.

## Status

- [x] v0.1.0 — initial release
  - 4-layer parallel async scanner
  - gitleaks + detect-secrets + keyword regex + LLM
  - Per-layer toggles via config.yaml
  - Custom patterns (domains, IPs, connection strings)
  - Docker Compose single-command deploy
  - /health endpoint with layer status

## Next

- [ ] Session-based vault (multi-turn conversation support)
- [ ] Hot-reload config without restart
- [ ] Metrics endpoint (masked secrets count, latency per layer)
- [ ] systemd service for Qwen2.5-Coder-7B on port 8081

## Competitive Landscape

Краткая выжимка из `docs/analysis.md` (полный анализ там).

### Ключевые конкуренты

| Проект | Тип | Лицензия | Главная фича |
|--------|-----|----------|--------------|
| LLM Guard | Python SDK | MIT | detect-secrets + Presidio anonymizer pipeline |
| LiteLLM + Presidio | Gateway proxy | MIT | Per-entity PiiAction policy, DualCache, multi-tenant |
| Microsoft Presidio | SDK/microservice | MIT | NER-based PII, 20+ entity types, multilingual |
| Limina (Private AI) | Commercial SaaS | Proprietary | 50+ PII/PHI/PCI types, 52 языка, on-prem container |
| Nightfall | Commercial SaaS | Proprietary | AI-DLP platform, 100+ models, endpoint agents |

### Наши преимущества
- **gitleaks** — 700+ named secret rules, лучший coverage для API keys/tokens
- **LLM layer** — семантическое обнаружение (есть только у нас среди open-source)
- **Transparent proxy** — ANTHROPIC_BASE_URL override, zero client changes
- **Simplicity** — ~130 строк proxy.py, `docker compose up -d`

### Наши пробелы (vs зрелые решения)
- PII detection (NER) — нет, только через LLM layer
- Policy engine (block/warn/sanitize per type) — нет
- Audit log — нет
- Prometheus metrics — нет
- Multi-tenant API keys — нет
- Session vault для multi-turn — нет ни у кого open-source (нужно реализовать)

### Vampy (hexway) — не конкурент
Vampy — AppSec/SAST/DAST platform. Изучен для референса архитектурных паттернов:
- Quality Gate: условия по критичности (LOW/MEDIUM/HIGH/CRITICAL) + тип сканера + max_value threshold
- LDAP: полная схема группового маппинга (admin/editor/readonly/blocked groups)
- OIDC: Keycloak, group-to-role mapping
- Все используется как референс для будущего v0.4.0 Policy Engine и v0.5.0 LDAP/SSO

## ROADMAP Summary

Детальный ROADMAP в `ROADMAP.md`. Краткие вехи:

| Версия | Что | Срок |
|--------|-----|------|
| **v0.2.0** | Session vault, parallel mask, request size limit, structured logging | 2-3 нед |
| **v0.3.0** | Prometheus /metrics, audit log, X-Secrets-Masked header | +2 нед |
| **v0.4.0** | Policy engine (block/warn/sanitize), scan profiles, quality gates, allowlist | +3 нед |
| **v0.5.0** | API key auth, multi-tenant, webhook alerts, LDAP/SSO docs | +2 нед |
| **v1.0.0** | Redis session vault, hot-reload, admin API, Helm production-ready, e2e tests | +4 нед |
