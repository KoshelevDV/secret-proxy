# secret-proxy

Minimal LLM proxy that masks secrets before sending to Claude/GPT.

Минимальный прокси для LLM, который маскирует секреты перед отправкой в Claude/GPT.

## Features / Возможности

- 🔍 **detect-secrets** (Yelp) — 700+ built-in secret patterns: API keys, tokens, passwords, connection strings
- 🧩 **Custom YAML config** — add your own regex patterns (internal domains, IPs, etc.)
- ⚡ **Zero persistence** — everything in-memory per-request, no DB, no Redis
- 🔄 **Streaming support** — SSE / streaming responses with secret restoration
- 🐳 **One-command start** — `docker compose up -d`

## Quick start

```bash
docker compose up -d
export ANTHROPIC_BASE_URL=http://localhost:4000
claude "review this code with password=abc123"
```

For OpenAI:
```bash
export OPENAI_BASE_URL=http://localhost:4000
```

## Config

Edit `config.yaml` to add custom patterns (domains, IPs, etc.):

```yaml
patterns:
  - name: my_company
    regex: 'mycompany\.internal'
    placeholder: "[COMPANY_INTERNAL]"
```

Built-in rules via detect-secrets: API keys, tokens, passwords, connection strings, and 700+ more.

## How it works

```
Request → scan for secrets → replace with [SECRET_N] → forward to LLM
Response ← restore [SECRET_N] back ← receive from LLM
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `UPSTREAM_URL` | `https://api.anthropic.com` | Upstream LLM API |
| `PORT` | `4000` | Listen port |
| `CONFIG_PATH` | `config.yaml` | Path to config file |
| `TIMEOUT` | `120` | HTTP timeout (seconds) |

## Run from source

```bash
pip install -r requirements.txt
python proxy.py
```

## Docker

```bash
docker build -t secret-proxy .
docker run -p 4000:4000 -v ./config.yaml:/app/config.yaml:ro secret-proxy
```

## Docker Compose

```bash
docker compose up -d
docker compose logs -f
```

## Helm

```bash
helm install secret-proxy ./helm/secret-proxy
helm upgrade secret-proxy ./helm/secret-proxy --set image.tag=latest
```

Override values:
```bash
helm install secret-proxy ./helm/secret-proxy \
  --set env.UPSTREAM_URL=https://api.openai.com \
  --set service.port=4000
```

## License

MIT

---

# secret-proxy (RU)

Минимальный прокси для LLM, маскирующий секреты перед отправкой запросов.

**Как работает:** запрос → обнаружение секретов → замена на `[SECRET_N]` → отправка в LLM → восстановление в ответе.

**Зависимостей:** FastAPI, httpx, detect-secrets, pyyaml. Без БД, без Redis.
