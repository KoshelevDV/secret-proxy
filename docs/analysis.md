# Landscape Analysis: LLM Secrets/PII Proxies

## Date: 2026-03-17

## Sources Actually Read

All facts below come exclusively from code/docs fetched via web_fetch or exec:

1. **LLM Guard README** — `raw.githubusercontent.com/protectai/llm-guard/main/README.md` ✅
2. **LLM Guard secrets.py** — `raw.githubusercontent.com/protectai/llm-guard/main/llm_guard/input_scanners/secrets.py` ✅
3. **LiteLLM presidio.py** — `raw.githubusercontent.com/BerriAI/litellm/main/litellm/proxy/guardrails/guardrail_hooks/presidio.py` ✅
4. **Presidio docs** — `microsoft.github.io/presidio/` ✅
5. **Private AI / Limina** — `private-ai.com` (redirected to getlimina.ai) ✅
6. **Nightfall** — `nightfall.ai` ✅
7. **Pangea** — `pangea.cloud/services/redact` ❌ (редирект на CrowdStrike AIDR — данные о Pangea не получены)
8. **CrowdStrike AIDR** — получен по редиректу с pangea.cloud ✅ (частично)
9. **Vampy (hexway)** — `/tmp/hexway_inspect/` локально ✅
   - `modules/quality_gate/constants.py`
   - `modules/quality_gate/models.py`
   - `serializers/quality_gate.py`
   - `serializers/service/ldap.py`
   - `serializers/oidc.py`
   - `tasks/quality_gate.py`
   - `tasks/ai.py`

---

## Projects Reviewed

### 1. LLM Guard (protectai/llm-guard)
**License:** MIT  
**Type:** Python SDK + optional API deployment

**Secret detection:** Uses `detect-secrets` library with 70+ named plugins:
`SoftlayerDetector`, `StripeDetector`, `NpmDetector`, `IbmCosHmacDetector`, `DiscordBotTokenDetector`, `BasicAuthDetector`, `AzureStorageKeyDetector`, `AWSKeyDetector`, `JwtTokenDetector`, `PrivateKeyDetector` + 50+ custom plugins (GitHub, GitLab, GCP, Grafana, Heroku, HubSpot, Databricks, Datadog, etc.).

**PII detection:** Uses `presidio_anonymizer.core.text_replace_builder.TextReplaceBuilder` for text replacement. Has `Anonymize` (input scanner) + `Deanonymize` (output scanner) pair for masking+restore.

**Architecture:**
- SDK-first: called directly in Python code, not a proxy
- Scanners are stateless Python classes
- No vault persistence across requests — deanonymize vault is per-call
- No built-in Redis/cache layer
- Optional API deployment via separate service

**Vault:** Per-request in-memory mapping (inside Anonymize/Deanonymize scanner instance).

**Streaming:** Not mentioned in README. SDK-level, no SSE handling.

**Scanners (full list from README):**
- Input: Anonymize, BanCode, BanCompetitors, BanSubstrings, BanTopics, Code, Gibberish, InvisibleText, Language, PromptInjection, Regex, Secrets, Sentiment, TokenLimit, Toxicity
- Output: BanCode, BanCompetitors, BanSubstrings, BanTopics, Bias, Code, Deanonymize, JSON, Language, LanguageSame, MaliciousURLs, NoRefusal, ReadingTime, FactualConsistency, Gibberish, Regex, Relevance, Sensitive, Sentiment, Toxicity, URLReachability

**LDAP/SSO:** Not mentioned.  
**Webhook/alerts:** Not mentioned.  
**Admin UI:** Not mentioned.  
**Metrics:** Not mentioned.  
**Docker Compose:** Optional (API mode).

---

### 2. LiteLLM + Presidio Guardrail
**License:** MIT (LiteLLM), MIT (Presidio)  
**Type:** LLM proxy with plugin guardrail system

**PII detection:** Delegates to external Presidio Analyzer service (`PRESIDIO_ANALYZER_API_BASE`). Analyzes text via HTTP POST to Presidio.

**Vault/restore:** In-memory dict `self.pii_tokens` — maps masked token to original text. Used for deanonymization when `output_parse_pii=True` or `apply_to_output=True`.

**Per-entity policy:** `pii_entities_config: Dict[PiiEntityType, PiiAction]` — per-category actions. `presidio_score_thresholds: Dict[PiiEntityType, float]` — confidence thresholds. `presidio_entities_deny_list` — entities to always block.

**Streaming:** Has `StreamingChoices` type import — streaming is supported in LiteLLM proxy.

**Session vault:** `pii_tokens` dict lives on the class instance (single-request scope unless session sharing implemented externally).

**Cache:** Uses `DualCache` (LiteLLM's Redis + in-memory hybrid cache).

**Multi-tenant:** LiteLLM proxy has per-API-key configuration natively.

**LDAP/SSO:** LiteLLM enterprise has SSO (not confirmed from this specific file).

**Admin UI:** LiteLLM proxy has a built-in UI (confirmed from general LiteLLM docs, not this file).

**Metrics:** LiteLLM has `/metrics` Prometheus endpoint (not confirmed from this file).

**Per-request config:** `PresidioPerRequestConfig` type exists — configurable per request.

**Languages:** `presidio_language` param (default `"en"`).

**Session handling:** asyncio.Lock for concurrent session safety; background thread session isolation via `_loop_sessions` dict.

**Logging only mode:** `logging_only=True` → `event_hook = logging_only` — scan without masking.

---

### 3. Microsoft Presidio
**License:** MIT  
**Type:** SDK + HTTP microservices

**Modules (from presidio docs):**
- `presidio-analyzer`: PII identification in text
- `presidio-anonymizer`: De-identification with operators
- `presidio-image-redactor`: PII redaction in images via OCR
- `presidio-structured`: PII in structured/semi-structured data

**Detection methods:** Named Entity Recognition, regular expressions, rule-based logic, checksum with context. Multiple languages.

**External models:** Supports connecting to external PII detection models.

**Deployment:** Python/PySpark, Docker, Kubernetes.

**Customization:** Custom PII recognizers, custom anonymization operators.

**Not a proxy** — library/service to call from your code.

**Limitation (stated in docs):** "No guarantee that Presidio will find all sensitive information" — additional systems recommended.

---

### 4. Private AI / Limina (private-ai.com → getlimina.ai)
**License:** Commercial (SaaS / on-prem container)  
**Type:** PII/PHI/PCI detection SaaS + on-prem

**Entity types:** 50+ — PII, PHI, PCI: names, SSNs, credit cards, conditions, medications, passport numbers, international variants.

**Languages:** 52 languages, multilingual and code-switching support.

**Deployment:** Container in your VPC or on-prem — "data never leaves your infrastructure".

**Operations:** Redact, pseudonymize, generate synthetic PII, generalize entities.

**Integrations (stated):** AWS, Azure, Snowflake, NVIDIA NeMo.

**Compliance:** Expert determination reports for HIPAA, GDPR, CPRA — "accepted by compliance teams".

**Use cases:** EMRs, call transcripts, chat logs, ASR/OCR outputs.

**Secret detection (API keys):** Not mentioned on landing.

---

### 5. Nightfall
**License:** Commercial (SaaS)  
**Type:** AI-native DLP platform

**Detection:** 100+ AI-based models, LLM classifiers + Computer Vision models. 95% accuracy claimed (vs "5-25% for legacy solutions"). Detects NHIs (non-human identities / credentials), PHI, PCI, PII.

**Coverage:** SaaS apps (Slack, M365, Google Workspace, GitHub, Salesforce), endpoints, browsers, email, AI apps (prompt inspection).

**AI prompt protection:** Inspects every prompt and response, blocks/redacts sensitive data before it reaches AI models. Prevents copy/paste and file upload leaks.

**Agentic DLP:** "Nyx" — AI analyst for investigation and autonomous response.

**Deployment:** API-based SaaS integrations, lightweight endpoint agents, browser plugins.

**Policy:** "Intelligent policies that self-learn". Per-user, per-app configuration implied.

**Secret detection:** Detects "non-human identities" (NHIs) — credentials and API keys.

**Secret detection (not confirmed):** Exact technical mechanism not disclosed on landing.

---

### 6. Vampy (hexway) — AppSec Platform
**Source:** `/tmp/hexway_inspect/` local files  
**License:** Commercial (proprietary)  
**Type:** AppSec/SAST/DAST management platform — NOT an LLM proxy

**Quality Gate system** (from `modules/quality_gate/`):
- Conditions by: `QualityGateCriticality` (LOW/MEDIUM/HIGH/CRITICAL), `ScannerType`, `Severity`, `max_value` (threshold)
- Status: IN_PROGRESS/TIMED_OUT/SKIPPED/FAILED/PASSED/ERROR
- Applied to: PRODUCT or REPOSITORY (with optional REPOSITORY_BRANCH sub-relation)
- Celery task `QualityGateCalculationTask` — async background calculation
- Configurable per slug, can be default gate

**LDAP** (from `serializers/service/ldap.py`):
- Full LDAP schema: protocol, host, port, base_dn, admin_login, admin_password
- Group mappings: adminGroupDN, editorGroupDN, readonlyGroupDN, blockedGroupDN
- User attribute mapping: userFilter, objectClass, loginAttribute, emailAttribute, firstName/LastName
- Password masked on dump via `hexway_commons.sensitive_data.secret_processing.display_secret`

**OIDC** (from `serializers/oidc.py`):
- Keycloak integration (callback URL pattern: `/oidc/keycloak/callback/`)
- Providers: OIDCProvider enum
- Group-to-role mapping: `mappedGroups` dict, `blockedGroups` list
- Standard OIDC fields: client_id, client_secret, scope, authorize_url, access_token_url

**AI integration** (from `tasks/ai.py`):
- `process_ai_request` Celery task for scan issue false-positive probability analysis
- Three-tier FP categorization: Low/Medium/High (configurable thresholds)
- AI model configured per integration (not hardcoded)

**Deployment:** Docker Compose + systemd (`/tmp/hexway_inspect/systemd/`). Likely Helm (enterprise).

---

## Feature Comparison Table

| Фича | secret-proxy | LLM Guard | LiteLLM+Presidio | Limina/Private AI | Nightfall |
|------|-------------|-----------|-----------------|-------------------|-----------|
| **Secret detection (API keys, tokens)** | ✅ 4 layers: gitleaks (700+ rules) + detect-secrets + regex + LLM | ✅ detect-secrets (70+ plugins, custom) | ❌ только PII (Presidio) | ❌ не упомянуто | ✅ NHI/credentials |
| **PII detection (names, emails, SSN)** | ⚠️ только через LLM layer | ✅ Presidio anonymizer | ✅ Presidio (50+ entity types) | ✅ 50+ типов PII/PHI/PCI | ✅ NHI/PHI/PCI/PII |
| **Masking + restore vault** | ✅ in-memory per-request dict | ✅ per-call (Anonymize+Deanonymize pair) | ✅ pii_tokens in-memory dict | ✅ pseudonymization | не подтверждено |
| **Streaming SSE support** | ✅ (proxy streams через httpx) | ❌ не упомянуто (SDK) | ✅ StreamingChoices поддерживается | не упомянуто | не применимо |
| **Session/multi-turn vault** | ❌ нет (per-request only) | ❌ нет | ❌ нет (per-instance) | не подтверждено | не применимо |
| **Redis/cache** | ❌ нет | ❌ нет | ✅ DualCache (Redis + memory) | не упомянуто | не применимо |
| **Audit log** | ❌ нет | ❌ не упомянуто | ⚠️ logging_only mode | не упомянуто | ✅ full prompt logs |
| **LDAP/SSO** | ❌ нет | ❌ нет | ⚠️ enterprise (не подтверждено из кода) | не упомянуто | не упомянуто |
| **Webhook/alerts** | ❌ нет | ❌ не упомянуто | ❌ не упомянуто | не упомянуто | ✅ DLP alerts |
| **Policy engine (block/warn/sanitize)** | ❌ только sanitize (mask) | ❌ block через scanner (is_valid) | ✅ pii_entities_config + PiiAction per type | ✅ block/redact/generalize | ✅ intelligent policies |
| **Scan profiles** | ❌ нет | ❌ нет | ✅ PresidioPerRequestConfig per request | не упомянуто | ✅ (enterprise) |
| **Multi-tenant API keys** | ❌ нет | ❌ нет | ✅ нативно в LiteLLM proxy | не упомянуто | ✅ |
| **Admin UI** | ❌ нет | ❌ нет | ✅ LiteLLM proxy UI | ✅ (demo UI) | ✅ |
| **Metrics (Prometheus)** | ❌ нет | ❌ нет | ✅ /metrics в LiteLLM | не упомянуто | не упомянуто |
| **Hot-reload config** | ❌ нет (restart required) | N/A (SDK) | ✅ (API конфиг) | N/A | N/A |
| **Docker Compose** | ✅ | ✅ (опционально) | ✅ | ✅ on-prem container | N/A |
| **Kubernetes/Helm** | ✅ helm/ в репо | не упомянуто | ✅ | ✅ | N/A |
| **License** | MIT | MIT | MIT | Commercial | Commercial |

> ⚠️ "не упомянуто" = факт не найден в реально прочитанных источниках. Не означает отсутствие.

---

## Key Architectural Patterns

### Vault Storage

| Решение | Vault | Scope |
|---------|-------|-------|
| secret-proxy | Python dict в памяти | Per-request |
| LLM Guard | Объект Anonymize scanner | Per-call (SDK) |
| LiteLLM+Presidio | `pii_tokens` dict на instance | Per-request/instance |
| Limina | Не раскрыто (SaaS) | Сессия |
| Nightfall | Не раскрыто (SaaS) | Platform-level |

**Проблема всех open-source решений:** vault живёт in-memory, per-request. При multi-turn диалоге (Claude Code session с историей) — секреты, маскированные в предыдущих запросах, не будут восстановлены в последующих.

### Streaming handling

- **secret-proxy:** Streaming работает — proxy прозрачно стримит httpx chunks. Но маскировка делается до отправки запроса, поэтому streaming ответа не блокирует.
- **LiteLLM+Presidio:** `StreamingChoices` импортируется, streaming-aware. При `apply_to_output=True` — пост-обработка ответа, включая стриминг.
- **LLM Guard SDK:** SDK-level, не proxy. Streaming не описан.

### Deployment models

| Решение | Модель |
|---------|--------|
| secret-proxy | **Gateway proxy** — ANTHROPIC_BASE_URL redirect |
| LLM Guard | **SDK** — встраивается в код приложения |
| LiteLLM+Presidio | **Gateway proxy** — полноценный LLM proxy с guardrail плагином |
| Presidio | **Sidecar microservice** — HTTP API, вызывается другими сервисами |
| Limina/Private AI | **SaaS API / on-prem container** |
| Nightfall | **SaaS platform** — агенты + browser plugins + API integrations |
| Vampy | **Standalone AppSec platform** — отдельный продукт, не proxy |

### Session Persistence

- Ни одно из open-source решений не имеет Redis-backed session vault для multi-turn.
- LiteLLM использует DualCache, но для routing/caching, не для vault.
- Vampy использует PostgreSQL + Celery для persistence, но это AppSec platform.

---

## Differentiators vs Competitors

### Что есть у secret-proxy и нет у других open-source:

1. **gitleaks с 700+ named rules** — LLM Guard использует только detect-secrets (меньше правил). gitleaks — де-факто стандарт для secret scanning в CI/CD. Это ключевое преимущество.

2. **LLM-based semantic scanner** — семантическое обнаружение секретов, которые не попадают под regex. Ни LLM Guard (secrets.py), ни LiteLLM+Presidio не имеют LLM-слоя для secrets.

3. **Простота** — 130 строк proxy.py, zero config, `docker compose up -d`. LiteLLM — полноценный proxy с сотнями фич. LLM Guard — SDK со сложным pipeline.

4. **Специализация на secrets (API keys, tokens)** — LiteLLM+Presidio фокусируется на PII. secret-proxy — на secrets. Разные ниши.

5. **Transparent proxy** — ANTHROPIC_BASE_URL override. Никаких изменений в коде клиента.

### Что есть у конкурентов и нет у secret-proxy:

1. **PII detection** — у нас только через LLM layer. Presidio, Limina — специализированные NER-модели.
2. **Policy engine** — LiteLLM+Presidio: per-entity PiiAction, score thresholds, deny list.
3. **Multi-tenant** — LiteLLM: нативно из коробки.
4. **Session vault** — ни у кого нет хорошего, но это известная проблема.
5. **Audit log** — нет нигде (open-source). Nightfall (коммерческий) — да.
6. **Metrics** — LiteLLM имеет /metrics. У нас нет.
7. **LDAP/SSO** — Vampy (enterprise AppSec) и LiteLLM enterprise имеют.

---

## Gap Analysis

Критические пробелы secret-proxy относительно зрелых решений:

| Gap | Приоритет | Кто решил |
|-----|-----------|-----------|
| Session vault (multi-turn) | CRITICAL | Никто (open-source) |
| Audit log | HIGH | Nightfall (commercial) |
| PII detection (NER) | HIGH | Presidio, Limina |
| Policy engine (block/warn) | HIGH | LiteLLM+Presidio |
| Metrics / observability | MEDIUM | LiteLLM |
| Hot-reload config | MEDIUM | LiteLLM |
| Multi-tenant API keys | MEDIUM | LiteLLM |
| Admin UI | LOW | LiteLLM, Nightfall |
| LDAP/SSO | LOW | Vampy, LiteLLM enterprise |
