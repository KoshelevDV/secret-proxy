FROM zricethezav/gitleaks:v8.30.0 AS gitleaks

FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
WORKDIR /app

# Copy gitleaks binary
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks

COPY --from=builder /install /usr/local
COPY . .

EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:4000/health')"
CMD ["python", "proxy.py"]
