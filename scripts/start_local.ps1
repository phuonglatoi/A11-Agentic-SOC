$ErrorActionPreference = "Stop"

if (-not $env:SOC_API_KEY) { $env:SOC_API_KEY = "change-me-ingest-key" }
if (-not $env:SOC_ADMIN_TOKEN) { $env:SOC_ADMIN_TOKEN = "change-me-admin-token" }
if (-not $env:DATABASE_URL) { $env:DATABASE_URL = "sqlite:///./data/soc.db" }

python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
