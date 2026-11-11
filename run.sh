#!/usr/bin/env bash
# 本机直接启动（Docker 方式见 docker-compose.yml）
set -euo pipefail
cd "$(dirname "$0")"
exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
