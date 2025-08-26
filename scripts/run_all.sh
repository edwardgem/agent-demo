#!/usr/bin/env bash
set -euo pipefail
uvicorn gateway.main:app --reload --port 8000 &
PID=$!
sleep 1
python client/app_cli.py low
kill $PID
