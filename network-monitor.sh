#!/bin/bash
SERVICE_NAME="${1:-ghanizada-trojan}"; REGION="${2:-us-central1}"
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --region="$REGION" --format='value(status.url)' 2>/dev/null) || exit 1
while true; do printf '%s ' "$(date '+%Y-%m-%d %H:%M:%S')"; curl -sS -o /dev/null -w 'HTTP %{http_code} %{time_total}s\n' --max-time 10 "$SERVICE_URL/healthz" || echo DOWN; sleep 10; done
