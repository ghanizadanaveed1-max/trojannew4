#!/bin/bash
set -euo pipefail
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
clear
echo -e "${CYAN}${BOLD}GHANIZADA USER MANAGER v6 • CLOUD RUN${RESET}"
PROJECT_ID=$(gcloud config get-value project 2>/dev/null || true)
if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" = "(unset)" ]; then read -rp "Project ID: " PROJECT_ID; gcloud config set project "$PROJECT_ID"; fi
read -rp "Region [us-central1]: " REGION; REGION=${REGION:-us-central1}
read -rp "Service name [ghanizada-trojan]: " SERVICE_NAME; SERVICE_NAME=${SERVICE_NAME:-ghanizada-trojan}
echo "[1] 1 vCPU / 1Gi"; echo "[2] 2 vCPU / 4Gi (recommended)"; echo "[3] 4 vCPU / 8Gi"; read -rp "Choice [2]: " CHOICE; CHOICE=${CHOICE:-2}
case "$CHOICE" in 1) CPU=1; MEMORY=1Gi;; 3) CPU=4; MEMORY=8Gi;; *) CPU=2; MEMORY=4Gi;; esac
for API in run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com storage.googleapis.com; do
  gcloud services enable "$API" --project="$PROJECT_ID" >/dev/null || true
done
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -f "$SCRIPT_DIR/Dockerfile" ]; then echo -e "${RED}[!] Dockerfile not found in $SCRIPT_DIR${RESET}"; exit 1; fi
if [ ! -f "$SCRIPT_DIR/server.py" ] || [ ! -f "$SCRIPT_DIR/config.json" ]; then echo -e "${RED}[!] Required project files missing.${RESET}"; exit 1; fi
IMAGE="gcr.io/$PROJECT_ID/$SERVICE_NAME"
BUCKET="ghanizada-${PROJECT_ID}-users"
if [ ${#BUCKET} -gt 63 ]; then BUCKET="ghanizada-$(echo -n "$PROJECT_ID" | sha256sum | cut -c1-24)-users"; fi

echo -e "${YELLOW}Preparing persistent storage: gs://$BUCKET${RESET}"
if ! gcloud storage buckets describe "gs://$BUCKET" --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud storage buckets create "gs://$BUCKET" --project="$PROJECT_ID" --location="$REGION" --uniform-bucket-level-access >/dev/null || true
fi
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
RUNTIME_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
if gcloud storage buckets describe "gs://$BUCKET" --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" --member="serviceAccount:$RUNTIME_SA" --role="roles/storage.objectAdmin" >/dev/null || echo -e "${YELLOW}[!] Could not grant bucket access; local fallback will be used.${RESET}"
  PERSIST_BUCKET_ENV="$BUCKET"
else
  echo -e "${YELLOW}[!] Bucket unavailable. User data will use local fallback only.${RESET}"
  PERSIST_BUCKET_ENV=""
fi

echo -e "${YELLOW}Building image from: $SCRIPT_DIR${RESET}"
gcloud builds submit "$SCRIPT_DIR" --tag "$IMAGE" --project="$PROJECT_ID"

# Keep the existing persistent admin password on upgrades. Only generate one for a new deployment.
ADMIN_KEY=""
if [ -n "$PERSIST_BUCKET_ENV" ] && gcloud storage cat "gs://$PERSIST_BUCKET_ENV/ghanizada/admin.json" >/tmp/ghanizada-admin.json 2>/dev/null; then
  echo -e "${GREEN}[✓] Existing admin password record found; it will be preserved.${RESET}"
else
  ADMIN_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
  echo -e "${YELLOW}[!] New admin password generated. Save it now.${RESET}"
fi
ENV_VARS="SNI=firebase-settings.crashlytics.com"
if [ -n "$PERSIST_BUCKET_ENV" ]; then ENV_VARS="$ENV_VARS,PERSIST_BUCKET=$PERSIST_BUCKET_ENV"; fi
if [ -n "$ADMIN_KEY" ]; then ENV_VARS="$ENV_VARS,OWNER_KEY=$ADMIN_KEY"; fi

gcloud run deploy "$SERVICE_NAME" \
  --image "$IMAGE" --platform managed --region "$REGION" --allow-unauthenticated \
  --port 8080 --cpu "$CPU" --memory "$MEMORY" --timeout 3600 \
  --min-instances 0 --max-instances 1 --set-env-vars "$ENV_VARS" --project "$PROJECT_ID"

SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --region "$REGION" --project "$PROJECT_ID" --format='value(status.url)')
HOST=${SERVICE_URL#https://}
echo
echo -e "${GREEN}${BOLD}DEPLOYMENT SUCCESSFUL${RESET}"
echo "============================================"
echo "Dashboard: $SERVICE_URL"
echo "Host:      $HOST"
echo "Port:      443"
echo "Trojan:    /ws/Ghanizada"
echo "VLESS:     /ws/VLESS-Ghanizada"
echo "VMess:     /ws/VMess-Ghanizada"
echo "Users:     none pre-configured"
echo "Storage:   ${PERSIST_BUCKET_ENV:-local fallback}"
echo "============================================"
if [ -n "$ADMIN_KEY" ]; then
  echo -e "${YELLOW}ADMIN PASSWORD (SAVE THIS):${RESET} $ADMIN_KEY"
else
  echo "Admin password: existing password preserved"
fi
echo
echo "Open the Dashboard URL in your browser, then log in."
