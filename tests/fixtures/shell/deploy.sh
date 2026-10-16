#!/usr/bin/env bash
# Deploy the harbour API.
# Usage: deploy.sh <env>
set -euo pipefail

source ./lib/common.sh
. ./lib/colors.sh

log() { echo "[deploy] $*"; }

function deploy_env {
  local env="$1"
  log "deploying to $env"   # TODO: add rollback
}

deploy_env "${1:-staging}"
