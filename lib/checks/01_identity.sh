#!/usr/bin/env bash
# Check: identity / foothold context
# SPDX-License-Identifier: AGPL-3.0-or-later

section "01 — Identity & foothold"

SA_DIR="/var/run/secrets/kubernetes.io/serviceaccount"
NS_FILE="${SA_DIR}/namespace"
TOKEN_FILE="${SA_DIR}/token"
CA_FILE="${SA_DIR}/ca.crt"

if in_cluster; then
  signal_found "k8s.in_cluster" "INFO" "Running inside a Kubernetes pod (API host ${KUBERNETES_SERVICE_HOST})" "" "all"
else
  signal_not_found "k8s.in_cluster" "Not running in-cluster (no SA token / KUBERNETES_SERVICE_HOST)"
fi

if file_readable "$NS_FILE"; then
  NS="$(tr -d '\n' < "$NS_FILE")"
  signal_info "k8s.namespace" "FOUND" "ServiceAccount namespace: ${NS}"
  export BBUSTER_NAMESPACE="$NS"
else
  signal_not_found "k8s.namespace" "Namespace file not mounted"
  export BBUSTER_NAMESPACE="${BBUSTER_NAMESPACE:-default}"
fi

if file_readable "$TOKEN_FILE"; then
  signal_found "k8s.sa_token_mounted" "MEDIUM" \
    "ServiceAccount token is automounted at ${TOKEN_FILE}" \
    "Set automountServiceAccountToken: false unless the pod needs API access" \
    "developer,security-eng"
  # Decode JWT payload (no verify) for audience/expiry hints
  if command -v base64 >/dev/null 2>&1; then
    payload="$(cut -d. -f2 < "$TOKEN_FILE" | tr '_-' '/+' | awk '{l=length($0)%4; printf "%s", $0; if(l) printf "%s", substr("====",1,4-l)}' | base64 -d 2>/dev/null || true)"
    if [[ -n "$payload" ]]; then
      signal_info "k8s.sa_token_claims" "INFO" "Token payload (truncated): ${payload:0:200}"
    fi
  fi
else
  signal_not_found "k8s.sa_token_mounted" "No ServiceAccount token mounted (good for least privilege)"
fi

if file_readable "$CA_FILE"; then
  signal_info "k8s.sa_ca" "FOUND" "API server CA bundle present"
else
  signal_not_found "k8s.sa_ca" "API CA not present"
fi

# Whoami via kubectl if available
if [[ -n "${KUBECTL:-}" ]]; then
  whoami="$(kctl auth whoami 2>/dev/null || true)"
  if [[ -n "$whoami" ]]; then
    signal_info "k8s.whoami" "FOUND" "$(echo "$whoami" | tr '\n' ' ' | head -c 300)"
  fi
fi

# Hostname / node hints from downward API env vars (common)
for var in HOSTNAME NODE_NAME POD_NAME POD_IP; do
  val="${!var:-}"
  if [[ -n "$val" ]]; then
    signal_info "env.${var}" "INFO" "${var}=${val}"
  fi
done

true
