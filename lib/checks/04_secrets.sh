#!/usr/bin/env bash
# Check: secrets & sensitive data exposure
# SPDX-License-Identifier: AGPL-3.0-or-later

section "04 — Secrets & sensitive data"

# Env var secrets (heuristic names)
SENSITIVE_ENV=0
while IFS='=' read -r name value || [[ -n "$name" ]]; do
  [[ -z "$name" ]] && continue
  upper="$(echo "$name" | tr '[:lower:]' '[:upper:]')"
  case "$upper" in
    *PASSWORD*|*SECRET*|*TOKEN*|*API_KEY*|*APIKEY*|*PRIVATE_KEY*|*AWS_SECRET*|*AZURE_*|*GCP_*|*DATABASE_URL*)
      # Do not print values
      signal_found "secrets.env.${name}" "HIGH" \
        "Environment variable name looks sensitive: ${name} (value redacted, len=${#value})" \
        "Prefer volume-mounted secrets or secretKeyRef with least exposure; rotate if leaked in logs" \
        "developer,security-eng"
      SENSITIVE_ENV=1
      ;;
  esac
done < <(env || true)

if [[ "$SENSITIVE_ENV" -eq 0 ]]; then
  signal_not_found "secrets.env" "No obviously sensitive env var names detected"
fi

# AWS/GCP/Azure credential files
for f in \
  "${HOME}/.aws/credentials" \
  "${AWS_SHARED_CREDENTIALS_FILE:-}" \
  "${GOOGLE_APPLICATION_CREDENTIALS:-}" \
  "${HOME}/.config/gcloud/application_default_credentials.json" \
  "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" \
  "/var/run/secrets/azure/tokens/azure-identity-token"
do
  [[ -z "$f" ]] && continue
  if file_readable "$f"; then
    signal_found "secrets.cred_file" "HIGH" \
      "Credential file readable: ${f}" \
      "Scope cloud identity tightly; avoid long-lived keys in pods" \
      "security-eng,red-team"
  fi
done

# Cloud metadata reachability (IMDSv1 style)
META="$(http_get "http://169.254.169.254/latest/meta-data/" 2)"
if [[ -n "$META" ]]; then
  signal_found "cloud.metadata_aws" "HIGH" \
    "AWS EC2 metadata service reachable (IMDS)" \
    "Enforce IMDSv2 hop limit=1; use IRSA/EKS Pod Identity instead of instance role when possible" \
    "red-team,security-eng"
else
  signal_not_found "cloud.metadata_aws" "AWS IMDS not reachable from this foothold"
fi

GCP_META="$(http_get "http://169.254.169.254/computeMetadata/v1/" 2)"
# GCP needs Metadata-Flavor header — try curl specially
if command -v curl >/dev/null 2>&1; then
  GCP_META="$(curl -sS -m 2 -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/ 2>/dev/null || true)"
fi
if [[ -n "$GCP_META" ]]; then
  signal_found "cloud.metadata_gcp" "HIGH" \
    "GCP metadata service reachable" \
    "Use Workload Identity; restrict metadata exposure" \
    "red-team,security-eng"
else
  signal_not_found "cloud.metadata_gcp" "GCP metadata not reachable"
fi

AZ_META="$(http_get "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2)"
if command -v curl >/dev/null 2>&1; then
  AZ_META="$(curl -sS -m 2 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null || true)"
fi
if [[ -n "$AZ_META" ]] && echo "$AZ_META" | grep -q 'compute\|subscriptionId\|vmId'; then
  signal_found "cloud.metadata_azure" "HIGH" \
    "Azure Instance Metadata Service reachable" \
    "Use AAD Workload Identity / managed identity with least privilege" \
    "red-team,security-eng"
else
  signal_not_found "cloud.metadata_azure" "Azure IMDS not reachable (or not Azure)"
fi

# kubeconfig lying around
for kc in "${KUBECONFIG:-}" "${HOME}/.kube/config" /kubeconfig /etc/kubernetes/admin.conf /etc/kubernetes/super-admin.conf; do
  [[ -z "$kc" ]] && continue
  if file_readable "$kc"; then
    signal_found "secrets.kubeconfig" "CRITICAL" \
      "kubeconfig readable at ${kc}" \
      "Remove kubeconfigs from workloads; use projected SA tokens" \
      "red-team,security-eng"
  fi
done

# etcd / serviceaccount key paths (node compromise indicators)
for f in /etc/kubernetes/pki/apiserver.key /etc/kubernetes/pki/sa.key /var/lib/etcd; do
  if [[ -e "$f" ]]; then
    signal_found "secrets.control_plane_path" "CRITICAL" \
      "Control-plane sensitive path visible: ${f}" \
      "This foothold appears host/node-level — isolate immediately" \
      "red-team,security-eng"
  fi
done

true
