#!/usr/bin/env bash
# Check: workloads hygiene (developer-oriented + security)
# SPDX-License-Identifier: AGPL-3.0-or-later

section "06 — Workload hygiene"

if [[ -z "${KUBECTL:-}" ]]; then
  signal_skipped "workloads.*" "kubectl not available — skipping workload scans"
  return 0 2>/dev/null || true
fi

# Privileged pods
priv="$(kctl get pods -A -o json 2>/dev/null || true)"
if [[ -z "$priv" ]]; then
  signal_skipped "workloads.pods" "Cannot list pods"
else
  # Use grep heuristics on json to avoid jq dependency
  if echo "$priv" | grep -q '"privileged"[[:space:]]*:[[:space:]]*true'; then
    signal_found "workloads.privileged_pods" "CRITICAL" \
      "One or more pods have privileged: true" \
      "Remove privileged containers; use capabilities drop + specific adds" \
      "security-eng,developer"
  else
    signal_not_found "workloads.privileged_pods" "No privileged: true found in listable pods"
  fi

  if echo "$priv" | grep -q '"hostNetwork"[[:space:]]*:[[:space:]]*true'; then
    signal_found "workloads.host_network_pods" "HIGH" \
      "Pods with hostNetwork: true discovered" \
      "Limit hostNetwork to system components only" \
      "security-eng"
  else
    signal_not_found "workloads.host_network_pods" "No hostNetwork pods visible"
  fi

  if echo "$priv" | grep -q '"hostPID"[[:space:]]*:[[:space:]]*true'; then
    signal_found "workloads.host_pid_pods" "HIGH" \
      "Pods with hostPID: true discovered" \
      "Avoid hostPID except for tightly controlled agents" \
      "security-eng"
  else
    signal_not_found "workloads.host_pid_pods" "No hostPID pods visible"
  fi

  if echo "$priv" | grep -q 'docker.sock'; then
    signal_found "workloads.docker_sock_mount" "CRITICAL" \
      "Pod volume references docker.sock" \
      "Remove docker.sock mounts from workloads" \
      "security-eng,red-team"
  else
    signal_not_found "workloads.docker_sock_mount" "No docker.sock mounts spotted in pod JSON"
  fi

  # latest image tag heuristic
  latest_count="$(echo "$priv" | grep -oE '"image"[[:space:]]*:[[:space:]]*"[^"]+:latest"' | wc -l | tr -d ' ')"
  if [[ "${latest_count:-0}" -gt 0 ]]; then
    signal_found "workloads.image_latest" "LOW" \
      "Found ${latest_count} container image(s) using :latest" \
      "Pin digests or immutable tags for deploy reproducibility" \
      "developer"
  else
    signal_not_found "workloads.image_latest" "No :latest image tags spotted in listable pods"
  fi
fi

# Default SA overuse
pods_default_sa="$(kctl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"|"}{.spec.serviceAccountName}{"\n"}{end}' 2>/dev/null || true)"
if [[ -n "$pods_default_sa" ]]; then
  def_count="$(echo "$pods_default_sa" | awk -F'|' '$2=="" || $2=="default" {c++} END{print c+0}')"
  if [[ "${def_count:-0}" -gt 0 ]]; then
    signal_found "workloads.default_sa" "LOW" \
      "${def_count} pods appear to use the default ServiceAccount" \
      "Create dedicated SAs per app with automountServiceAccountToken: false when unused" \
      "developer,security-eng"
  else
    signal_not_found "workloads.default_sa" "No pods clearly using default SA in listable set"
  fi
fi

# Missing resource limits (sample via jsonpath)
no_limits="$(kctl get pods -A -o json 2>/dev/null | grep -c '"limits"' || true)"
# Weak signal — only note info if we can list
if [[ -n "$priv" ]]; then
  signal_info "workloads.limits_hint" "INFO" \
    "Review resource requests/limits manually — automated absence detection requires deeper JSON walk"
fi

true
