#!/usr/bin/env bash
# Check: network exposure
# SPDX-License-Identifier: AGPL-3.0-or-later

section "05 — Network exposure"

# kubelet ports / unauthenticated kubelet is classic (hostNetwork footholds)
if in_cluster && command -v curl >/dev/null 2>&1; then
  for url in \
    "https://127.0.0.1:10250/pods" \
    "http://127.0.0.1:10255/pods" \
    "https://127.0.0.1:10250/runningpods/"
  do
    code="$(curl -sk --connect-timeout 1 -m 2 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
    code="${code:-000}"
    if [[ "$code" == "200" ]]; then
      signal_found "network.kubelet_open" "CRITICAL" \
        "Kubelet endpoint responded HTTP ${code}: ${url}" \
        "Disable anonymous kubelet auth; restrict kubelet ports; set authentication.anonymous.enabled=false" \
        "red-team,security-eng"
    elif [[ "$code" == "401" || "$code" == "403" ]]; then
      signal_info "network.kubelet_reachable" "FOUND" "Kubelet reachable (${code}) at ${url}"
    fi
  done
else
  signal_skipped "network.kubelet_probe" "Skipped kubelet localhost probe (not in-cluster or no curl)"
fi

# API server from inside
if in_cluster; then
  ver="$(k8s_api '/version' || true)"
  if echo "$ver" | grep -q 'gitVersion'; then
    signal_info "network.apiserver" "FOUND" "API server reachable: $(echo "$ver" | tr -d '\n' | head -c 160)"
  else
    signal_found "network.apiserver" "MEDIUM" \
      "In-cluster but API /version failed — check DNS/network policies" \
      "Ensure kube-api access is intentional and NetworkPolicy denies by default" \
      "security-eng"
  fi
fi

# Listening sockets (ss/netstat)
listens=""
if command -v ss >/dev/null 2>&1; then
  listens="$(ss -lntu 2>/dev/null | awk 'NR>1{print $5}' | sort -u | head -40 || true)"
elif command -v netstat >/dev/null 2>&1; then
  listens="$(netstat -lntu 2>/dev/null | awk 'NR>2{print $4}' | sort -u | head -40 || true)"
fi
listens="${listens:-}"

if [[ -n "$listens" ]]; then
  signal_info "network.listen_ports" "FOUND" "Listening endpoints: $(echo "$listens" | tr '\n' ' ')"
  if echo "$listens" | grep -Eq ':2375|:2376|:10250|:10255|:4194|:6443'; then
    signal_found "network.sensitive_listen" "HIGH" \
      "Sensitive service ports appear to be listening inside this foothold" \
      "Audit why privileged ports are exposed in this pod/network namespace" \
      "red-team,security-eng"
  else
    signal_not_found "network.sensitive_listen" "No classic sensitive ports in listen list"
  fi
else
  signal_skipped "network.listen_ports" "ss/netstat not available"
fi

# DNS to kubernetes.default
if command -v getent >/dev/null 2>&1; then
  if getent hosts kubernetes.default.svc.cluster.local >/dev/null 2>&1; then
    signal_info "network.cluster_dns" "FOUND" "Cluster DNS resolves kubernetes.default.svc.cluster.local"
  else
    signal_not_found "network.cluster_dns" "Could not resolve kubernetes.default.svc.cluster.local"
  fi
else
  signal_skipped "network.cluster_dns" "getent not available"
fi

# Services enumeration (if permitted)
if [[ -n "${KUBECTL:-}" ]]; then
  svc="$(kctl get svc -A -o wide 2>/dev/null || true)"
  if [[ -n "$svc" ]]; then
    np="$(echo "$svc" | awk '$2 ~ /NodePort|LoadBalancer/ {print $1"/"$2"/"$3"/"$6}' | head -20)"
    if [[ -n "$np" ]]; then
      signal_found "network.exposed_services" "MEDIUM" \
        "NodePort/LoadBalancer services present: $(echo "$np" | tr '\n' '; ')" \
        "Prefer ClusterIP + Ingress with auth; limit NodePort exposure" \
        "developer,security-eng"
    else
      signal_not_found "network.exposed_services" "No NodePort/LoadBalancer services visible"
    fi
  else
    signal_skipped "network.exposed_services" "Cannot list services (RBAC or kubectl issue)"
  fi

  # NetworkPolicies existence
  npcount="$(kctl get networkpolicies -A --no-headers 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "${npcount:-0}" -eq 0 ]]; then
    # Distinguish empty vs forbidden
    if kctl get networkpolicies -A >/dev/null 2>&1; then
      signal_found "network.no_networkpolicies" "MEDIUM" \
        "Zero NetworkPolicies visible cluster-wide" \
        "Adopt default-deny NetworkPolicies per namespace" \
        "developer,security-eng"
    else
      signal_skipped "network.no_networkpolicies" "Cannot list NetworkPolicies"
    fi
  else
    signal_not_found "network.no_networkpolicies" "NetworkPolicies present (count=${npcount})"
  fi
fi

true
