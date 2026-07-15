#!/usr/bin/env bash
# Check: admission / cluster posture (security-eng)
# SPDX-License-Identifier: AGPL-3.0-or-later

section "07 — Cluster posture & admission"

if [[ -z "${KUBECTL:-}" ]]; then
  signal_skipped "posture.*" "kubectl not available"
  return 0 2>/dev/null || true
fi

# Pod Security admission labels on namespaces
ns="$(kctl get ns -o json 2>/dev/null || true)"
if [[ -n "$ns" ]]; then
  if echo "$ns" | grep -q 'pod-security.kubernetes.io/enforce'; then
    signal_not_found "posture.psa_missing" "Some namespaces have pod-security enforce labels"
    signal_info "posture.psa" "FOUND" "Pod Security Admission labels detected on namespaces"
  else
    signal_found "posture.psa_missing" "MEDIUM" \
      "No pod-security.kubernetes.io/enforce labels seen on namespaces" \
      "Enable Pod Security Admission (enforce: baseline/restricted)" \
      "security-eng,developer"
  fi
else
  signal_skipped "posture.psa" "Cannot list namespaces"
fi

# Admission webhooks present?
vwh="$(kctl get validatingwebhookconfigurations --no-headers 2>/dev/null | wc -l | tr -d ' ')"
mwh="$(kctl get mutatingwebhookconfigurations --no-headers 2>/dev/null | wc -l | tr -d ' ')"
if kctl get validatingwebhookconfigurations >/dev/null 2>&1; then
  if [[ "${vwh:-0}" -eq 0 && "${mwh:-0}" -eq 0 ]]; then
    signal_found "posture.no_admission_webhooks" "LOW" \
      "No validating/mutating webhook configurations visible" \
      "Consider policy engines (Kyverno/Gatekeeper) for enforce-time controls" \
      "security-eng"
  else
    signal_not_found "posture.no_admission_webhooks" "Webhooks present (validating=${vwh}, mutating=${mwh})"
  fi
else
  signal_skipped "posture.admission_webhooks" "Cannot list webhook configurations"
fi

# anonymous access / bootstrap tokens left around are hard; check ClusterRoleBinding system:anonymous
anon="$(kctl get clusterrolebinding -o json 2>/dev/null || true)"
if [[ -n "$anon" ]]; then
  if echo "$anon" | grep -q 'system:anonymous'; then
    signal_found "posture.anonymous_binding" "HIGH" \
      "ClusterRoleBinding references system:anonymous" \
      "Remove anonymous bindings; disable anonymous API auth if unused" \
      "security-eng,red-team"
  else
    signal_not_found "posture.anonymous_binding" "No system:anonymous subject spotted in ClusterRoleBindings"
  fi

  if echo "$anon" | grep -q 'system:unauthenticated'; then
    signal_found "posture.unauthenticated_binding" "HIGH" \
      "ClusterRoleBinding references system:unauthenticated" \
      "Remove unauthenticated grants" \
      "security-eng,red-team"
  else
    signal_not_found "posture.unauthenticated_binding" "No system:unauthenticated subject spotted"
  fi
fi

# Nodes NotReady
if kctl get nodes >/dev/null 2>&1; then
  notready="$(kctl get nodes --no-headers 2>/dev/null | awk '$2 !~ /Ready/ {print $1,$2}' | head -10)"
  if [[ -n "$notready" ]]; then
    signal_found "posture.nodes_notready" "MEDIUM" \
      "Nodes not Ready: $(echo "$notready" | tr '\n' '; ')" \
      "Investigate node health — NotReady can indicate compromise or outage" \
      "security-eng"
  else
    signal_not_found "posture.nodes_notready" "All listable nodes report Ready"
  fi
fi

true
