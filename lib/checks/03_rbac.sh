#!/usr/bin/env bash
# Check: RBAC / dangerous API permissions
# SPDX-License-Identifier: AGPL-3.0-or-later

section "03 — RBAC & API permissions"

if [[ -z "${KUBECTL:-}" ]] && ! in_cluster; then
  signal_skipped "rbac.*" "No kubectl and not in-cluster — skipping RBAC checks"
  return 0 2>/dev/null || true
fi

NS="${BBUSTER_NAMESPACE:-default}"

# Dangerous permission matrix (verb resource)
declare -a DANGEROUS=(
  "create:pods:CRITICAL:Can create pods (escape via privileged pod)"
  "create:pods/exec:CRITICAL:Can exec into pods"
  "get:secrets:CRITICAL:Can read Secrets"
  "list:secrets:CRITICAL:Can list Secrets"
  "create:secrets:HIGH:Can create Secrets"
  "impersonate:users:CRITICAL:Can impersonate users"
  "impersonate:serviceaccounts:CRITICAL:Can impersonate ServiceAccounts"
  "create:serviceaccounts/token:HIGH:Can mint SA tokens"
  "create:rolebindings:CRITICAL:Can bind roles (self-escalate)"
  "create:clusterrolebindings:CRITICAL:Can bind cluster roles"
  "create:roles:HIGH:Can create Roles"
  "create:clusterroles:CRITICAL:Can create ClusterRoles"
  "create:daemonsets:HIGH:Can create DaemonSets (node-wide)"
  "create:cronjobs:HIGH:Can create CronJobs (persistence)"
  "create:deployments:MEDIUM:Can create Deployments"
  "create:nodes:CRITICAL:Can create/modify Nodes"
  "update:nodes:HIGH:Can update Nodes"
  "get:nodes:MEDIUM:Can get Nodes"
  "list:nodes:MEDIUM:Can list Nodes"
  "create:persistentvolumes:MEDIUM:Can create PVs"
  "get:configmaps:LOW:Can get ConfigMaps"
)

if [[ -n "${KUBECTL:-}" ]]; then
  # Full can-i --list snapshot
  can_list="$(kctl auth can-i --list -n "$NS" 2>/dev/null || true)"
  if [[ -n "$can_list" ]]; then
    signal_info "rbac.can_i_list" "FOUND" "auth can-i --list available for ns/${NS}"
    # Wildcard detection
    if echo "$can_list" | grep -qE '^\*\s+\*|^\*\s+\[\*\]'; then
      signal_found "rbac.wildcard_all" "CRITICAL" \
        "Wildcard verbs/resources granted (*) in namespace ${NS}" \
        "Replace * RBAC with least-privilege Role/ClusterRole" \
        "security-eng,red-team"
    else
      signal_not_found "rbac.wildcard_all" "No obvious *.* grant in can-i --list for ns/${NS}"
    fi
  else
    signal_info "rbac.can_i_list" "NOT_FOUND" "auth can-i --list failed or empty"
  fi

  for entry in "${DANGEROUS[@]}"; do
    IFS=':' read -r verb resource severity desc <<<"$entry"
    result="$(k8s_can_i "$verb" "$resource" "$NS")"
    id="rbac.${verb}.${resource//\//_}"
    if [[ "$result" == "yes" ]]; then
      signal_found "$id" "$severity" "$desc (ns/${NS})" \
        "Remove ${verb} on ${resource} from this identity unless required" \
        "security-eng,red-team"
    elif [[ "$result" == "no" ]]; then
      signal_not_found "$id" "No permission: ${verb} ${resource} in ns/${NS}"
    else
      signal_skipped "$id" "Could not evaluate ${verb} ${resource}"
    fi
  done

  # Cluster-scoped dangerous checks
  for pair in "list:namespaces" "get:clusterroles" "list:clusterrolebindings"; do
    IFS=':' read -r verb resource <<<"$pair"
    result="$(k8s_can_i "$verb" "$resource")"
    id="rbac.cluster.${verb}.${resource}"
    if [[ "$result" == "yes" ]]; then
      sev="MEDIUM"
      [[ "$resource" == "clusterrolebindings" ]] && sev="HIGH"
      signal_found "$id" "$sev" "Cluster-scoped ${verb} ${resource} allowed" \
        "Scope identity to needed namespaces only" \
        "security-eng,red-team"
    else
      signal_not_found "$id" "No cluster ${verb} ${resource}"
    fi
  done
else
  # curl SelfSubjectAccessReview would be ideal; approximate with list secrets
  resp="$(k8s_api "/api/v1/namespaces/${NS}/secrets?limit=1" || true)"
  if echo "$resp" | grep -q '"kind":"SecretList"'; then
    signal_found "rbac.get_secrets_api" "CRITICAL" \
      "API returned SecretList — identity can list secrets in ${NS}" \
      "Restrict secrets get/list; use External Secrets / sealed secrets patterns" \
      "red-team,security-eng"
  elif echo "$resp" | grep -qi 'Forbidden\|Unauthorized'; then
    signal_not_found "rbac.get_secrets_api" "Secrets list forbidden in ${NS}"
  else
    signal_skipped "rbac.get_secrets_api" "Ambiguous API response for secrets"
  fi
fi

true
