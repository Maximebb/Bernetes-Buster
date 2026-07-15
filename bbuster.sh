#!/usr/bin/env bash
# Bernetes-Buster — LinPEAS-style Kubernetes misconfiguration explorer
# Copyright (C) 2026 Bernetes-Buster contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Run inside a pod/Job (or any shell with cluster API reachability) to collect
# FOUND / NOT FOUND signals for common K8s misconfigurations and privesc paths.
#
# Usage:
#   ./bbuster.sh                          # full scan, security-eng profile
#   ./bbuster.sh --profile developer
#   ./bbuster.sh --profile red-team
#   ./bbuster.sh --json /tmp/report.json
#   ./bbuster.sh --quiet --json -

set -euo pipefail

BBUSTER_VERSION="0.1.0"
BBUSTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
source "${BBUSTER_ROOT}/lib/common.sh"
# shellcheck source=lib/report.sh
source "${BBUSTER_ROOT}/lib/report.sh"

PROFILE="security-eng"
JSON_OUT=""
QUIET=0
NO_COLOR_FLAG=0
CHECKS_GLOB="*"

usage() {
  cat <<EOF
Bernetes-Buster v${BBUSTER_VERSION}
LinPEAS-style Kubernetes misconfiguration & privilege-escalation explorer.

Usage: $(basename "$0") [options]

Options:
  -p, --profile NAME     developer | security-eng | red-team (default: security-eng)
  -j, --json PATH        Write machine-readable JSON report (- for stdout)
  -q, --quiet            Suppress human-readable output (implies useful with --json)
      --no-color         Disable ANSI colors
      --checks GLOB      Only run matching check scripts (default: *)
  -h, --help             Show this help
  -V, --version          Show version

Profiles:
  developer      Fast, low-noise checks for manifest/runtime hygiene
  security-eng   Full read-only audit (default) — CIS-oriented signals
  red-team       Aggressive enumeration from a foothold (still read-only)

Deploy as a Kubernetes Job:
  kubectl apply -f deploy/rbac-readonly.yaml
  kubectl apply -f deploy/job.yaml
  kubectl logs -f job/bernetes-buster

License: GNU Affero General Public License v3.0 or later
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--profile) PROFILE="${2:?}"; shift 2 ;;
    -j|--json) JSON_OUT="${2:?}"; shift 2 ;;
    -q|--quiet) QUIET=1; shift ;;
    --no-color) NO_COLOR_FLAG=1; shift ;;
    --checks) CHECKS_GLOB="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -V|--version) echo "bbuster ${BBUSTER_VERSION}"; exit 0 ;;
    *) die "Unknown option: $1 (try --help)" ;;
  esac
done

export BBUSTER_PROFILE="$PROFILE"
export BBUSTER_QUIET="$QUIET"
if [[ "$NO_COLOR_FLAG" -eq 1 ]] || [[ ! -t 1 ]] || [[ "${NO_COLOR:-}" == "1" ]]; then
  bb_disable_color
fi

bb_validate_profile "$PROFILE"
report_init "$PROFILE" "$BBUSTER_VERSION"

banner
info "Profile: ${PROFILE} | Host: $(hostname) | Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
section "Environment"

# Detect tooling
if [[ "${BBUSTER_SKIP_API:-0}" == "1" ]]; then
  KUBECTL=""
elif command -v kubectl >/dev/null 2>&1; then
  KUBECTL="kubectl"
elif command -v oc >/dev/null 2>&1; then
  KUBECTL="oc"
else
  KUBECTL=""
fi
export KUBECTL

if [[ -n "$KUBECTL" ]]; then
  # Keep API calls from hanging forever on bad kubeconfigs
  export KUBECTL_REQUEST_TIMEOUT="${KUBECTL_REQUEST_TIMEOUT:-5s}"
  kver="$("${KUBECTL}" --request-timeout="${KUBECTL_REQUEST_TIMEOUT}" version --client -o yaml 2>/dev/null | awk '/gitVersion:/{print $2; exit}' || true)"
  signal_info "kubectl_available" "FOUND" "Using ${KUBECTL} ${kver}"
else
  signal_info "kubectl_available" "NOT_FOUND" "No kubectl/oc in PATH (or BBUSTER_SKIP_API=1) — API checks use curl against the SA token when in-cluster"
fi

# Load profile knobs
# shellcheck disable=SC1090
source "${BBUSTER_ROOT}/profiles/${PROFILE}.sh"

# Run checks in order
shopt -s nullglob
if [[ "$CHECKS_GLOB" == "*" ]]; then
  CHECKS=( "${BBUSTER_ROOT}/lib/checks/"*.sh )
else
  CHECKS=( "${BBUSTER_ROOT}/lib/checks/"${CHECKS_GLOB} )
fi
IFS=$'\n' CHECKS=( $(printf '%s\n' "${CHECKS[@]}" | LC_ALL=C sort) )
unset IFS
shopt -u nullglob

if [[ ${#CHECKS[@]} -eq 0 ]]; then
  die "No checks matched glob: ${CHECKS_GLOB}"
fi

for check in "${CHECKS[@]}"; do
  [[ -f "$check" ]] || continue
  [[ "$(basename "$check")" == *.sh ]] || continue
  # shellcheck disable=SC1090
  source "$check"
done

report_summary

if [[ -n "$JSON_OUT" ]]; then
  report_write_json "$JSON_OUT"
fi

# Exit non-zero if any CRITICAL FOUND signals (CI-friendly)
if report_has_critical_findings; then
  exit 2
fi
exit 0
