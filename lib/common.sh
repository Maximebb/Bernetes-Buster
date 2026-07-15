#!/usr/bin/env bash
# Shared helpers for Bernetes-Buster
# SPDX-License-Identifier: AGPL-3.0-or-later

# Colors (disabled by bb_disable_color)
RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[1;34m'
CYAN=$'\033[1;36m'
MAGENTA=$'\033[1;35m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
RESET=$'\033[0m'

bb_disable_color() {
  RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; MAGENTA=""; BOLD=""; DIM=""; RESET=""
}

die() { echo "${RED}[!]${RESET} $*" >&2; exit 1; }

quiet_echo() {
  if [[ "${BBUSTER_QUIET:-0}" -eq 1 ]]; then
    return 0
  fi
  echo "$@"
}

info()    { quiet_echo "${BLUE}[*]${RESET} $*"; }
ok()      { quiet_echo "${GREEN}[+]${RESET} $*"; }
warn()    { quiet_echo "${YELLOW}[!]${RESET} $*"; }
bad()     { quiet_echo "${RED}[-]${RESET} $*"; }
tip()     { quiet_echo "${CYAN}[>]${RESET} $*"; }

banner() {
  [[ "${BBUSTER_QUIET:-0}" -eq 1 ]] && return 0
  cat <<EOF
${MAGENTA}${BOLD}
 ____                      _                ____            _
| __ )  ___ _ __ ___   ___| |_ ___  ___    | __ ) _   _ ___| |_ ___ _ __
|  _ \\ / _ \\ '__| '_ \\ / _ \\ __/ _ \\/ __|   |  _ \\| | | / __| __/ _ \\ '__|
| |_) |  __/ |  | | | |  __/ ||  __/\\__ \\   | |_) | |_| \\__ \\ ||  __/ |
|____/ \\___|_|  |_| |_|\\___|\\__\\___||___/   |____/ \\__,_|___/\\__\\___|_|
${RESET}${DIM}Kubernetes misconfiguration explorer — read-only by default${RESET}
EOF
}

section() {
  [[ "${BBUSTER_QUIET:-0}" -eq 1 ]] && return 0
  echo
  quiet_echo "${BOLD}${CYAN}════════════════════════════════════════════════════════════${RESET}"
  quiet_echo "${BOLD}${CYAN}  $*${RESET}"
  quiet_echo "${BOLD}${CYAN}════════════════════════════════════════════════════════════${RESET}"
}

bb_validate_profile() {
  case "$1" in
    developer|security-eng|red-team) ;;
    *) die "Unknown profile: $1 (developer|security-eng|red-team)" ;;
  esac
}

# Return 0 if path is readable and non-empty
file_readable() { [[ -r "$1" ]] && [[ -s "$1" ]]; }

# Safe HTTP GET with timeout (uses curl if present)
http_get() {
  local url="$1"
  local timeout="${2:-3}"
  if command -v curl >/dev/null 2>&1; then
    curl -sS -m "$timeout" --connect-timeout "$timeout" "$url" 2>/dev/null || true
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T "$timeout" -O - "$url" 2>/dev/null || true
  fi
}

# In-cluster API request using mounted SA token
k8s_api() {
  local path="$1"
  local token_file="/var/run/secrets/kubernetes.io/serviceaccount/token"
  local ca_file="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
  local host="${KUBERNETES_SERVICE_HOST:-}"
  local port="${KUBERNETES_SERVICE_PORT_HTTPS:-443}"

  if [[ -z "$host" ]] || ! file_readable "$token_file"; then
    return 1
  fi
  local token
  token="$(cat "$token_file")"
  if command -v curl >/dev/null 2>&1; then
    curl -sS -m 8 --connect-timeout 5 \
      --cacert "$ca_file" \
      -H "Authorization: Bearer ${token}" \
      "https://${host}:${port}${path}" 2>/dev/null || return 1
  else
    return 1
  fi
}

k8s_can_i() {
  local verb="$1"
  local resource="$2"
  local ns="${3:-}"
  if [[ -z "${KUBECTL:-}" ]]; then
    echo "unknown"
    return 0
  fi
  local args=(--request-timeout="${KUBECTL_REQUEST_TIMEOUT:-5s}" auth can-i "$verb" "$resource" --quiet)
  [[ -n "$ns" ]] && args+=(-n "$ns")
  if "${KUBECTL}" "${args[@]}" >/dev/null 2>&1; then
    echo "yes"
  else
    echo "no"
  fi
}

# kubectl wrapper with request timeout
kctl() {
  if [[ -z "${KUBECTL:-}" ]]; then
    return 1
  fi
  "${KUBECTL}" --request-timeout="${KUBECTL_REQUEST_TIMEOUT:-5s}" "$@"
}

in_cluster() {
  [[ -n "${KUBERNETES_SERVICE_HOST:-}" ]] && [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]]
}

# Capability check helpers
has_cap() {
  local cap="$1"
  if [[ -r /proc/self/status ]]; then
    grep -qiE "Cap(Eff|Prm|Bnd):.*${cap}" /proc/self/status 2>/dev/null && return 0
  fi
  if command -v capsh >/dev/null 2>&1; then
    capsh --print 2>/dev/null | grep -qi "$cap" && return 0
  fi
  # Fallback: decode CapEff hex if python available is overkill; use busybox style
  return 1
}

cap_eff_hex() {
  awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null || echo ""
}

# Decode whether all caps (approx: CapEff == 0000003fffffffff on 64-bit)
is_privileged_caps() {
  local hex
  hex="$(cap_eff_hex)"
  [[ -z "$hex" ]] && return 1
  # Common privileged masks
  [[ "$hex" == *"ffffffff" ]] || [[ "$hex" == "0000003fffffffff" ]] || [[ "$hex" == "000001ffffffffff" ]]
}
