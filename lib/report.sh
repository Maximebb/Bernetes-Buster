#!/usr/bin/env bash
# Report aggregation — FOUND / NOT_FOUND / INFO / SKIPPED signals
# SPDX-License-Identifier: AGPL-3.0-or-later

# Arrays of findings (bash 4+)
declare -a REPORT_IDS=()
declare -a REPORT_STATUSES=()
declare -a REPORT_SEVERITIES=()
declare -a REPORT_MESSAGES=()
declare -a REPORT_REMEDIATIONS=()
declare -a REPORT_AUDIENCES=()

REPORT_PROFILE=""
REPORT_VERSION=""
REPORT_STARTED=""
REPORT_CRITICAL_COUNT=0
REPORT_HIGH_COUNT=0
REPORT_MEDIUM_COUNT=0
REPORT_LOW_COUNT=0
REPORT_FOUND_COUNT=0
REPORT_NOT_FOUND_COUNT=0

report_init() {
  REPORT_PROFILE="$1"
  REPORT_VERSION="$2"
  REPORT_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  REPORT_IDS=()
  REPORT_STATUSES=()
  REPORT_SEVERITIES=()
  REPORT_MESSAGES=()
  REPORT_REMEDIATIONS=()
  REPORT_AUDIENCES=()
  REPORT_CRITICAL_COUNT=0
  REPORT_HIGH_COUNT=0
  REPORT_MEDIUM_COUNT=0
  REPORT_LOW_COUNT=0
  REPORT_FOUND_COUNT=0
  REPORT_NOT_FOUND_COUNT=0
}

# signal <id> <status> <severity> <message> [remediation] [audience]
# status: FOUND | NOT_FOUND | INFO | SKIPPED
# severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
# audience: all | developer | security-eng | red-team  (comma-ok)
_signal_record() {
  local id="$1" status="$2" severity="$3" message="$4"
  local remediation="${5:-}"
  local audience="${6:-all}"

  REPORT_IDS+=("$id")
  REPORT_STATUSES+=("$status")
  REPORT_SEVERITIES+=("$severity")
  REPORT_MESSAGES+=("$message")
  REPORT_REMEDIATIONS+=("$remediation")
  REPORT_AUDIENCES+=("$audience")

  case "$status" in
    FOUND) REPORT_FOUND_COUNT=$((REPORT_FOUND_COUNT + 1)) ;;
    NOT_FOUND) REPORT_NOT_FOUND_COUNT=$((REPORT_NOT_FOUND_COUNT + 1)) ;;
  esac

  if [[ "$status" == "FOUND" ]]; then
    case "$severity" in
      CRITICAL) REPORT_CRITICAL_COUNT=$((REPORT_CRITICAL_COUNT + 1)) ;;
      HIGH) REPORT_HIGH_COUNT=$((REPORT_HIGH_COUNT + 1)) ;;
      MEDIUM) REPORT_MEDIUM_COUNT=$((REPORT_MEDIUM_COUNT + 1)) ;;
      LOW) REPORT_LOW_COUNT=$((REPORT_LOW_COUNT + 1)) ;;
    esac
  fi
}

# Human + record helpers matching linpeas-style FOUND/NOT FOUND lines
signal_found() {
  local id="$1" severity="$2" message="$3"
  local remediation="${4:-}"
  local audience="${5:-all}"
  _signal_record "$id" "FOUND" "$severity" "$message" "$remediation" "$audience"
  case "$severity" in
    CRITICAL|HIGH) bad  "FOUND  [${severity}] ${id}: ${message}" ;;
    MEDIUM)        warn "FOUND  [${severity}] ${id}: ${message}" ;;
    *)             info "FOUND  [${severity}] ${id}: ${message}" ;;
  esac
  [[ -n "$remediation" ]] && tip "Remediation: ${remediation}"
}

signal_not_found() {
  local id="$1" message="$2"
  local audience="${3:-all}"
  _signal_record "$id" "NOT_FOUND" "INFO" "$message" "" "$audience"
  ok "NOT FOUND  ${id}: ${message}"
}

signal_info() {
  local id="$1" status="$2" message="$3"
  _signal_record "$id" "$status" "INFO" "$message" "" "all"
  info "${status}  ${id}: ${message}"
}

signal_skipped() {
  local id="$1" message="$2"
  _signal_record "$id" "SKIPPED" "INFO" "$message" "" "all"
  quiet_echo "${DIM}SKIPPED  ${id}: ${message}${RESET}"
}

report_has_critical_findings() {
  [[ "$REPORT_CRITICAL_COUNT" -gt 0 ]]
}

report_summary() {
  section "Report summary"
  quiet_echo "Profile:     ${REPORT_PROFILE}"
  quiet_echo "Version:     ${REPORT_VERSION}"
  quiet_echo "Started:     ${REPORT_STARTED}"
  quiet_echo "Finished:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  quiet_echo "FOUND:       ${REPORT_FOUND_COUNT}"
  quiet_echo "NOT FOUND:   ${REPORT_NOT_FOUND_COUNT}"
  quiet_echo "By severity (FOUND only): CRITICAL=${REPORT_CRITICAL_COUNT} HIGH=${REPORT_HIGH_COUNT} MEDIUM=${REPORT_MEDIUM_COUNT} LOW=${REPORT_LOW_COUNT}"
  echo
  if [[ "$REPORT_CRITICAL_COUNT" -gt 0 ]]; then
    bad "Critical misconfigurations detected — review FOUND signals above."
  elif [[ "$REPORT_HIGH_COUNT" -gt 0 ]]; then
    warn "High-severity findings present — prioritize remediation."
  elif [[ "$REPORT_FOUND_COUNT" -eq 0 ]]; then
    ok "No misconfiguration signals FOUND for this profile/scope."
  else
    info "Review FOUND signals; none were CRITICAL."
  fi
}

# Escape a string for JSON
_json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

report_write_json() {
  local out="$1"
  local finished
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local tmp
  tmp="$(mktemp)"

  {
    echo "{"
    echo "  \"tool\": \"bernetes-buster\","
    echo "  \"version\": \"$(_json_escape "$REPORT_VERSION")\","
    echo "  \"profile\": \"$(_json_escape "$REPORT_PROFILE")\","
    echo "  \"started_at\": \"$(_json_escape "$REPORT_STARTED")\","
    echo "  \"finished_at\": \"$(_json_escape "$finished")\","
    echo "  \"summary\": {"
    echo "    \"found\": ${REPORT_FOUND_COUNT},"
    echo "    \"not_found\": ${REPORT_NOT_FOUND_COUNT},"
    echo "    \"critical\": ${REPORT_CRITICAL_COUNT},"
    echo "    \"high\": ${REPORT_HIGH_COUNT},"
    echo "    \"medium\": ${REPORT_MEDIUM_COUNT},"
    echo "    \"low\": ${REPORT_LOW_COUNT}"
    echo "  },"
    echo "  \"signals\": ["
    local i n=${#REPORT_IDS[@]}
    for ((i = 0; i < n; i++)); do
      local comma=","
      [[ $i -eq $((n - 1)) ]] && comma=""
      cat <<EOF
    {
      "id": "$(_json_escape "${REPORT_IDS[$i]}")",
      "status": "$(_json_escape "${REPORT_STATUSES[$i]}")",
      "severity": "$(_json_escape "${REPORT_SEVERITIES[$i]}")",
      "message": "$(_json_escape "${REPORT_MESSAGES[$i]}")",
      "remediation": "$(_json_escape "${REPORT_REMEDIATIONS[$i]}")",
      "audience": "$(_json_escape "${REPORT_AUDIENCES[$i]}")"
    }${comma}
EOF
    done
    echo "  ]"
    echo "}"
  } >"$tmp"

  if [[ "$out" == "-" ]]; then
    cat "$tmp"
  else
    mv "$tmp" "$out"
    info "JSON report written to ${out}"
  fi
  rm -f "$tmp" 2>/dev/null || true
}
