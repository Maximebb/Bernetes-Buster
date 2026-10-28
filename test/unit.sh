#!/usr/bin/env bash
# Unit tests for pure helpers (report aggregation, JSON escaping, counters).
# Runs fully offline — sources the libs directly, no cluster or kubectl needed.
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0
pass=0

check() {
  # check <description> <actual> <expected>
  if [[ "$2" == "$3" ]]; then
    pass=$((pass + 1))
  else
    echo "FAIL: $1"
    echo "   expected: [$3]"
    echo "   actual:   [$2]"
    fail=1
  fi
}

# Quiet so sourcing checks/output helpers stay silent, and no ANSI in assertions.
export BBUSTER_QUIET=1
# shellcheck source=../lib/common.sh
source "${ROOT}/lib/common.sh"
bb_disable_color
# shellcheck source=../lib/report.sh
source "${ROOT}/lib/report.sh"

echo "==> _json_escape handles special characters"
check "backslash"      "$(_json_escape 'a\b')"          'a\\b'
check "double quote"   "$(_json_escape 'say "hi"')"     'say \"hi\"'
check "tab"            "$(_json_escape "$(printf 'a\tb')")" 'a\tb'
check "newline"        "$(_json_escape "$(printf 'a\nb')")" 'a\nb'
check "plain"          "$(_json_escape 'nothing-special')" 'nothing-special'

echo "==> counters tally FOUND / NOT_FOUND and severities"
report_init "unit" "0.0.0"
signal_found     "t.crit"  "CRITICAL" "crit msg" "fix" "all"
signal_found     "t.high"  "HIGH"     "high msg" "fix" "all"
signal_found     "t.med"   "MEDIUM"   "med msg"  ""    "all"
signal_found     "t.low"   "LOW"      "low msg"  ""    "all"
signal_not_found "t.clean" "all good"
signal_not_found "t.clean2" "also good"
signal_skipped   "t.skip"  "skipped"
signal_info      "t.info"  "FOUND" "informational"

check "found count"     "$REPORT_FOUND_COUNT"     "5"   # 4 signal_found + 1 signal_info FOUND
check "not_found count" "$REPORT_NOT_FOUND_COUNT" "2"
check "critical count"  "$REPORT_CRITICAL_COUNT"  "1"
check "high count"      "$REPORT_HIGH_COUNT"      "1"
check "medium count"    "$REPORT_MEDIUM_COUNT"    "1"
check "low count"       "$REPORT_LOW_COUNT"       "1"
check "total records"   "${#REPORT_IDS[@]}"       "8"

echo "==> report_has_critical_findings reflects state"
if report_has_critical_findings; then crit="yes"; else crit="no"; fi
check "critical present" "$crit" "yes"

report_init "unit2" "0.0.0"
signal_not_found "t.clean" "nothing"
if report_has_critical_findings; then crit="yes"; else crit="no"; fi
check "critical absent after reinit" "$crit" "no"
check "reinit clears found" "$REPORT_FOUND_COUNT" "0"

echo "==> report_write_json emits valid, self-consistent JSON"
report_init "unit3" "9.9.9"
signal_found     "json.crit" "CRITICAL" 'msg with "quotes" and \backslash' "remediate" "security-eng"
signal_not_found "json.ok"   "clean"
tmp="$(mktemp)"
report_write_json "$tmp" >/dev/null

# Pick a JSON validator that exists on this host.
json_ok() {
  if command -v jq >/dev/null 2>&1; then
    jq -e . "$1" >/dev/null 2>&1
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$1" >/dev/null 2>&1
  else
    echo "WARN: no jq/python3 to validate JSON — skipping parse check" >&2
    return 0
  fi
}

if json_ok "$tmp"; then valid="yes"; else valid="no"; fi
check "json parses" "$valid" "yes"

if command -v jq >/dev/null 2>&1; then
  check "json tool field"     "$(jq -r '.tool' "$tmp")"            "bernetes-buster"
  check "json version field"  "$(jq -r '.version' "$tmp")"         "9.9.9"
  check "json found summary"  "$(jq -r '.summary.found' "$tmp")"   "1"
  check "json critical sum"   "$(jq -r '.summary.critical' "$tmp")" "1"
  check "json signal count"   "$(jq -r '.signals | length' "$tmp")" "2"
  # summary.found must equal the number of FOUND signals actually in the array.
  check "found matches array" \
    "$(jq -r '.summary.found' "$tmp")" \
    "$(jq -r '[.signals[] | select(.status=="FOUND")] | length' "$tmp")"
  # Special characters must round-trip intact through escaping + parsing.
  check "special chars round-trip" \
    "$(jq -r '.signals[] | select(.id=="json.crit") | .message' "$tmp")" \
    'msg with "quotes" and \backslash'
fi
rm -f "$tmp"

echo "==> profile validation accepts known, rejects unknown"
if ( bb_validate_profile security-eng ) 2>/dev/null; then v="ok"; else v="bad"; fi
check "valid profile accepted" "$v" "ok"
if ( bb_validate_profile bogus ) 2>/dev/null; then v="ok"; else v="bad"; fi
check "invalid profile rejected" "$v" "bad"

if [[ "$fail" -ne 0 ]]; then
  echo "UNIT FAILED (${pass} passed)"
  exit 1
fi
echo "UNIT OK (${pass} assertions passed)"
