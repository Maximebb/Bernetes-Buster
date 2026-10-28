#!/usr/bin/env bash
# Smoke tests runnable without a cluster
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0

assert_file() {
  [[ -f "$1" ]] || { echo "MISSING: $1"; fail=1; }
}

echo "==> Required files"
assert_file bbuster.sh
assert_file LICENSE
assert_file lib/common.sh
assert_file lib/report.sh
assert_file profiles/developer.sh
assert_file profiles/security-eng.sh
assert_file profiles/red-team.sh
assert_file deploy/job.yaml
assert_file deploy/rbac-readonly.yaml
assert_file Dockerfile

echo "==> bash -n"
bash -n bbuster.sh
find lib profiles -name '*.sh' -print0 | xargs -0 -n1 bash -n

echo "==> Unit tests (pure helpers)"
bash "$ROOT/test/unit.sh" || fail=1

echo "==> --help / --version"
bash bbuster.sh --help >/dev/null
ver="$(bash bbuster.sh --version)"
[[ "$ver" == bbuster* ]] || { echo "bad version: $ver"; fail=1; }

# JSON validator: prefer jq, fall back to python3, else skip gracefully.
json_valid() {
  if command -v jq >/dev/null 2>&1; then
    jq -e . "$1" >/dev/null 2>&1
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$1" >/dev/null 2>&1
  else
    echo "   (no jq/python3 — skipping strict JSON parse)"; return 0
  fi
}

echo "==> Offline scan produces FOUND/NOT FOUND JSON"
out="$(mktemp)"
# Allow exit 0 or 2 (critical findings on this host are possible)
set +e
BBUSTER_SKIP_API=1 bash bbuster.sh --profile developer --quiet --json "$out"
rc=$?
set -e
[[ "$rc" -eq 0 || "$rc" -eq 2 ]] || { echo "unexpected exit $rc"; fail=1; }
grep -q '"tool": "bernetes-buster"' "$out" || { echo "bad json tool"; fail=1; }
grep -q '"status"' "$out" || { echo "no statuses"; fail=1; }
grep -Eq '"FOUND"|"NOT_FOUND"|"INFO"|"SKIPPED"' "$out" || { echo "no signal statuses"; fail=1; }

echo "==> Emitted JSON is well-formed"
json_valid "$out" || { echo "report is not valid JSON"; fail=1; }

echo "==> summary counts match the signals array"
if command -v jq >/dev/null 2>&1; then
  s_found="$(jq -r '.summary.found' "$out")"
  a_found="$(jq -r '[.signals[]|select(.status=="FOUND")]|length' "$out")"
  [[ "$s_found" == "$a_found" ]] || { echo "summary.found=$s_found != array FOUND=$a_found"; fail=1; }
  s_nf="$(jq -r '.summary.not_found' "$out")"
  a_nf="$(jq -r '[.signals[]|select(.status=="NOT_FOUND")]|length' "$out")"
  [[ "$s_nf" == "$a_nf" ]] || { echo "summary.not_found mismatch ($s_nf/$a_nf)"; fail=1; }
  s_crit="$(jq -r '.summary.critical' "$out")"
  a_crit="$(jq -r '[.signals[]|select(.status=="FOUND" and .severity=="CRITICAL")]|length' "$out")"
  [[ "$s_crit" == "$a_crit" ]] || { echo "summary.critical mismatch ($s_crit/$a_crit)"; fail=1; }
  # every signal must carry the documented keys
  miss="$(jq -r '[.signals[]|select((has("id") and has("status") and has("severity") and has("message"))|not)]|length' "$out")"
  [[ "$miss" == "0" ]] || { echo "$miss signals missing required keys"; fail=1; }
fi
rm -f "$out"

echo "==> --no-color output contains no ANSI escapes"
nc="$(BBUSTER_SKIP_API=1 bash bbuster.sh --profile developer --no-color 2>/dev/null || true)"
if printf '%s' "$nc" | grep -q $'\033'; then echo "ANSI escape leaked with --no-color"; fail=1; fi

echo "==> --checks glob runs a subset only"
sub="$(mktemp)"
set +e
BBUSTER_SKIP_API=1 bash bbuster.sh --checks '01_*.sh' --quiet --json "$sub"
set -e
if command -v jq >/dev/null 2>&1; then
  # 01_identity emits k8s.* / env.* ids; container.* must be absent when only 01 runs.
  only01="$(jq -r '[.signals[]|select(.id|startswith("container."))]|length' "$sub")"
  [[ "$only01" == "0" ]] || { echo "--checks 01_*.sh leaked container signals"; fail=1; }
  has01="$(jq -r '[.signals[]|select(.id|startswith("k8s."))]|length' "$sub")"
  [[ "$has01" -gt 0 ]] || { echo "--checks 01_*.sh produced no identity signals"; fail=1; }
fi
rm -f "$sub"

echo "==> invalid input is rejected"
set +e
BBUSTER_SKIP_API=1 bash bbuster.sh --profile nonsense --quiet >/dev/null 2>&1
bad_profile=$?
BBUSTER_SKIP_API=1 bash bbuster.sh --bogus-flag --quiet >/dev/null 2>&1
bad_flag=$?
set -e
[[ "$bad_profile" -ne 0 ]] || { echo "unknown profile should exit non-zero"; fail=1; }
[[ "$bad_flag" -ne 0 ]]    || { echo "unknown flag should exit non-zero"; fail=1; }

echo "==> Profiles load"
for p in developer security-eng red-team; do
  pout="$(mktemp)"
  set +e
  BBUSTER_SKIP_API=1 bash bbuster.sh --profile "$p" --quiet --json "$pout"
  rc=$?
  set -e
  [[ "$rc" -eq 0 || "$rc" -eq 2 ]] || { echo "profile $p failed rc=$rc"; fail=1; }
  rm -f "$pout"
done

if [[ "$fail" -ne 0 ]]; then
  echo "SMOKE FAILED"
  exit 1
fi
echo "SMOKE OK"
