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

echo "==> --help / --version"
bash bbuster.sh --help >/dev/null
ver="$(bash bbuster.sh --version)"
[[ "$ver" == bbuster* ]] || { echo "bad version: $ver"; fail=1; }

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
rm -f "$out"

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
