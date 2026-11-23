#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

TB="$SRC/mayhem/build-test"
for b in "$TB/t/vector" "$TB/t/result" "$TB/gearmand/gearmand" "$TB/bin/gearman"; do
  [ -x "$b" ] || { echo "missing $b — run mayhem/build.sh first" >&2; emit_ctrf "gearmand-tests" 0 1; exit 1; }
done
PASSED=0; FAILED=0
pass() { echo "PASS: $*"; PASSED=$((PASSED + 1)); }
fail() { echo "FAIL: $*"; FAILED=$((FAILED + 1)); }

# 1) Upstream's libtest unit suites (libgearman vector + result APIs). Every case prints
#    "[ ok ]" or "[ failed ]"; a suite with no ok case at all (e.g. a neutered binary) fails.
cd "$TB"
mkdir -p tmp_chroot   # libtest chdir()s into ./tmp_chroot
for suite in vector result; do
  out=$(YATL_RANDOM_SEED=1 "./t/$suite" 2>&1); rc=$?
  ok=$(grep -c '\[ ok \]' <<<"$out" || true)
  bad=$(grep -c '\[ failed \]' <<<"$out" || true)
  PASSED=$((PASSED + ok)); FAILED=$((FAILED + bad))
  if [ "$rc" -ne 0 ] || [ "$ok" -eq 0 ]; then fail "t/$suite (rc=$rc, ok=$ok)"; echo "$out" | tail -20; fi
done
cd "$SRC"

# 2) End to end: start the built gearmand on a free loopback port, register a worker with the
#    gearman CLI, and check that jobs submitted through the CLI come back transformed and that
#    the admin "status" command reports the function.
PORT=$(( 20000 + RANDOM % 20000 ))
LOG="${TMPDIR:-/tmp}/gearmand-test.$$.log"
"$TB/gearmand/gearmand" -L 127.0.0.1 -p "$PORT" --log-file="$LOG" -t 0 &
GPID=$!
WPID=
cleanup() { kill $WPID $GPID 2>/dev/null; wait 2>/dev/null; rm -f "$LOG"; }
trap cleanup EXIT
up=0
for _ in $(seq 100); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then up=1; break; fi
  sleep 0.1
done
if [ "$up" -eq 1 ]; then pass "gearmand listens"; else fail "gearmand did not start"; fi

"$TB/bin/gearman" -h 127.0.0.1 -p "$PORT" -w -f upper -- tr a-z A-Z &
WPID=$!
sleep 0.5
got=$(printf 'hello gearman' | timeout 20 "$TB/bin/gearman" -h 127.0.0.1 -p "$PORT" -f upper 2>&1)
[ "$got" = "HELLO GEARMAN" ] && pass "foreground job result" || fail "foreground job: got '$got'"
got=$(timeout 20 "$TB/bin/gearman" -h 127.0.0.1 -p "$PORT" -f upper abc xyz 2>&1)
[ "$got" = "ABCXYZ" ] && pass "job from argv workload" || fail "argv job: got '$got'"

status=$(exec 3<>"/dev/tcp/127.0.0.1/$PORT"; printf 'status\n' >&3; timeout 5 sed '/^\.$/q' <&3)
grep -qP '^upper\t0\t0\t1$' <<<"$status" && pass "admin status lists the worker" \
  || fail "admin status: '$status'"
ver=$(exec 3<>"/dev/tcp/127.0.0.1/$PORT"; printf 'version\n' >&3; timeout 5 head -n1 <&3)
grep -q '^OK ' <<<"$ver" && pass "admin version" || fail "admin version: '$ver'"

emit_ctrf "gearmand-tests" "$PASSED" "$FAILED"
