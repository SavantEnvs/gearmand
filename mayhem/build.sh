#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# gearmand is autotools. configure.ac lives in the tree; autoreconf regenerates the (gitignored)
# configure/Makefile.in on every run so a `git clean -ffdX`-ed tree rebuilds. Both builds below are
# out of tree under mayhem/build-*/ (gitignored by mayhem/.gitignore).
autoreconf -fi

CONF_ARGS=(--disable-shared --enable-static --disable-libmemcached --disable-libdrizzle
           --disable-libpq --disable-libtokyocabinet --without-mysql --without-sphinx-build)

# The gperf rules in libgearman/include.am read their inputs relative to the build dir, so a
# VPATH build needs the .gperf sources linked in before make generates command.hpp/error_code.hpp.
prep_builddir() {
  mkdir -p "$1/libgearman"
  ln -sf "$SRC/libgearman/command.gperf" "$SRC/libgearman/error_code.gperf" "$1/libgearman/"
}
# Naming targets skips BUILT_SOURCES (and plain `make` needs sphinx for the man pages), so make the
# generated headers first.
GEN_HEADERS=(configmake.h libhashkit-1.0/configure.h libgearman/error_code.hpp libgearman/command.hpp
             libtest/version.h libtest/ssl.h)

# 1) Sanitized build of the libraries the harnesses link (libgearman, libgearman-server,
#    libhashkit). ASan and every UBSan check stay on and halting, except two UBSan checks that are
#    relaxed where an input that is otherwise valid trips them. Each was reproduced in a Mayhem
#    or local run with the check on:
#    - `enum`: the Gear unpackers cast the wire command number to gearman_command_t and only then
#      range-check it, so every unknown command aborts as "invalid enum load" before the parser
#      rejects it: gearman_packet_unpack_header() at libgearman/packet.cc:346 (client and worker
#      replies), gearmand_packet_unpack_header() at
#      libgearman-server/plugins/protocol/gear/protocol.cc:82 (server), and the range check itself
#      in gearman_command_info() at libgearman/command.cc:136, which loads the same cast value
#      (built into both libgearman and libgearman-server). Relaxed in those three sources only.
#    - `nonnull-attribute`: zero-length mem*/strn* calls with a NULL pointer for an empty argument,
#      reply or blob. Relaxed for every libgearman/ source (in libgearman.la and in the copies
#      libgearman-server.la compiles) and for the sqlite queue. Frames seen:
#      packet_create_arg() at libgearman/packet.cc:96 (memcpy), gearman_vector_st::append() at
#      libgearman/vector.cc:277 (memcpy), gearman_client_st's reply compare at
#      libgearman/client.cc:1719 (strncmp), libgearman/check.cc:66 (memcmp), and
#      Instance::replay_loop() at libgearman-server/plugins/queue/sqlite/instance.cc:558 (memcpy).
#    The rest of libgearman-server, libhashkit and the harnesses build with both checks on.
FUZZ_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1"
LIB_FLAGS="$FUZZ_FLAGS -fsanitize=fuzzer-no-link"
NN="nonnull-attribute"
RELAXED_OBJS=(
  "libgearman/libgearman_la-packet.lo:enum,$NN"
  "libgearman/libgearman_la-command.lo:enum,$NN"
  "libgearman/server_libgearman_server_la-command.lo:enum,$NN"
  "libgearman-server/plugins/protocol/gear/libgearman_server_la-protocol.lo:enum"
  "libgearman-server/plugins/queue/sqlite/libgearman_server_la-instance.lo:$NN"
)
# libgearman/ sources libgearman-server.la compiles itself (libgearman.la gets NN as a whole below).
for f in backtrace pipe uuid vector strerror; do
  RELAXED_OBJS+=("libgearman/server_libgearman_server_la-$f.lo:$NN")
done
FB="$SRC/mayhem/build-fuzz"
prep_builddir "$FB"
(
  cd "$FB"
  if [ ! -f config.status ]; then
    "$SRC/configure" "${CONF_ARGS[@]}" CFLAGS="$LIB_FLAGS" CXXFLAGS="$LIB_FLAGS"
  fi
  make -j"$MAYHEM_JOBS" "${GEN_HEADERS[@]}"
  # Those objects are always recompiled here with their relaxed flags, so the library targets
  # below find them up to date and never rebuild them with the full set.
  for entry in "${RELAXED_OBJS[@]}"; do
    obj="${entry%%:*}"
    rm -f "$obj" "${obj%.lo}.o"
    make "$obj" CXXFLAGS="$LIB_FLAGS -fno-sanitize=${entry#*:}"
  done
  # libhashkit first, with the full set: libgearman.la depends on it and would otherwise build it
  # with the relaxed flags below.
  make -j"$MAYHEM_JOBS" libhashkit/libhashkit.la
  # libgearman.la with nonnull-attribute relaxed for all of it. Its sources are always recompiled
  # (as above), so a re-run never keeps a stale object built with the full set.
  find libgearman -name 'libgearman_la-*.lo' ! -name 'libgearman_la-packet.lo' \
    ! -name 'libgearman_la-command.lo' -exec sh -c 'rm -f "$1" "${1%.lo}.o"' _ {} \;
  make -j"$MAYHEM_JOBS" libgearman/libgearman.la CXXFLAGS="$LIB_FLAGS -fno-sanitize=$NN"
  make -j"$MAYHEM_JOBS" libgearman-server/libgearman-server.la
)

# 2) Harnesses: libFuzzer binary + standalone reproducer each.
$CXX $FUZZ_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$FB/lsan_off.o"
$CC $FUZZ_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FB/standalone_main.o"
CLIENT_LIBS=("$FB/libgearman/.libs/libgearman.a" "$FB/libhashkit/.libs/libhashkit.a" -luuid -lpthread)
SERVER_LIBS=("$FB/libgearman-server/.libs/libgearman-server.a" "${CLIENT_LIBS[@]}"
             -lhiredis -lsqlite3 -levent -levent_pthreads -lboost_program_options -lrt)
build_harness() {  # name, libs...
  local name="$1"; shift
  $CXX $FUZZ_FLAGS -I"$SRC" -I"$FB" -c "$SRC/mayhem/harnesses/$name.cc" -o "$FB/$name.o"
  $CXX $FUZZ_FLAGS $LIB_FUZZING_ENGINE "$FB/$name.o" "$FB/lsan_off.o" "$@" -o "$SRC/$name"
  $CXX $FUZZ_FLAGS "$FB/standalone_main.o" "$FB/$name.o" "$FB/lsan_off.o" "$@" \
    -o "$SRC/$name-standalone"
}
build_harness fuzz_gearmand "${SERVER_LIBS[@]}"
build_harness fuzz_client "${CLIENT_LIBS[@]}"
build_harness fuzz_worker "${CLIENT_LIBS[@]}"
build_harness fuzz_servers "${CLIENT_LIBS[@]}"
build_harness fuzz_sqlite_queue "${SERVER_LIBS[@]}"
build_harness fuzz_redis_queue "${SERVER_LIBS[@]}"
# Config-file target: gearmand's own main (renamed) plus the other sources of the gearmand program.
GM_OBJS=()
for src in gearmand/gearmand.cc util/daemon.cc util/pidfile.cc libtest/cpu.cc; do
  obj="$FB/gm_$(basename "${src%.cc}").o"
  $CXX $FUZZ_FLAGS -DHAVE_CONFIG_H -Dmain=gearmand_main -I"$SRC" -I"$FB" -c "$SRC/$src" -o "$obj"
  GM_OBJS+=("$obj")
done
build_harness fuzz_config "${GM_OBJS[@]}" "${SERVER_LIBS[@]}"

# 3) Functional-test build with the project's normal flags: the gearmand server, the gearman CLI
#    and upstream's self-contained unit suites (t/vector, t/result) that mayhem/test.sh runs.
TB="$SRC/mayhem/build-test"
prep_builddir "$TB"
(
  cd "$TB"
  if [ ! -f config.status ]; then
    env -u CFLAGS -u CXXFLAGS -u LDFLAGS "$SRC/configure" "${CONF_ARGS[@]}" \
      CFLAGS="-O2 $COVERAGE_FLAGS" CXXFLAGS="-O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
  fi
  make -j"$MAYHEM_JOBS" "${GEN_HEADERS[@]}"
  make -j"$MAYHEM_JOBS" gearmand/gearmand bin/gearman t/vector t/result
)
