#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Run the device test tiers INSIDE the CI image, the way the GitLab jobs
# runtime-gcc / conformance-gcc do: DUT in its own network namespace, unique local
# addresses on a veth pair, runtime_test_server built from this tree, one
# pytest process per tier. This is the in-container half; on a developer
# machine you normally do not call it yourself but go through
#   tests/common/tools/run-in-docker.ps1   (Windows PowerShell)
#   tests/common/tools/run-in-docker.sh    (Linux / macOS / Git Bash)
# which pack the source tree, start the container and hand it this script.
#
# Usage (inside the container, repo unpacked at the current directory):
#   bash tests/common/tools/run-local-ci.sh [--tier all|conformance|runtime|tool]
#                                           [--section 5.x [--section 5.y]]
#                                           [--preset linux-test-gcc]
#                                           [--server-logs] [--coap-debug]
#                                           [--oscore-debug] [--group-debug]
#                                           [--time-scale 0.05] [--slow]
#                                           [--] [pytest-args...]
#
#   --tier      conformance -> the conformance-test template, played by the
#                          test tool (tests/iot-test-tool/run_sequences.py) with
#                          this stack's override files (tests/conformance);
#                          "eitt" is accepted for it too
#               runtime -> tests/runtime/   (hand-written device tests)
#               tool    -> the test tool's own tests (no DUT at all);
#                          "harness" is accepted for it too
#               all     -> conformance, then runtime, each in its OWN pytest process
#                          and therefore against a FRESH DUT (finding O6:
#                          one process for both tiers shares one device and
#                          the runtime firmware-update test leaves fwv 0.0.2
#                          behind for EITT 5.2.6.1). Default.
#   --section   Select whole EITT sections by number. Use this, not -k: pytest's
#               -k is a substring match, so `-k 5.6` also picks 5.5.5.6 and
#               5.5.6.1, which then run without their sibling preparation
#               TestCases and fail spuriously.
#   Everything after the options (or after `--`) goes to pytest unchanged,
#   e.g. `-x`, `--tb=long`, `tests/runtime/test_observe.py`.
#
# Environment mirrored from .gitlab-ci.yml's .device-test block; the values
# here are the CI values. RUNTIME_TEST_QUIET=1 hides the DUT's stdout (its
# stderr, which carries sanitizer reports, is always shown).
# ---------------------------------------------------------------------------
set -euo pipefail

TIER=all
PRESET=linux-test-gcc
SECTIONS=()
QUIET=1
OSCORE_DBG=0
COAP_DBG=0
GROUP_DBG=0
TIME_SCALE=0.05
SLOW=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tier)         TIER="$2"; shift 2 ;;
    --tier=*)       TIER="${1#*=}"; shift ;;
    --section)      SECTIONS+=("$2"); shift 2 ;;
    --section=*)    SECTIONS+=("${1#*=}"); shift ;;
    --preset)       PRESET="$2"; shift 2 ;;
    --preset=*)     PRESET="${1#*=}"; shift ;;
    --server-logs)  QUIET=0; shift ;;
    --coap-debug)   COAP_DBG=1; shift ;;
    --oscore-debug) OSCORE_DBG=1; shift ;;
    --group-debug)  GROUP_DBG=1; shift ;;
    --time-scale)   TIME_SCALE="$2"; shift 2 ;;
    --time-scale=*) TIME_SCALE="${1#*=}"; shift ;;
    --slow)         SLOW=1; shift ;;
    --)             shift; break ;;
    -h|--help)      sed -n '2,43p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)              break ;;
  esac
done
case "$TIER" in
  eitt)    TIER=conformance ;;
  harness) TIER=tool ;;
esac
case "$TIER" in
  all|conformance|runtime|tool) ;;
  *) echo "run-local-ci.sh: unknown --tier '$TIER' (all|conformance|runtime|tool)" >&2; exit 2 ;;
esac
TOOL=tests/iot-test-tool
if [ ! -f "$TOOL/run_sequences.py" ]; then
  echo "run-local-ci.sh: $TOOL is empty: git submodule update --init $TOOL" >&2
  exit 2
fi

SECTION_ARGS=()
for s in "${SECTIONS[@]:-}"; do
  [ -n "$s" ] && SECTION_ARGS+=(--section "$s")
done

# The tool's own tests need no device and no network; run them and stop.
if [ "$TIER" = tool ]; then
  echo "=== Installing Python dependencies ==="
  curl -sSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
  python3 /tmp/get-pip.py --break-system-packages --quiet
  python3 -m pip install --break-system-packages --quiet -r "$TOOL/requirements.txt"
  (cd "$TOOL" && python3 -m interpreter.knx_files update > /dev/null) \
    || echo "warning: update.knx.org not reachable; using the KNX files in the cache"
  echo "=== the test tool's tests ==="
  cd "$TOOL"
  exec python3 -m pytest -rfE "$@"
fi

echo "=== Device network: DUT in its own netns, ULA on both veth ends ==="
# Same block as .gitlab-ci.yml (.device-network) and run-in-docker.ps1. Why a
# separate namespace and not just a veth pair: with both ends in one
# namespace the DUT learns the tool's address from the SOURCE of our
# discovery reply, the kernel picks a local address for that, and the DUT
# then sends unicast s-mode telegrams to itself (5.4.1.4 / 5.4.1.15). Why a
# unique local address: a veth pair comes up link-local only, and the DUT
# refuses to send any device-originated s-mode message until the network
# scope is >= site-local (KNX_MULTICAST_SCOPE 5).
DUT_ADDR=fd11:9988:7766::1
TOOL_ADDR=fd11:9988:7766::2
apt-get update -qq && apt-get install -y -qq iproute2 > /dev/null 2>&1
ip netns add dut
ip link add veth-dut type veth peer name veth-test
ip link set veth-dut netns dut
ip link set veth-test up
ip netns exec dut ip link set lo up
ip netns exec dut ip link set veth-dut up
ip netns exec dut sysctl -w net.ipv6.conf.veth-dut.disable_ipv6=0 > /dev/null
sysctl -w net.ipv6.conf.veth-test.disable_ipv6=0 > /dev/null
sleep 3
ip netns exec dut ip -6 route add ff00::/8 dev veth-dut || true
ip -6 route add ff00::/8 dev veth-test || true
ip netns exec dut ip -6 addr add ${DUT_ADDR}/64 dev veth-dut nodad || true
ip -6 addr add ${TOOL_ADDR}/64 dev veth-test nodad || true
sleep 1
echo "DUT ${DUT_ADDR} (netns dut, veth-dut) <-> tool ${TOOL_ADDR} (veth-test)"

echo "=== Building runtime_test_server ($PRESET) ==="
cmake --preset="$PRESET" -DOC_DEBUG_ENABLED=OFF -DOC_PRINT_ENABLED=OFF -DOC_DEBUG_OSCORE_ENABLED=OFF
cmake --build --preset="$PRESET" --target runtime_test_server

echo "=== Installing Python dependencies ==="
curl -sSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
python3 /tmp/get-pip.py --break-system-packages --quiet
python3 -m pip install --break-system-packages --quiet -r tests/common/requirements.txt -r "$TOOL/requirements.txt"

export RUNTIME_TEST_SERVER="build/$PRESET/tests/runtime_test_server"
export RUNTIME_TEST_SERVER_PREFIX='ip netns exec dut'
export DUT_IFACE=veth-dut DEVICE_HOST="$DUT_ADDR" DEVICE_IFACE=veth-test
export COAP_TIMEOUT=5 SERVER_STARTUP_TIMEOUT=30 RUNTIME_TEST_QUIET="$QUIET"
export RUNTIME_TEST_TIME_SCALE="$TIME_SCALE"
export KNX_TEST_DEBUG_OSCORE="$OSCORE_DBG" KNX_TEST_DEBUG_COAP="$COAP_DBG"
export KNX_TEST_DEBUG_GROUP="$GROUP_DBG" KNX_TEST_DEBUG_MDNS="$GROUP_DBG"
[ -n "$SLOW" ] && export RUN_SLOW_TESTS=1

# KNX's files (template, comment scheme, ...) in the cache, as EITT fetches
# them; run-in-docker mounts the host's cache, so offline is fine once filled.
if [ "$TIER" != runtime ]; then
  (cd "$TOOL" && python3 -m interpreter.knx_files update > /dev/null) \
    || echo "warning: update.knx.org not reachable; using the KNX files in the cache"
fi

case "$TIER" in
  conformance) PATHS=(conformance) ;;
  runtime)     PATHS=(tests/runtime/) ;;
  all)         PATHS=(conformance tests/runtime/) ;;
esac

# One pytest process per tier path -> one DUT per tier (see --tier all above).
# `|| rc=$?` defeats `set -e` so the second tier still runs after a failing
# first one; the worst status becomes the exit code, and the -rfE summary
# lines of both invocations stay in the log.
# With more than one tier, a run record (--run-record FILE) gets one file per
# tier (FILE.conformance.krr.jsonl, FILE.runtime.krr.jsonl): the writer
# truncates its file, so one name would leave only the last tier's record.
tier_args() {
  local tier=$1; shift
  TIER_ARGS=()
  local next=0 a
  for a in "$@"; do
    if [ "$next" = 1 ]; then TIER_ARGS+=("$(per_tier "$a" "$tier")"); next=0; continue; fi
    case "$a" in
      --run-record=*) TIER_ARGS+=("--run-record=$(per_tier "${a#--run-record=}" "$tier")") ;;
      --run-record)   TIER_ARGS+=("$a"); next=1 ;;
      *)              TIER_ARGS+=("$a") ;;
    esac
  done
}
per_tier() {
  if [ "${#PATHS[@]}" -lt 2 ]; then echo "$1"; return; fi
  echo "${1%.krr.jsonl}.$2.krr.jsonl"
}

worst=0
for path in "${PATHS[@]}"; do
  echo "=== pytest $path ==="
  rc=0
  if [ "$path" = conformance ]; then
    tier_args conformance "$@"
    python3 "$TOOL/run_sequences.py" \
      --dut-command "$RUNTIME_TEST_SERVER_PREFIX $RUNTIME_TEST_SERVER" \
      --overrides tests/conformance "${SECTION_ARGS[@]}" "${TIER_ARGS[@]}" || rc=$?
  else
    tier_args runtime "$@"
    python3 -m pytest -rfE "$path" "${TIER_ARGS[@]}" || rc=$?
  fi
  if [ "$rc" -gt "$worst" ]; then worst=$rc; fi
done
exit "$worst"
