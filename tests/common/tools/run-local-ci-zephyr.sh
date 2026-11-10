#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Run the runtime conformance test suite against a running EITT device.
#
# Unlike run-local-ci.sh (which builds runtime_test_server and runs it inside
# the CI Docker image), this runner drives pytest directly on the host against
# an already-running EITT device under test (DUT). The DUT is either real
# hardware (a Zephyr EITT device on the network) or the Linux/Windows virtual
# EITT GUI (eitt_virtual_gui). Nothing is built or containerised here. The DUT
# must already be running and reachable at DEVICE_HOST before this script starts.
#
# Usage (from the repo root):
#   ./tests/common/tools/run-local-ci-zephyr.sh [pytest-args...]
# With no arguments the default CI test set (below) runs. Any arguments are
# passed straight through to pytest.
#
# Examples:
#   # Run only tests/runtime/test_group_comm.py:
#   ./tests/common/tools/run-local-ci-zephyr.sh tests/runtime/test_group_comm.py
#
#   # Run a single test class, verbose:
#   ./tests/common/tools/run-local-ci-zephyr.sh 'tests/runtime/test_group_comm.py::TestOwnGroupObjectUpdate' -v
#
#   # Point at the virtual EITT GUI instead of the default device:
#   DEVICE_HOST=<virtual-ipv6> ./tests/common/tools/run-local-ci-zephyr.sh tests/runtime/test_discovery_pagination.py
#
# NOTE: Run this in a Python virtual environment with requirements.txt installed.
#       Connection and multicast parameters (DEVICE_HOST, DEVICE_IFACE,
#       KNX_MULTICAST_SCOPE, ...) are documented and defaulted further down.
#
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

# Default: the whole runtime tier (same as CI); fixtures.py orders the
# modules.  Override by passing args.
if [ $# -eq 0 ]; then
  set -- tests/runtime/
fi

# Parameters. All are overridable as environment variables. No positional
# arguments are consumed, so every command-line argument is passed to pytest.
#
#   EXTERNAL_DUT (fixed to 1 below)
#       Test a real device instead of a local runtime_test_server.
#   DEVICE_HOST (default fd09:f0fd:a40b:1:5ae6:c5ff:fe01:1364)
#       Device unicast IPv6 address, i.e. how the client reaches the DUT.
#       Note: If this is not set DNS-SD is used to find the device.
#   DEVICE_IFACE (default wlp0s20f3)
#       Host interface facing the access point, i.e. the IPv6 multicast egress
#       interface. REQUIRED to un-skip the multicast tests, which otherwise
#       report "Multicast tests require DEVICE_IFACE env var".
#   KNX_MULTICAST_SCOPE (default 5)
#       IPv6 multicast scope for the group tests. 2 = link-local (ff02::fd),
#       3 = realm-local (ff03::fd), 5 = site-local (ff05::fd).
#   KNX_TEST_DEBUG_OSCORE / KNX_TEST_DEBUG_COAP (default 0)
#       Set to 1 to print the [oscore] / [coap] traces.
#   DUT_IFACE is intentionally NOT set. It is a CI/veth-only knob for poking a
#   local DUT interface with `ip addr`, impossible against a remote device.
#
# Command-line arguments go straight to pytest, for example:
#   DEVICE_IFACE=eth0 ./tests/common/tools/run-local-ci-zephyr.sh -rs -k multicast
#   KNX_MULTICAST_SCOPE=2 ./tests/common/tools/run-local-ci-zephyr.sh tests/runtime/test_discovery_multicast.py
#
# NOTE: Set the following environment variables to override the defaults which are hardware dependent.
DEVICE_HOST="${DEVICE_HOST:-fd09:f0fd:a40b:1:5ae6:c5ff:fe01:1364}"	# Zephyr Device
#DEVICE_HOST="${DEVICE_HOST:-fd09:f0fd:a40b:0001:1d95:79d6:f730:b2f1}"	# Virtual EITT Linux
DEVICE_IFACE="${DEVICE_IFACE:-wlp0s20f3}"
KNX_MULTICAST_SCOPE="${KNX_MULTICAST_SCOPE:-5}"

echo "=== Running tests ==="
# pytest options used below:
#   -v          Verbose. One line per test with PASSED/FAILED/SKIPPED.
#   -s          Do not capture stdout, so print() shows live (= --capture=no).
#   --tb=short  Condensed failure traceback.
#               Alternatives: --tb=long|auto|line|native|no.
# Other handy pytest options: -rs (show SKIP reasons), -ra (all non-pass
#   reasons), -k EXPR (select by name), -x or --maxfail=N (stop early),
#   --lf or --ff (last-failed / failed-first), -l (show locals),
#   --durations=N, --pdb, --co (collect only).

#  DUT_IFACE=veth-dut \
#  RUNTIME_TEST_QUIET=1 \
# Build the command once so the exact command (with expanded values and the
# selected test files) is printed before it runs.
declare -a cmd=(
  env
  EXTERNAL_DUT=1
  DEVICE_HOST="${DEVICE_HOST}"
  DEVICE_IFACE="${DEVICE_IFACE}"
  KNX_MULTICAST_SCOPE="${KNX_MULTICAST_SCOPE}"
  KNX_TEST_DEBUG_OSCORE=0
  KNX_TEST_DEBUG_COAP=0
  python3 -m pytest "$@" -v -s --tb=short
)
echo "+ ${cmd[*]}"
exec "${cmd[@]}"
