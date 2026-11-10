---
name: feedback-device-tiers-in-docker
description: Run the runtime and conformance tiers only through tests/common/tools/run-in-docker.ps1/.sh; a host-native run gives misleading failures.
type: feedback
---

Run the device tiers with `tests/common/tools/run-in-docker.ps1`
(`-Tier runtime|conformance`, `-Section 5.6`, `-IncludeUncommitted`, extra
arguments go to pytest) or `run-in-docker.sh`; on Windows from PowerShell,
not Git Bash (Git Bash mangles the argument list and shadows `tar`). Never
run them natively on the host.

**Why:** the device needs the veth pair and `dut` network namespace that
only the container sets up; on the host, collection and reporting look
normal while multicast goes nowhere, and the failures read as a regression.

**How to apply:** a run several times slower than usual means the device is
unreachable; check `docker ps` before reading failures. Never run two at
once (shared veth/netns names). Select template parts with `-Section`, never
`-k` (substring match). A baseline is a run of committed HEAD.
