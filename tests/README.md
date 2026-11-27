# Tests

Five tiers. Two of them run over a live device; the others are compiled,
or shared code.

| Tier | Directory | What it is | Needs a DUT | Run with |
| --- | --- | --- | --- | --- |
| unit | [`unit/`](unit/) | Google Test, C++ exercising the C functions directly | no | `ctest --preset linux-test-gcc` |
| fuzz | [`fuzz/`](fuzz/) | libFuzzer harnesses over the pre-auth parsers, clang only | no | `ctest --preset linux-fuzz-clang` |
| common | [`common/`](common/) | shared test infrastructure — **no tests live here** | — | — |
| conformance | [`conformance/`](conformance/) + [`iot-test-tool/`](iot-test-tool/) | KNX's conformance-test template played against the device by the test tool, one pytest item per sequence (collection) | yes | `run-in-docker.ps1 -Tier conformance` |
| runtime | [`runtime/`](runtime/) | hand-written device tests for behaviour the template does *not* cover | yes | `run-in-docker.ps1 -Tier runtime` |

The conformance-test tool is its own repository,
[knx-iot-point-api-test-tool](https://gitlab.knx.org/public-projects/knx-iot-point-api/knx-iot-point-api-test-tool),
pinned here as the git submodule `iot-test-tool/` (fetch it once:
`git submodule update --init tests/iot-test-tool`). It holds the interpreter,
the headless runner (`run_sequences.py`), the browser GUI, the CoAP/OSCORE
client and its own tests; see its README. What is this stack's lives here:
the override files in [`conformance/`](conformance/) — `overrides.yaml`
(written by hand: accepted response codes, skip/xfail, operator prompts
mapped to the test device's endpoints) and `overrides.project.yaml`
(written by the GUI's "Write overrides"; point the GUI's Settings, Overrides
folder at `tests/conformance`). KNX's template and its companion files are
not in either repository: the tool fetches them from update.knx.org into a
per-machine cache.

For work on the tool and the stack together, `KNX_TOOL_DIR` points the
runtime tier at a normal checkout of the tool instead of the submodule; CI
always uses the pinned submodule. Bumping the pin is an ordinary commit
here that runs the device jobs.

## Layout

```
tests/
  pytest.ini        rootdir ini: pythonpath = . common iot-test-tool ; testpaths = runtime
  conftest.py       thin — re-exports everything common/fixtures.py defines,
                    because pytest reads fixtures and hooks only from a conftest

  common/           shared infrastructure, holds no tests
    fixtures.py       fixtures, constants, helpers and the pytest hooks
                      (tier ordering, --run-record); builds and starts the DUT,
                      performs SPAKE2+ and OSCORE provisioning
    tools/            run-in-docker.ps1 / .sh, run-local-ci*.sh, lizard_report.py
    runtime_test_server.c   the device under test
    requirements.txt  what the runtime tier needs (the tool has its own)

  conformance/      this stack's override files for the test tool
  iot-test-tool/    the conformance-test tool (git submodule)
  runtime/          the hand-written tier — behaviour-named test_*.py only
```

The runtime tests import by plain module name — `from fixtures import
DUT_IA`, `from transport.coap_client import CoapClient` (the tool's CoAP
client). `pytest.ini`'s `pythonpath = . common iot-test-tool` makes that work
from any working directory.

## Running

Always in Docker for anything that needs the DUT — the suite needs a veth
pair and a `dut` network namespace that only the Docker harness creates, and
a host-native run fails in ways that look like code regressions:

```powershell
.\tests\common\tools\run-in-docker.ps1                 # both device tiers, each against a fresh DUT
.\tests\common\tools\run-in-docker.ps1 -Tier conformance
.\tests\common\tools\run-in-docker.ps1 -Tier runtime
.\tests\common\tools\run-in-docker.ps1 -Tier conformance -Section 5.6
.\tests\common\tools\run-in-docker.ps1 -IncludeUncommitted -Tier runtime
```

The same from Linux, macOS or Git Bash (`--help` lists every option):

```bash
tests/common/tools/run-in-docker.sh                    # both device tiers
tests/common/tools/run-in-docker.sh --tier conformance --section 5.6
tests/common/tools/run-in-docker.sh --tier runtime --uncommitted
tests/common/tools/run-in-docker.sh --tier tool        # the tool's own tests, no device
```

To run the unit, coverage and fuzz jobs in Linux as well, use the image in
`docker/Dockerfile`; see [docs/docker.md](../docs/docker.md).

The DUT is built with the test presets, which set the reset delay
(`KNX_RESET_DELAY_MILLISECONDS`, 1 ms) and the default echo response delay
(`KNX_OSCORE_OSN_DELAY_MILLISECONDS`, 10 ms) short: both tools act on the device right
after a reset or a group message, while a product waits 1 s before a reset and
up to 1 s before an echo response.

Both wrappers pack the tree with the tool (committed HEAD with the tool at
the pinned commit, or the working trees with `-IncludeUncommitted` /
`--uncommitted`), mount the host's cache of KNX's files, start the CI image
privileged and run `common/tools/run-local-ci.sh` inside it. That script is
the in-container half and takes the same `--tier` / `--section` options, so
a Linux CI runner can call it directly.

The tool's GUI runs on the tester's machine against a real device
(`python -m web.backend` in `tests/iot-test-tool`, see the tool's README).

### Heap peak

`-Massif` (`--massif`) runs the DUT under Valgrind Massif, as the nightly
`runtime-massif` / `conformance-massif` jobs do:

```powershell
.\tests\common\tools\run-in-docker.ps1 -Tier runtime -Massif -IncludeUncommitted
```

The profiles (`<tier>.<pid>.out`) and their `ms_print` reports
(`<tier>.<pid>.txt`) land in `build/massif/`, the same path as in CI. A report
starts with the heap over time and its peak, followed by the allocation trees
of the detailed snapshots, the peak among them. The stack's allocation wrappers
are `--alloc-fn`, so a site in a tree is the code that asked for the memory.
The figures are 64-bit host values, a trend to follow; the 32-bit target model
is `docs/memory_breakdown.md`. Valgrind slows the DUT down, so the runner
lengthens the CoAP, start-up and stop timeouts (`SERVER_STOP_TIMEOUT` gives the
DUT time to write its profile on exit).

See [`runtime/README.md`](runtime/README.md) for the runner's options and
gotchas.
