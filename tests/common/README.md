# Shared test infrastructure

Everything the runtime tier ([`../runtime/`](../runtime/)) builds on, and
what the conformance runs share with it (the device under test, the run
scripts). **No tests live here**, and `tests/pytest.ini`'s `testpaths`
never names this directory, so pytest never collects from it.

| | |
| --- | --- |
| `fixtures.py` | the fixtures, constants, helpers and pytest hooks of the runtime tier: builds and starts the DUT, waits for `RUNTIME_TEST_SERVER_READY`, performs the SPAKE2+ handshake and OSCORE provisioning, and yields the CoAP endpoint. Also `pytest_addoption` (`--run-record`) and `pytest_collection_modifyitems` (the module ordering). |
| `tools/` | `run-in-docker.ps1` / `run-in-docker.sh` (the supported way to run the device tiers), `run-local-ci.sh` (the in-container half, what CI runs), `run-local-ci-zephyr.sh` (against an external device). |
| `runtime_test_server.c` | the headless CoAP device under test. Built by `tests/CMakeLists.txt` to `build/<preset>/tests/runtime_test_server`. |
| `requirements.txt` | what the runtime tier needs; the conformance runs add the test tool's own `requirements.txt` (`../iot-test-tool/requirements.txt`). |

The wire-level clients (`transport.coap_client`, `transport.knx_oscore`,
`transport.knx_spake2plus`, `transport.mdns_client`) are not here: they are
part of the conformance-test tool, the git submodule
[`../iot-test-tool/`](../iot-test-tool/), and the runtime tier imports them
from there.

## How the tiers reach it

`tests/pytest.ini` sets `pythonpath = . common iot-test-tool`, relative to
the ini file, so for every runtime-tier run — whatever the working
directory — `sys.path` carries:

| entry | provides |
| --- | --- |
| `tests/` | `conftest.py` |
| `tests/common/` | `fixtures` |
| `tests/iot-test-tool/` | `transport.*`, `interpreter.*` (the run-record writer) |

so a test writes `from fixtures import DUT_IA, set_lsm` and `from
transport.coap_client import CoapClient`. With `KNX_TOOL_DIR` set to a
checkout of the tool, `tests/conftest.py` puts that checkout first on
`sys.path` instead of the submodule.

The conformance runs do not go through this ini: the tool's
`run_sequences.py` brings its own pytest configuration and is pointed at
this stack's override files with `--overrides tests/conformance`.

## Why `fixtures.py` and not `conftest.py`

pytest collects fixtures and hooks **only** from a file named
`conftest.py`, and a conftest is not importable under a stable module name
from a sibling directory. Both are needed here: the tests import constants
and helpers out of it by name (`from fixtures import MC_SCOPE`), *and*
pytest has to see its fixtures and hooks.

So the definitions live in this plain, importable module, and
`tests/conftest.py` is a short file that re-exports them into the
namespace pytest reads. Add a new `pytest_*` hook here and it must also be
named explicitly in `tests/conftest.py`'s import list.
