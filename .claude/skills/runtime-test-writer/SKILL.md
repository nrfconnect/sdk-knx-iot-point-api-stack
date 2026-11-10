---
name: runtime-test-writer
description: "Use when writing or changing a pytest runtime test in tests/runtime/ (full stack over real CoAP/OSCORE/IPv6 against runtime_test_server). Covers when such a test is allowed at all, how to write it and how to run it in Docker."
---

# Writing a runtime test

Runtime tests (`tests/runtime/test_<topic>.py`) drive the real device
(`tests/common/runtime_test_server.c`, the full stack) over UDP/IPv6 with
the transport clients of the test tool (submodule `tests/iot-test-tool/`).
No mocks.

## 1. Is a runtime test allowed?

The conformance tier already plays KNX's whole conformance-test template
against the device. A runtime test may exist only for behaviour the
template does not cover, or covers with a materially weaker assertion
(`tests/runtime/README.md`).

1. Look for a covering TestCase in the template (in the tool's cache:
   `python -m interpreter.knx_files dir` in `tests/iot-test-tool/` prints
   where). If it covers the behaviour with the same strength: stop, no test.
2. If the test asserts more than a template case does, mark it
   `@pytest.mark.eitt_overlap("5.3.8.1")`.
3. Never delete a runtime test without naming the template case that
   covers it.

## 2. Gather the facts

- Reference traces (recorded EITT runs against real hardware, ground truth
  for the wire): `tests/iot-test-tool/tests/fixtures/reference-traces/5_X.xml`
  (5.4 is `5_4_1.xml`). Decode `RawContent` with
  `cbor2.loads(bytes.fromhex(...))`; rows marked `Active="N"` were not run.
- The stack handler for the resource (e.g. `api/oc_knx_sec.c` for
  `/auth/*`): payload keys and types, preconditions, response codes. The
  device's C is the authority, not the RFC or memory.
- If the knx-iot-rag MCP server is configured: the test and API specs.
- 2-3 existing files in `tests/runtime/` for style.

## 3. Write it

- Name the file and the test functions for the behaviour
  (`test_write_at_and_verify`), never for an EITT id. An EITT id may appear
  in a docstring ("Overlaps EITT 5.3.8.1: ...").
- Fixtures from `tests/common/fixtures.py` (re-exported by
  `tests/conftest.py`): `coap` (unprotected), `oscore_ctx` (full-scope
  context `RtTest` / AT `RuntimeTest`), `device_host`, `device_iface`,
  `mc_scope`; helpers `auth_prepare`, `ia_prepare`, `set_lsm`,
  `parse_link_format`. Imports: `from transport.coap_client import ...`,
  `from transport.knx_oscore import OscoreContext`,
  `from fixtures import DUT_IA, set_lsm, ...`.
- Every assertion names the actual result:
  `assert resp is not None, "GET /x timed out"`, then
  `assert resp.is_successful, f"GET /x failed: {resp.code}"`.
- Use the fixtures' client and context; don't create clients, don't hard-code
  ports, don't `time.sleep()` for synchronisation (rely on CoAP timeouts).
- Clean up what the test creates (AT entries except `RuntimeTest`, tables,
  LSM state); later modules share the device.
- Don't assert that the mDNS address/port stays the same across a restart or
  reset; assert that the endpoint found again is reachable
  (`..._endpoint_reachable`).
- A deviation of the stack from the spec: keep the spec-correct assertion,
  mark the test `xfail(strict=False)` and list it under
  `KNOWN STACK DEVIATIONS` in the module docstring. When the stack is fixed
  (XPASS), remove the marker and the entry; never keep it as "resolved".
- A new module goes into `RUNTIME_MODULE_ORDER` in `tests/common/fixtures.py`
  at the position its device-state side effects need. Order is per test,
  not per class.

Payload formats, recipes (access tokens, LSM, group tables, multicast,
triggers, S-mode) and troubleshooting: [reference.md](reference.md).

## 4. Run it - only in Docker

```powershell
.\tests\common\tools\run-in-docker.ps1 -Tier runtime -IncludeUncommitted tests/runtime/test_<topic>.py -v
.\tests\common\tools\run-in-docker.ps1 -Tier runtime -IncludeUncommitted -k "<expr>"
```

The runner builds the server in the container. (`run-in-docker.sh` on
Linux; on Windows from PowerShell, not Git Bash.) Never run the
tier natively on the host: the device needs the veth pair and network
namespace only the container creates; a host run fails in ways that look
like regressions. CI: `runtime-gcc` collects the whole directory;
`runtime-asan-memcheck` runs it under ASan on schedule.

Iterate until the new tests pass; then run the whole runtime tier once,
since tests share device state.

## Rules

- Never change stack C code (`api/`, `messaging/`, `security/`, `port/`,
  `tests/common/runtime_test_server.c`) or `tests/common/fixtures.py` /
  `tests/conftest.py` without approval.
- Never edit `tests/iot-test-tool/` here; changes to the tool belong in its
  repository.
- No coverage counts in this skill: the overlap with the template is the
  `eitt_overlap` markers (`pytest tests/runtime -m eitt_overlap --collect-only -q`).
