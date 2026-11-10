# Unit tests: reference

Loaded on demand from SKILL.md.

## Initialization Patterns (Recipes)

Use these proven patterns based on what the module needs:

### Pattern A: No init needed (pure functions)

```cpp
#include <gtest/gtest.h>
#include <cstring>
extern "C" {
#include "module.h"
}

TEST(FunctionName, HappyPath) { /* ... */ }
```

Used by: `oc_base64`, `oc_uuid`, `oc_knx_fb`, `coap/oscore` (PIV/SSN helpers),
`coap/engine` (duplicate detection uses static history).

### Pattern B: oc_mmem_init() needed (string/alloc operations)

```cpp
extern "C" {
#include "oc_helpers.h"
#include "util/oc_mmem.h"
}

class OcHelpersTest : public ::testing::Test {
protected:
  void SetUp() override { oc_mmem_init(); }
};

TEST_F(OcHelpersTest, ConcatStrings) { /* ... */ }
```

Used by: `oc_helpers` (string ops), `oc_mmem`, `oc_rep` (parse with
`oc_parse_rep`, free with `oc_free_rep` in `TearDown`).

### Pattern C: PSA crypto init needed (security/HKDF/AEAD)

```cpp
extern "C" {
#include "security/oc_oscore_context.h"
#include "psa/crypto.h"
}

/* Global one-time setup — PSA crypto must init before any HMAC/AEAD */
class PsaCryptoEnv : public ::testing::Environment {
public:
  void SetUp() override { psa_crypto_init(); }
};
static auto *g_psa_env __attribute__((unused)) =
    ::testing::AddGlobalTestEnvironment(new PsaCryptoEnv);

TEST(ContextDeriveParam, SenderKey) { /* ... */ }
```

Used by: `oc_oscore_crypto`, `oc_oscore_context`.

### Pattern D: Mutex + message pool needed (CoAP transactions/observers)

```cpp
extern "C" {
#include "messaging/coap/transactions.h"
#include "port/oc_network_events_mutex.h"
#include "oc_buffer.h"
}

class CoapTransactions : public ::testing::Test {
protected:
  void SetUp() override {
    oc_network_event_handler_mutex_init();
  }
  void TearDown() override {
    coap_free_all_transactions();
    oc_network_event_handler_mutex_destroy();
  }
};
```

Used by: `coap/transactions`, `coap/observe`.

### Pattern E: Helper functions for test data

```cpp
/* Build a minimal endpoint for testing */
static oc_endpoint_t make_endpoint(uint16_t port)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = IPV6;
  ep.addr.ipv6.port = port;
  ep.addr.ipv6.address[15] = 1; /* ::1 */
  return ep;
}
```

---

## Troubleshooting (Common Build/Run Failures)

### Compilation Errors

| Symptom | Cause | Fix |
|---------|-------|-----|
| `error: 'struct_name' was not declared` | Missing `extern "C"` wrapper | Wrap the `#include` in `extern "C" { }` |
| `error: invalid conversion from 'void*' to 'type*'` | C allows implicit void* cast, C++ doesn't | Add explicit `(type*)` cast in test code OR use the value differently |
| `undefined reference to 'function_name'` | Function is `static` in .c file | Don't test it — test through public API instead |
| `undefined reference to 'oc_mmem_init'` | Missing link library | `kis_add_test` already links kisClientServer which has it — check include path |
| `multiple definition of 'variable'` | Global defined in header without `extern` | Include only the header you need, not the .c file |
| Warning: `__attribute__((unused))` on MSVC | GCC attribute not portable | Use `[[maybe_unused]]` for C++17, or `(void)var;` |

### Test Failures

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| Test hangs forever | Infinite loop in production code (e.g., circular linked list) | Use `GTEST_SKIP()` + document in FINDINGS.md |
| Segfault in SetUp | Init function requires prior init it depends on | Check init order — `oc_mmem_init()` before string ops, `psa_crypto_init()` before HKDF |
| Values differ between runs | Function depends on random/time | Test deterministic parts only, or seed with known value |
| Test passes locally, fails in CI | Platform difference (endianness, clock resolution, IPv6 availability) | Add `#ifdef` or `GTEST_SKIP()` for platform-specific tests |
| `EXPECT_EQ` on C strings fails | Comparing pointers not content | Use `EXPECT_STREQ` for null-terminated strings |
| Test pollutes other tests | Shared static state not cleaned | Add cleanup in `TearDown()` or use `_free_all` functions |

## Smart Test Generation Strategy

### Analyzing Functions for Testability

Before writing tests, classify each function in the module:

1. **Read the function signature** — what are the inputs and outputs?
2. **Trace the data flow** — does it read/write global state?
3. **Check for early returns** — each `if (...) return` is a test case
4. **Count code paths** — aim for at least one test per distinct path
5. **Look for implicit contracts** — buffer size assumptions, null checks, range limits

### Edge Case Discovery Checklist

For each function, systematically consider:

- **NULL inputs**: What happens if a pointer parameter is NULL?
- **Zero-length**: Empty string, zero count, zero size buffer
- **Boundary values**: 0, 1, `MAX-1`, `MAX`, `MAX+1` for integers
- **Buffer limits**: Exact fit, one byte short, way too small
- **Round-trip integrity**: encode(decode(x)) == x and decode(encode(x)) == x
- **Idempotency**: Calling twice with same input gives same result
- **Overflow**: UINT32_MAX, UINT64_MAX, negative values in unsigned contexts
- **Alignment**: Odd offsets for struct operations
- **Encoding specifics**: For CBOR/CoAP — single byte vs multi-byte encoding thresholds (0, 13, 269, 65805)

### Deciding What NOT to Test

Skip functions that:
- Are `static` (internal) — test through their public callers
- Require live networking (sockets, multicast)
- Require persistent filesystem storage that isn't mockable
- Only set global state with no public getter
- Are thin wrappers around platform APIs (`oc_clock_time()`, `oc_random_value()`)

Document skipped functions in the test file header comment with rationale.

---

## Platform / Dependency Handling

Some modules depend on platform initialization. Strategy by dependency level:

### Level 0 — Pure (no init)
Test directly. Examples: `oc_base64`, `oc_uuid`, `oc_cflags_as_string`.

### Level 1 — Light init
Use a test fixture with `SetUp()`/`TearDown()`. Examples:
- `oc_mmem_init()` for string/memory operations
- `psa_crypto_init()` for HKDF/AEAD operations
- `oc_network_event_handler_mutex_init()` for message allocation

### Level 2 — Static state concerns
Some modules use static arrays/lists (e.g., `coap/engine` duplicate history).
Tests must use unique MID/port values to avoid collisions with other test cases
running in the same process. Alternatively, call the module's `_free_all` or
`_clear` function in TearDown.

### Level 3 — Full stack required
Skip with documented rationale, or follow how the existing tests of
`oc_main`, `oc_discovery` and `oc_client_api` set the stack up.

---

