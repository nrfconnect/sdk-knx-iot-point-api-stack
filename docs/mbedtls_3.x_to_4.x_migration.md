# Mbed TLS 3.x to 4.x Migration Analysis

## Directories

| Purpose | Path |
| --- | --- |
| KNX-IoT Stack repo | `/data/Develop/KNX-IoT/gitlab.knx.org_-_public-projects_-_knx-iot-point-api-stack.git` |
| KNX-IoT Demos repo | `/data/Develop/KNX-IoT/gitlab.knx.org_-_public-projects_-_knx-iot-point-api_-_knx-iot-point-api-demos.git` |
| Zephyr RTOS v4.3.0 | `/data/Develop/Zephyr/Zephyr-RTOS` |
| Zephyr RTOS v4.3.0 Mbed TLS wrapper | `/data/Develop/Zephyr/Zephyr-RTOS/modules/mbedtls` (Zephyr integration layer; actual Mbed TLS source at `modules/crypto/mbedtls` requires `west update` and is not checked out locally) |
| Zephyr RTOS v4.4.0 | `/data/Develop/Zephyr_v4.4.x/Zephyr-RTOS` |
| Zephyr RTOS v4.4.0 Mbed TLS 4.1.0 module | `/data/Develop/Zephyr_v4.4.x/modules/crypto/mbedtls` |
| Zephyr RTOS v4.4.0 Mbed TLS 3.6.6 module | `/data/Develop/Zephyr_v4.4.x/modules/crypto/mbedtls-3.6` (kept for TF-M only) |
| Zephyr RTOS v4.4.0 ESP32 Mbed TLS component | `/data/Develop/Zephyr_v4.4.x/modules/hal/espressif/components/mbedtls` |

---

## Mbed TLS Versions

| Component | Version | Source |
| --- | --- | --- |
| KNX-IoT Stack (builtin) | **3.6.5** | `port/CMakeLists.txt` and `zephyr/CMakeLists.txt` (FetchContent from GitHub) |
| Zephyr v4.3.0 | **3.6.5** | `doc/releases/release-notes-4.3.rst` in the Zephyr repo |
| Zephyr v4.4.0 — main crypto module | **4.1.0** | `modules/crypto/mbedtls/zephyr/module.yml` (`cmake-ext: True`, `kconfig-ext: True`); confirmed by `ChangeLog` ("Mbed TLS 4.1.0 branch released 2026-03-31"). Zephyr GitHub issue [#102005](https://github.com/zephyrproject-rtos/zephyr/issues/102005) (CLOSED) confirms the migration from 3.6 to 4.0 was completed via PR #104031. |
| Zephyr v4.4.0 — compatibility module | **3.6.6** | `modules/crypto/mbedtls-3.6/zephyr/module.yml` (`cmake-ext: False`, `kconfig-ext: False`); confirmed by `ChangeLog` ("Mbed TLS 3.6.6 branch released 2026-03-31"). Kept **for TF-M only** until TF-M is bumped to v2.3 (comment in `west.yml`). CMake variable: `ZEPHYR_MBEDTLS_3_6_MODULE_DIR`. |

---

## Security Motivation for the Migration

This section summarises why the migration to PSA Crypto matters from a security
perspective, beyond the mechanical necessity of keeping up with a breaking API
change.

### 1. Key Isolation — Logical Separation of Key Material

In Mbed TLS 3.x, the application holds raw key bytes directly. An AES key for
OSCORE lives in a `mbedtls_ccm_context` on the heap or stack; a SPAKE2+ scalar
lives in a `mbedtls_mpi`. Any memory read — a buffer overrun, a debugger
session, a crash dump, or an accidental log — can expose the key bytes, because
they are ordinary memory the application owns.

In PSA, the application holds only a `psa_key_id_t`: a small opaque integer
handle. The actual key bytes are imported once into the PSA key store and are
never returned to the caller unless the key was explicitly created with
`PSA_KEY_USAGE_EXPORT`. Application code cannot form a pointer to them.

**Important caveat:** On a software-only embedded target (no TrustZone, no
secure element), the PSA key store is still in the same physical RAM as the
rest of the application. The isolation is *logical*, not physical:

- Key bytes do not appear in application stack frames, heap structs, or
  function arguments — accidental leakage paths are eliminated.
- A buffer overrun in application code does not *directly* reach the key store
  (it is a different allocation, managed by the library).
- Without `PSA_KEY_USAGE_EXPORT` the API will refuse to return the raw bytes,
  regardless of what the caller holds.

On hardware with TrustZone or a secure element the isolation becomes *physical*:
the PSA implementation runs in a separate security domain and the key bytes
never cross to the normal world. PSA is designed for this upgrade path — no
application code changes are required when moving from software-only to a
hardware-backed key store.

References:
- PSA key management API: https://arm-software.github.io/psa-api/crypto/1.1/api/keys/management.html

### 2. Algorithm Policy Enforcement

When a key is imported into the PSA key store, `psa_key_attributes_t` binds it
to a specific algorithm (e.g. `PSA_ALG_CCM`) and a set of usage flags (e.g.
`PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT`). The PSA layer rejects any
attempt to use that key for a different purpose at the API boundary — a key
imported for AES-CCM cannot be silently passed to an HMAC operation.

In Mbed TLS 3.x there is no such enforcement. A raw AES key is just bytes; it
can be passed to any cipher function without restriction.

References:
- PSA key policy API: https://arm-software.github.io/psa-api/crypto/1.1/api/keys/policy.html
- PSA key attributes: https://arm-software.github.io/psa-api/crypto/1.1/api/keys/attributes.html

### 3. Thread Safety

In Mbed TLS 3.x, `mbedtls_ctr_drbg_context` is a shared mutable object. The
KNX-IoT Stack exposes it via `oc_random_get_ctr_drbg_context()` so that
SPAKE2+ and the RNG layer can share the same generator instance. Access from
multiple RTOS threads without an explicit mutex is a data race.

The PSA Crypto layer manages its own global state internally and is
thread-safe. All callers simply call `psa_generate_random()` with no shared
context object. The `oc_random_get_ctr_drbg_context()` accessor and the shared
pointer are eliminated entirely.

References:
- Mbed TLS thread safety: https://mbed-tls.readthedocs.io/en/latest/kb/development/thread-safety-and-multi-threading/

### 4. Hardware Acceleration Readiness

PSA Crypto defines a driver interface through which a hardware crypto
peripheral — AES-CCM engine, SHA accelerator, hardware true RNG — can be
registered as a PSA driver. Application code calls the same
`psa_aead_encrypt()` or `psa_generate_random()` regardless of whether the
operation executes in software or on the hardware peripheral.

**Current situation on ESP32/Zephyr (verified in Zephyr 4.4.x source):**

| Peripheral | Used by Mbed TLS / PSA on Zephyr? | Notes |
|---|---|---|
| Hardware RNG | **Yes** | `zephyr_entropy.c` implements `mbedtls_psa_external_get_random()` via the Zephyr entropy driver (`entropy_esp32.c`). All calls to `psa_generate_random()` go through the ESP32 hardware RNG. |
| Hardware AES | **No** | `crypto_esp32_aes.c` exists in Zephyr 4.4.x but implements Zephyr's generic `crypto` driver API (`zephyr/crypto/cipher.h`), which is a separate subsystem. The Zephyr Mbed TLS 4.1.0 module has no ESP32 PSA driver shim for AES. AES-CCM in OSCORE runs in software. |
| Hardware SHA | **No** | Same situation as AES. `crypto_esp32_sha.c` is a Zephyr `crypto` API driver, not a PSA driver. SHA operations in Mbed TLS run in software. |

The KNX-IoT Stack's own private Mbed TLS 3.x build (via `FetchContent`) uses
no hardware acceleration at all — including RNG, which in that build comes from
the CTR-DRBG software PRNG seeded by the Zephyr entropy driver.

**What the PSA migration enables for the future:** PSA provides the standard
interface for registering hardware acceleration drivers. If Espressif or the
Zephyr project adds PSA driver shims for the ESP32 AES and SHA peripherals in
a future release, the KNX-IoT Stack would benefit automatically without any
changes to stack code. The migration to PSA now ensures the stack is on the
correct API to receive that benefit.

References:
- Hardware accelerated crypto porting: https://os.mbed.com/docs/mbed-os/v6.16/porting/hardware-accelerated-crypto.html
- Zephyr entropy integration for PSA: `modules/mbedtls/zephyr_entropy.c` in the Zephyr RTOS repo

### 5. CVEs Resolved in Mbed TLS 4.x

Mbed TLS 3.6 carried several published CVEs. The 4.x release line addresses
these, and the removal of the legacy API surface (which carried most of the
historical attack surface) reduces the area exposed to future vulnerabilities.

References:
- Mbed TLS security advisories: https://mbed-tls.readthedocs.io/en/latest/security-advisories/
- Mbed TLS GitHub releases (security fix details per release): https://github.com/Mbed-TLS/mbedtls/releases
- Mbed TLS 4.0 migration guide: https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-4.0.0/docs/4.0-migration-guide.md

---

## Analysis: Current KNX-IoT Stack

### 1. Mbed TLS Components Used

The stack uses Mbed TLS in four distinct areas:

#### 1.1 Random Number Generation (RNG)

Files: `port/oc_random.h`, `port/random_psa.c` (Linux/Windows), `port/zephyr/random.c`

| Header              | Types / Functions Used |
|---------------------|------------------------|
| `mbedtls/entropy.h` | `mbedtls_entropy_context`, `mbedtls_entropy_init`, `mbedtls_entropy_func`, `mbedtls_entropy_free` |
| `mbedtls/ctr_drbg.h` | `mbedtls_ctr_drbg_context`, `mbedtls_ctr_drbg_init`, `mbedtls_ctr_drbg_seed`, `mbedtls_ctr_drbg_random`, `mbedtls_ctr_drbg_free` |

The `mbedtls_ctr_drbg_context` pointer is exposed to the rest of the stack via `oc_random_get_ctr_drbg_context()` so that SPAKE2+ and TLS can share the same RNG instance.

#### 1.2 OSCORE Crypto

File: `security/oc_oscore_crypto.c`

| Header          | Types / Functions Used |
|-----------------|------------------------|
| `mbedtls/ccm.h` | `mbedtls_ccm_context`, `mbedtls_ccm_init`, `mbedtls_ccm_setkey` (`MBEDTLS_CIPHER_ID_AES`), `mbedtls_ccm_encrypt_and_tag`, `mbedtls_ccm_auth_decrypt`, `mbedtls_ccm_free` |
| `mbedtls/md.h`  | `mbedtls_md_context_t`, `mbedtls_md_init`, `mbedtls_md_setup`, `mbedtls_md_info_from_type` (`MBEDTLS_MD_SHA256`), `mbedtls_md_hmac_starts`, `mbedtls_md_hmac_update`, `mbedtls_md_hmac_finish`, `mbedtls_md_free` |

Note: OSCORE implements its own HKDF (RFC 5869) using the MD HMAC API directly instead of using `mbedtls_hkdf`.

#### 1.3 SPAKE2+

Files: `security/oc_spake2plus.c`, `security/oc_spake2plus.h`

| Header                | Types / Functions Used |
|-----------------------|------------------------|
| `mbedtls/ecp.h`       | `mbedtls_ecp_group`, `mbedtls_ecp_point`, `mbedtls_ecp_group_init/load/free`, `mbedtls_ecp_point_init/free/read_binary/write_binary/is_zero`, `mbedtls_ecp_gen_keypair`, `mbedtls_ecp_mul`, `mbedtls_ecp_muladd` |
| `mbedtls/bignum.h`    | `mbedtls_mpi`, `mbedtls_mpi_init/free/read_binary/write_binary/read_string/mod_mpi/sub_mpi/size` |
| `mbedtls/md.h`        | `mbedtls_md_context_t`, `mbedtls_md_init/setup/free`, `mbedtls_md_info_from_type` (`MBEDTLS_MD_SHA256`), `mbedtls_md_hmac` |
| `mbedtls/pkcs5.h`     | `mbedtls_pkcs5_pbkdf2_hmac()` — **deprecated in Mbed TLS 3.6**, superseded by `mbedtls_pkcs5_pbkdf2_hmac_ext()` |
| `mbedtls/hkdf.h`      | `mbedtls_hkdf` |
| `mbedtls/sha256.h`    | `mbedtls_sha256` (direct one-shot hash for transcript) |
| `mbedtls/ctr_drbg.h`  | `mbedtls_ctr_drbg_random` (used as callback, pointer passed in from RNG layer) |
| `mbedtls/entropy.h`   | Indirectly via `oc_random.h` |

Macros used: `MBEDTLS_MPI_CHK(f)` + `cleanup:` label pattern (error-handling idiom).

#### 1.4 TLS/DTLS

> **REMOVED.** The TLS/DTLS transport (`security/oc_tls.c`, `security/oc_tls.h`,
> guarded by `KNX_TCP_TLS`) has been deleted from the stack. TCP and TLS/DTLS
> transports are not supported; only UDP CoAP + OSCORE is. The section below is
> kept for historical context only — none of these files or headers exist any
> more, and `KNX_TCP_TLS` is no longer a recognised symbol.

Files: `security/oc_tls.c`, `security/oc_tls.h`

These files were compiled only when the preprocessor symbol `KNX_TCP_TLS` was defined, which no build configuration (Linux, Windows, or Zephyr) ever did. The code was therefore dormant for its entire lifetime, and both files have since been deleted.

| Header                          | Notes |
|---------------------------------|-------|
| `mbedtls/ssl.h`                 | Full DTLS/TLS stack |
| `mbedtls/ssl_cookie.h`          | DTLS cookie context |
| `mbedtls/ssl_internal.h`        | **Did not exist in Mbed TLS 3.x** (removed in 3.0), so this file could never have compiled. Moot now that it has been deleted. |
| `mbedtls/x509_crt.h`            | X.509 certificate handling (via `oc_tls.h`) |
| `mbedtls/timing.h`              | DTLS timeout |
| `mbedtls/memory_buffer_alloc.h` | Static buffer allocator (non-dynamic builds) |
| `mbedtls/oid.h`, `mbedtls/pkcs5.h`, `mbedtls/md.h`, `mbedtls/ctr_drbg.h`, `mbedtls/entropy.h` | Supporting crypto |

---

### 2. Is Mbed TLS Used for Something Besides SPAKE2+?

**Yes.** Mbed TLS is used for three independent purposes:

1. **RNG** — CTR-DRBG + entropy, used stack-wide for all random number generation.
2. **OSCORE encryption** — AES-CCM for OSCORE packet encryption/decryption; custom HKDF-SHA256 for OSCORE key derivation.
3. **SPAKE2+** — Full ECC (P-256), PBKDF2, HKDF, SHA-256, HMAC for the PASE handshake.
4. **TLS/DTLS** (dormant) — Complete TLS stack, currently inactive.

---

### 3. Current SPAKE2+ Workflow (PASE Handshake)

The following chart shows the SPAKE2+ implementation as found in `security/oc_spake2plus.c`.
Party A = Prover (Management Client, initiator).
Party B = Verifier (KNX device, responder).

```
Initialization (both parties, at stack startup):
┌──────────────────────────────────────────────────────────────────┐
│ oc_spake_init()                                                   │
│   mbedtls_ecp_group_init(&grp)                                   │
│   mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1)        │
│   pointer_to_ctr_drbg_ctx = oc_random_get_ctr_drbg_context()    │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
Step 1 — Parameter Exchange (Verifier B → Prover A):
┌──────────────────────────────────────────────────────────────────┐
│ oc_spake_parameter_exchange(rand[32], salt[32])                  │
│   mbedtls_ctr_drbg_random(ctx, rand,  32)                       │
│   mbedtls_ctr_drbg_random(ctx, salt,  32)                       │
│ → B sends rand and salt to A out-of-band                         │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
Step 2 — Password Expansion (both parties independently):
┌──────────────────────────────────────────────────────────────────┐
│ oc_spake_get_w0_L_params(salt, it, &w0, &L)                     │
│   oc_spake_calc_w0_L()                                          │
│     oc_spake_calc_w0_w1()                                       │
│       input = encode(password) || encode("") || encode("")       │
│                      [length-prefixed little-endian uint64]      │
│       [w0s || w1s] = PBKDF2-HMAC-SHA256(input, salt, it, 80 B) │
│                      (mbedtls_pkcs5_pbkdf2_hmac — DEPRECATED)   │
│       w0 = w0s mod N    (N = P-256 group order)                 │
│       w1 = w1s mod N                                            │
│     L = w1 × G          (mbedtls_ecp_mul)                       │
│                                                                   │
│ Note: L is computed by party B (Verifier) and stored.            │
│       Party A (Prover) derives w0 and w1 the same way.          │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
Step 3 — Key Generation and Public Shares:
┌──────────────────────────────────────────────────────────────────┐
│ Party A:                                                          │
│   (x, pub_x) = oc_spake_gen_keypair()   (mbedtls_ecp_gen_keypair)│
│   shareP = pub_x + w0 × M              (mbedtls_ecp_muladd)     │
│   (M = fixed P-256 constant from SPAKE2+ spec, uncompressed)     │
│                                                                   │
│ Party B:                                                          │
│   (y, pub_y) = oc_spake_gen_keypair()                            │
│   shareV = pub_y + w0 × N              (mbedtls_ecp_muladd)     │
│   (N = fixed P-256 constant from SPAKE2+ spec, uncompressed)     │
│                                                                   │
│ A → B: shareP (65 bytes, uncompressed P-256 point)               │
│ B → A: shareV (65 bytes, uncompressed P-256 point)               │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
Step 4 — Transcript and K_main (computed independently by each party):
┌──────────────────────────────────────────────────────────────────┐
│ Party B (Verifier / Responder):                                   │
│   Z = y × (shareP − w0 × M)           (calculate_Z_M)           │
│   V = y × L                           (mbedtls_ecp_mul)         │
│                                                                   │
│ Party A (Prover / Initiator):                                     │
│   Z = x × (shareV − w0 × N)           (calculate_ZV_N)          │
│   V = w1 × (shareV − w0 × N)          (calculate_ZV_N)          │
│                                                                   │
│ Both:                                                             │
│   TT = encode("knxpase")              [SPAKE_CONTEXT]            │
│      || encode(idProver="")                                       │
│      || encode(idVerifier="")                                     │
│      || encode_point(M)                                           │
│      || encode_point(N)                                           │
│      || encode_point(shareP)                                      │
│      || encode_point(shareV)                                      │
│      || encode_point(Z)                                           │
│      || encode_point(V)                                           │
│      || encode_mpi(w0)                                            │
│   K_main[32] = SHA-256(TT)            (mbedtls_sha256)           │
│                                                                   │
│ Note: encode_uint() uses little-endian uint64 length prefix.      │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
Step 5 — Key Confirmation:
┌──────────────────────────────────────────────────────────────────┐
│ KcA||KcB[64] = HKDF-SHA256(K_main, "", "ConfirmationKeys", 64)  │
│                             (mbedtls_hkdf)                       │
│                                                                   │
│ confirmV = HMAC-SHA256(KcB, shareP)   (oc_spake_calc_confirmV)  │
│ confirmP = HMAC-SHA256(KcA, shareV)   (oc_spake_calc_confirmP)  │
│                             (mbedtls_md_hmac)                    │
│                                                                   │
│ B → A: confirmV    A verifies confirmV.                          │
│ A → B: confirmP    B verifies confirmP.                          │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
Step 6 — Shared Key Derivation:
┌──────────────────────────────────────────────────────────────────┐
│ K_shared[16] = HKDF-SHA256(K_main, "", "SharedKey", 16)         │
│                             (oc_spake_calc_K_shared)             │
│ — or —                                                           │
│ K_shared[32] = HKDF-SHA256(K_main, "", "SharedKey", 32)         │
│                             (oc_spake_calc_K_shared_256)         │
│                                                                   │
│ K_shared is used as the OSCORE master secret.                    │
└──────────────────────────────────────────────────────────────────┘
```

---

### 4. How SPAKE2+ Is Implemented in the Current KNX-IoT Stack

SPAKE2+ is **not** part of the Mbed TLS library. It is implemented entirely from scratch in `security/oc_spake2plus.c` using Mbed TLS as a primitive provider.

The implementation assembles SPAKE2+ from the following primitives:

| Primitive            | Mbed TLS module    | Purpose in SPAKE2+ |
|----------------------|--------------------|--------------------|
| P-256 ECC group      | ECP (`SECP256R1`)  | Elliptic curve group for all point operations |
| Scalar multiplication | ECP (`ecp_mul`)   | L = w1×G, Z, V computations |
| Multi-scalar multiply | ECP (`ecp_muladd`) | shareP = pub + w0×M, shareV = pub + w0×N |
| Big integer arithmetic | BigNum (`mpi`)   | w0, w1 intermediate values, modular reduction |
| CTR-DRBG             | CTR_DRBG           | Ephemeral key generation, salt/rand generation |
| PBKDF2-HMAC-SHA256   | PKCS5              | Password → (w0s, w1s) stretching |
| SHA-256 (one-shot)   | SHA256             | Transcript hash → K_main |
| HKDF-SHA256          | HKDF               | Key confirmation keys and K_shared derivation |
| HMAC-SHA256          | MD                 | confirmV and confirmP computation |

The M and N constants (fixed SPAKE2+ P-256 points) are hardcoded as uncompressed 65-byte arrays. They were pre-computed using Python (`cryptography` module) to decompress the original compressed-point specification values.

The transcript encoding uses a custom little-endian uint64 length-prefix format implemented in `encode_uint()`, `encode_string()`, `encode_point()`, and `encode_mpi()`.

---

## References

- [Password-authenticated key agreement — Wikipedia](https://en.wikipedia.org/wiki/Password-authenticated_key_agreement)
- [PSA Crypto API 1.2 PAKE Extension — `PSA_ALG_SPAKE2P_HMAC`](https://arm-software.github.io/psa-api/crypto/1.2/ext-pake/api/pake.html#c.PSA_ALG_SPAKE2P_HMAC)
- [Roadmap: Bump Mbed TLS 3.6 → 4.0/TF-PSA-Crypto 1.0 — Zephyr Issue #102005](https://github.com/zephyrproject-rtos/zephyr/issues/102005) (CLOSED — migration completed via PR #104031)
- [Zephyr v4.4 Migration Guide — Mbed TLS section](https://docs.zephyrproject.org/latest/releases/migration-guide-4.4.html#mbed-tls)
- [Mbed TLS Releases — GitHub](https://github.com/Mbed-TLS/mbedtls/releases)
- [Mbed TLS 4.0 Migration Guide](https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-4.0.0/docs/4.0-migration-guide.md)
- [Mbed TLS 4.0 Migration Guide — TLS Options](https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-4.0.0/docs/4.0-migration-guide.md#changes-to-tls-options)
- [TF-PSA-Crypto PSA Transition — Compile-time Configuration](https://github.com/Mbed-TLS/TF-PSA-Crypto/blob/development/docs/psa-transition.md#compile-time-configuration)
- [TF-PSA-Crypto 1.0 Migration Guide (in mbedtls repo)](https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-4.0.0/tf-psa-crypto/docs/1.0-migration-guide.md)
- [TF-PSA-Crypto 1.0 Migration Guide (standalone repo)](https://github.com/Mbed-TLS/TF-PSA-Crypto/blob/development/docs/1.0-migration-guide.md)
- [TF-PSA-Crypto 1.0 Migration Guide — External RNG section](https://github.com/Mbed-TLS/TF-PSA-Crypto/blob/development/docs/1.0-migration-guide.md#if-you-have-a-fast-cryptographic-quality-external-random-generator)
- [Mbed TLS Issue #9378: Add MATTER support for SPAKE2+](https://github.com/Mbed-TLS/mbedtls/issues/9378) (OPEN — Backlog; depends on #9370)


---

## Migration from Mbed TLS 3.x to 4.x

### 1. What Needs to Change When Migrating from 3.6.5 to 4.x

> **Note:** Mbed TLS 4.1.0 is available locally at `/data/Develop/Zephyr_v4.4.x/modules/crypto/mbedtls`. The analysis below is confirmed from the [Mbed TLS 4.0 Migration Guide](https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-4.0.0/docs/4.0-migration-guide.md) and the [TF-PSA-Crypto 1.0 Migration Guide](https://github.com/Mbed-TLS/TF-PSA-Crypto/blob/development/docs/1.0-migration-guide.md).

#### Issues Already Present (3.x, Active Today)

These are problems that exist right now, regardless of any 4.x migration:

| Issue | File | Details |
|-------|------|---------|
| ~~`mbedtls/ssl_internal.h` included~~ | ~~`security/oc_tls.c`~~ | **RESOLVED — file removed.** `security/oc_tls.c` and the `KNX_TCP_TLS` TLS/DTLS transport have been deleted from the stack, so this header is no longer referenced anywhere. |

#### APIs Deprecated in 3.6.5 and Removed in Mbed TLS 4.x

| Deprecated API | Location in KNX-IoT Stack | Replacement |
|---|---|---|
| `mbedtls_pkcs5_pbkdf2_hmac(ctx, ...)` | `security/oc_spake2plus.c:204` | In 3.6.5: `mbedtls_pkcs5_pbkdf2_hmac_ext(md_type, ...)`. In 4.x: `psa_key_derivation_*` with `PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)`. |

The call site in `oc_spake_calc_w0_w1()` currently does the following (intermediate 3.6.5 fix, before the 4.x migration):

1. Initializes a `mbedtls_md_context_t ctx`.
2. Calls `mbedtls_md_setup(&ctx, ..., 1)` to configure it for HMAC.
3. Passes `&ctx` to `mbedtls_pkcs5_pbkdf2_hmac()`.

With `mbedtls_pkcs5_pbkdf2_hmac_ext()` this simplifies to a single call with `MBEDTLS_MD_SHA256` as the first argument, eliminating the need for the MD context setup.

#### APIs Removed in Mbed TLS 4.x (Confirmed)

**The PSA Crypto API is now the only API for cryptographic primitives** in Mbed TLS 4.x. All legacy algorithm-specific modules have been removed. `psa_crypto_init()` must be called before any cryptographic operation.

| API / Module | Used In | Status in 4.x | PSA Replacement |
|---|---|---|---|
| `mbedtls_entropy_context`, `mbedtls_entropy_*` | RNG | **REMOVED** | `psa_crypto_init()` initializes the global PSA RNG; use `psa_generate_random()` for random bytes |
| `mbedtls_ctr_drbg_context`, `mbedtls_ctr_drbg_*` | RNG, SPAKE2+, TLS | **REMOVED** | `psa_generate_random()` |
| `mbedtls_ecp_group`, `mbedtls_ecp_point`, full ECP API | SPAKE2+ | **REMOVED** | `psa_key_id_t` handles and `psa_*` functions for ECC operations |
| `mbedtls_mpi` / BigNum API | SPAKE2+ | Partially retained for algorithms not yet in PSA (e.g., WPA3/HostAP), but **no longer a public stable API** | No PSA equivalent for raw ECC math yet |
| `MBEDTLS_MPI_CHK` + `cleanup:` | SPAKE2+ | Removed along with public BigNum API | N/A |
| `mbedtls_hkdf` | SPAKE2+ | **REMOVED** | `psa_key_derivation_*` with `PSA_ALG_HKDF(PSA_ALG_SHA_256)` |
| `mbedtls_ccm_*` | OSCORE | **REMOVED** | `psa_aead_*` with `PSA_ALG_CCM` |
| `mbedtls_md_context_t`, `mbedtls_md_info_from_type`, `mbedtls_md_hmac` | OSCORE, SPAKE2+ | `md.h` retained with **reduced functionality** — most functions removed | `psa_mac_*`, `psa_hash_*` |
| `mbedtls_pkcs5_pbkdf2_hmac_ext` | SPAKE2+ | **REMOVED** | `psa_key_derivation_*` with `PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)` |

Note: The `oc_random_get_ctr_drbg_context()` function and the `mbedtls_ctr_drbg_context` pointer shared across SPAKE2+ and the RNG layer will both need to be removed. Since Mbed TLS 4.x uses a single global PSA RNG (initialized via `psa_crypto_init()`), the sharing mechanism becomes unnecessary — all callers simply call `psa_generate_random()` directly.

#### Config System

The KNX-IoT Stack uses a custom `knx_mbedtls_config.h` that `#define`s individual feature macros (e.g., `MBEDTLS_CCM_C`, `MBEDTLS_ECP_C`). In Mbed TLS 4.x the entire configuration system has been replaced: cryptographic feature selection moves to `psa/crypto_config.h` using `PSA_WANT_*` macros, and `mbedtls_config.h` retains only TLS/X.509 options. The `knx_mbedtls_config.h` approach is therefore invalid in 4.x and the file must be completely rewritten for any 4.x migration.

Notable existing issues in `security/knx_mbedtls_config.h`:

| Define | Status |
|--------|--------|
| `MBEDTLS_X509_EXPANDED_SUBJECT_ALT_NAME_SUPPORT` | Marked `TODO FIXME not in MBEDTLS library` |
| `MBEDTLS_SSL_BUFFER_MIN` | Marked `TODO FIXME not in MBEDTLS library` |
| `MBEDTLS_KEY_EXCHANGE_ECDH_ANON_ENABLED` | Marked `TODO FIXME not in MBEDTLS library` |
| `MBEDTLS_SSL_SRV_RESPECT_CLIENT_PREFERENCE` | Marked `TODO FIXME` — replaced by `mbedtls_ssl_conf_preference_order()` |

These should be resolved before migrating to 4.x.

---

### 2. Which Mbed TLS Version Does Zephyr v4.4.0 Use?

Zephyr v4.4.0 (at rc3 as of 2026-04-15) ships **two** Mbed TLS modules side by side (from `west.yml` in the Zephyr 4.4.0 repo):

| Module | `west.yml` name | Path | Version | cmake-ext / kconfig-ext | Purpose |
| --- | --- | --- | --- | --- | --- |
| Main crypto | `mbedtls` | `modules/crypto/mbedtls` | **4.1.0** | YES / YES | Zephyr's primary crypto library |
| Compatibility | `mbedtls-3.6` | `modules/crypto/mbedtls-3.6` | **3.6.6** | NO / NO | TF-M build only (until TF-M v2.3) |

The migration from Mbed TLS 3.6 to 4.0 in Zephyr was tracked in [issue #102005](https://github.com/zephyrproject-rtos/zephyr/issues/102005) and **completed** (issue closed, merged via PR #104031). Both versions are released as of 2026-03-31.

### 3. Can the KNX-IoT Stack Use the Zephyr mbedtls-3.6 Module?

**Yes, technically — with caveats.**

Zephyr 4.4.x provides Mbed TLS 3.6.6 at `ZEPHYR_MBEDTLS_3_6_MODULE_DIR`. The API is fully compatible with the current KNX-IoT Stack (3.6.5 → 3.6.6 is a security-patch release, no API changes). `knx_mbedtls_config.h` requires no modifications.

**Caveats:**

- The `mbedtls-3.6` module has `cmake-ext: False` and `kconfig-ext: False` — it is **not** automatically integrated into the Zephyr build system. It is present solely for TF-M. Its continued presence is not guaranteed beyond TF-M v2.3 adoption.
- The `mbedtls` (4.1.0) module is what Zephyr uses for all its own crypto. Running both 3.6.6 and 4.1.0 in the same build is possible only because the KNX-IoT stack builds its own private copy as a separate CMake target (via `FetchContent`).

**Changes needed in `zephyr/CMakeLists.txt`** under `CONFIG_KNXIOT_MBEDTLS_BUILTIN`:

```cmake
if(DEFINED ZEPHYR_MBEDTLS_3_6_MODULE_DIR)
    # Reuse the mbedtls-3.6 module already fetched by west — no separate download.
    FetchContent_Declare(mbedtls SOURCE_DIR "${ZEPHYR_MBEDTLS_3_6_MODULE_DIR}")
else()
    # Fallback: download as before (standalone build, or Zephyr older than 4.4).
    FetchContent_Declare(
        mbedtls
        URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.5/mbedtls-3.6.5.tar.bz2
        URL_HASH SHA256=4a11f1777bb95bf4ad96721cac945a26e04bf19f57d905f241fe77ebeddf46d8
        DOWNLOAD_EXTRACT_TIMESTAMP ON
    )
endif()
```

**Alternative (simpler, lower risk):** Keep the existing FetchContent approach unchanged. Both approaches result in Mbed TLS 3.6.x compiled as a private CMake target, fully isolated from the Zephyr `mbedtls` 4.1.0 targets. No symbol conflicts arise.

---

## SPAKE2+ in Mbed TLS

### 1. Can the SPAKE2+ Implementation Be Contributed to Mbed TLS?

#### What Mbed TLS Has Today

Mbed TLS 3.6.5 / 4.1.0 includes `mbedtls_ecjpake` (EC-JPAKE, RFC 8236) and PSA-level PAKE support via `psa_pake_*` operations. TF-PSA-Crypto 1.0 (the crypto submodule shipped with Mbed TLS 4.1.0) currently implements **only `PSA_ALG_JPAKE`** on secp256r1. SPAKE2+ is not present in any released version.

[Mbed TLS issue #9378](https://github.com/Mbed-TLS/mbedtls/issues/9378) (OPEN, Backlog — "Implement SPAKE2+" project) tracks adding `PSA_ALG_SPAKE2P_MATTER` support, which uses IETF draft-02 key derivation (not RFC 9383). It depends on issue #9370 and has no delivery date. The PSA API extension for SPAKE2+ is defined at [`PSA_ALG_SPAKE2P_HMAC`](https://arm-software.github.io/psa-api/crypto/1.2/ext-pake/api/pake.html#c.PSA_ALG_SPAKE2P_HMAC) (PSA Crypto API 1.2 PAKE extension), but is not yet implemented in any Mbed TLS release.

#### What an Upstream Contribution Would Require

To contribute SPAKE2+ to Mbed TLS, the implementation would need to:

1. **Follow the PSA PAKE API** (`psa_pake_setup/input/output/get_implicit_key`), since that is the direction Mbed TLS is moving for interactive key-agreement protocols. The current KNX-IoT implementation uses the legacy ECP and BigNum APIs directly — both of which are removed in Mbed TLS 4.x.

2. **Separate KNX-specific choices from the protocol.** The current implementation hardcodes:
   - The transcript context string `"knxpase"` (KNX-specific).
   - Empty prover and verifier ID strings.
   - A non-standard 80-byte PBKDF2 output and custom encode format.
   - The decision not to check the cofactor (relying on secp256r1 h=1).

3. **Implement the standard SPAKE2+ transcript** as defined in RFC 9383 (SPAKE2+). The current implementation pre-dates or diverges from the RFC in the transcript encoding format (little-endian uint64 length prefix vs. the RFC format).

4. **Port to the PSA driver interface** if the goal is to allow hardware acceleration.

**Conclusion:** The current implementation is KNX-specific and not directly upstreamable in its present form. A standards-conforming PSA-based SPAKE2+ implementation would need to be written from scratch following the Mbed TLS contribution guidelines. The Mbed TLS team does have SPAKE2+ on their roadmap (issue #9378), but specifically targets the MATTER variant and has no timeline. Whether a KNX-oriented contribution is worthwhile depends on project priority and coordination with the Mbed TLS team.

---

## SPAKE2+ Migration Design (Mbed TLS 4.x)

### 1. API Split: Private ECP/BigNum vs. PSA

Mbed TLS 4.x removes all public legacy crypto APIs. SPAKE2+ needs two categories of primitives:

| Primitive | PSA equivalent? | API used in 4.x migration |
|-----------|----------------|--------------------------|
| Random bytes | Yes | `psa_generate_random()` |
| PBKDF2-HMAC-SHA256 | Yes | `psa_key_derivation_*` with `PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)` |
| HKDF-SHA256 | Yes | `psa_key_derivation_*` with `PSA_ALG_HKDF(PSA_ALG_SHA_256)` |
| HMAC-SHA256 | Yes | `psa_mac_compute()` with `PSA_ALG_HMAC(PSA_ALG_SHA_256)` |
| SHA-256 (one-shot) | Yes | `psa_hash_compute(PSA_ALG_SHA_256, ...)` |
| P-256 key generation | Yes | `psa_generate_key()` + `psa_export_key()` + `psa_export_public_key()` |
| P-256 scalar multiply (ecp_mul) | **No** | `mbedtls_ecp_mul()` — private TF-PSA-Crypto API |
| P-256 multi-scalar multiply (ecp_muladd) | **No** | `mbedtls_ecp_muladd()` — private TF-PSA-Crypto API |
| Big integer modular reduction (w0s mod N) | **No** | `mbedtls_mpi_mod_mpi()` — private TF-PSA-Crypto API |

The raw ECC arithmetic (point multiplication, multi-scalar multiply) and big integer modular reduction have no PSA equivalents in Mbed TLS 4.1.0. They are accessible via the private internal headers in TF-PSA-Crypto:

- `mbedtls/private/ecp.h` — `mbedtls_ecp_group`, `mbedtls_ecp_point`, and all `mbedtls_ecp_*` functions.
- `mbedtls/private/bignum.h` — `mbedtls_mpi` and all `mbedtls_mpi_*` functions.

These headers are located at `tf-psa-crypto/drivers/builtin/include/` within the Mbed TLS source tree. They require `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS` to be defined before inclusion to unlock the struct definitions. This is intentional: Mbed TLS itself still uses these interfaces internally (documented limitation; see Mbed TLS 4.0 migration guide, section "Usage of private declarations"). The `MBEDTLS_ALLOW_PRIVATE_ACCESS` macro may also be needed in some configurations.

**Use within the KNX-IoT stack:** The private headers are included only in `security/oc_spake2plus.c`. No other file in the KNX-IoT stack touches the private ECP/BigNum API. The additional include path (`${mbedtls_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/include`) is added as a PRIVATE include on the security source target in CMake.

**Relation to upstreaming:** Code contributed *into* TF-PSA-Crypto (e.g. as a driver or core module) always has access to these private interfaces — the `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS` guard is always active within the library tree. The KNX-IoT implementation is structured so that `oc_spake2plus.c` can be moved into the TF-PSA-Crypto source tree with minimal changes.

### 2. spake_data_t: Byte Arrays Instead of Mbed TLS Types

The 3.x `spake_data_t` struct exposed `mbedtls_mpi` and `mbedtls_ecp_point` fields directly:

```c
// 3.x — exposed Mbed TLS types in the public struct
typedef struct {
  mbedtls_mpi w0;
  mbedtls_ecp_point L;
  mbedtls_mpi y;
  mbedtls_ecp_point pub_y;
  uint8_t K_main[32];
} spake_data_t;
```

This forced every caller (`oc_knx.c`) to:
- Include `mbedtls/bignum.h` and `mbedtls/ecp.h` (both removed in 4.x as public headers).
- Call `mbedtls_mpi_init`, `mbedtls_ecp_point_init`, `mbedtls_mpi_free`, `mbedtls_ecp_point_free` directly.
- Define `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS` just to allocate the struct on the stack.

In the 4.x migration, `spake_data_t` uses plain byte arrays:

```c
// 4.x — opaque byte arrays, no Mbed TLS types exposed
typedef struct {
  uint8_t w0[32];              // w0 scalar, big-endian
  uint8_t L[kPubKeySize];      // L = w1*G, uncompressed P-256 point
  uint8_t y[32];               // private ephemeral scalar, big-endian
  uint8_t pub_y[kPubKeySize];  // y*G, uncompressed P-256 point
  uint8_t K_main[32];          // transcript hash SHA-256(TT)
} spake_data_t;
```

**Benefits:**
- Callers need no Mbed TLS headers — only `<stdint.h>` and `<stddef.h>`.
- Callers need no init/free calls — the struct is zero-initialized and needs no cleanup.
- All private ECP/BigNum code is confined to `oc_spake2plus.c`.
- Matches the pattern a future PSA PAKE API would use (opaque internal state).

**Alignment with a future PSA SPAKE2+ API:** The PSA PAKE operations (`psa_pake_operation_t`) are fully opaque to callers. The byte-array design of `spake_data_t` is the closest currently achievable approximation of that pattern, and makes a later transition to a `psa_pake_operation_t`-based API straightforward.

### 3. CMake: Private Include Path

Building `oc_spake2plus.c` with the private headers requires an additional include path that is not exposed by the Mbed TLS CMake targets. It is added as a PRIVATE include directory in `CMakeLists.txt` (Linux/Windows) and `zephyr/CMakeLists.txt` (Zephyr):

Linux/Windows (`CMakeLists.txt`, inside `if(CONFIG_KNXIOT_MBEDTLS_BUILTIN)`):
```cmake
# Note:
# oc_spake2plus.c uses private TF-PSA-Crypto ECP/BigNum headers for raw
# P-256 point arithmetic that has no PSA equivalent in Mbed TLS 4.x.
# See docs/mbedtls_3.x_to_4.x_migration.md, section "SPAKE2+ Migration Design".
target_include_directories(kisClientServer PRIVATE
    "${mbedtls_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/include"
)
```

Zephyr (`zephyr/CMakeLists.txt`, inside `if(CONFIG_KNXIOT_MBEDTLS_BUILTIN)`):
```cmake
# Note:
# oc_spake2plus.c uses private TF-PSA-Crypto ECP/BigNum headers for raw
# P-256 point arithmetic that has no PSA equivalent in Mbed TLS 4.x.
# See docs/mbedtls_3.x_to_4.x_migration.md, section "SPAKE2+ Migration Design".
zephyr_library_include_directories(
    "${mbedtls_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/include"
)
```

### 4. `oc_knx.c`: Caller Update

With the new byte-array `spake_data_t`, the caller (`api/oc_knx.c`) no longer needs to include any Mbed TLS headers or manage struct member lifecycles. All `mbedtls_mpi_init`, `mbedtls_ecp_point_init`, `mbedtls_mpi_free`, and `mbedtls_ecp_point_free` calls on `spake_data_t` fields are replaced with `memset(&spake_data, 0, sizeof(spake_data))`. The local `mbedtls_ecp_point pB` variable and the now-removed `oc_spake_encode_pubkey()` call are replaced by passing `g_pase.shareV` (a `uint8_t[65]`) directly to `oc_spake_calc_shareV()`, which now writes the encoded point directly into the output buffer.

### 5. `spake2plus.c`: Which mbedTLS Calls Were Replaced and Why

All `mbedtls_xxx` crypto functions used in `spake2plus.c` fall into two categories in
Mbed TLS 4.x:

**Category A — Removed from public API, PSA equivalent available:** These functions no
longer exist in any public Mbed TLS 4.x header and must be replaced with the PSA Crypto
API.

| Removed mbedTLS 3.x call                                                        | PSA 4.x replacement                                                          |
| -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `mbedtls_ctr_drbg_random(ctx, buf, n)`                                          | `psa_generate_random(buf, n)`                                                |
| `mbedtls_ecp_gen_keypair(&grp, &priv, &pub, ...)`                               | `psa_generate_key` + `psa_export_key` / `psa_export_public_key`             |
| `mbedtls_pkcs5_pbkdf2_hmac` / `mbedtls_pkcs5_pbkdf2_hmac_ext`                  | `psa_key_derivation_*` with `PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)`          |
| `mbedtls_hkdf(...)`                                                              | `psa_key_derivation_*` with `PSA_ALG_HKDF(PSA_ALG_SHA_256)`                 |
| `mbedtls_sha256(input, len, output, 0)`                                          | `psa_hash_compute(PSA_ALG_SHA_256, ...)`                                     |
| `mbedtls_md_hmac(info, key, klen, input, ilen, output)`                          | `psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), ...)`               |

**Category B — No PSA equivalent, moved to private headers:** These functions remain in
the Mbed TLS 4.x source tree but are no longer part of the public API. They are accessed
in `spake2plus.c` via `mbedtls/private/ecp.h` and `mbedtls/private/bignum.h` with
`MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS` defined before the includes (see §3).

| mbedTLS call (still used via private header)                                     | Reason there is no PSA replacement                                           |
| -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `mbedtls_ecp_group_init` / `_load` / `_free`                                    | PSA has no API for managing raw group state                                  |
| `mbedtls_ecp_point_init` / `_free` / `_write_binary` / `_read_binary`           | PSA has no API for raw point encoding or decoding                            |
| `mbedtls_ecp_mul(&grp, &Z, &scalar, &point, ...)`                               | No PSA equivalent for arbitrary-point scalar multiplication                  |
| `mbedtls_ecp_muladd(&grp, &out, &a, &A, &b, &B)`                               | No PSA equivalent for multi-scalar (Shamir's trick) multiplication           |
| `mbedtls_mpi_init` / `_free` / `_read_binary` / `_write_binary` / `_mod_mpi`   | No PSA equivalent for arbitrary big integer modular arithmetic               |

Using private headers is intentional and documented: the Mbed TLS project explicitly
supports this access pattern for operations that cannot yet be expressed in the PSA API
(see the [Mbed TLS 4.0 migration guide](https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-4.0.0/docs/4.0-migration-guide.md),
section "Usage of private declarations"). This access is isolated entirely to
`spake2plus.c` — no other file in the KNX-IoT stack touches the private ECP/BigNum API.

---

## OSCORE Crypto Migration (Mbed TLS 4.x)

### 1. `security/oc_oscore_crypto.c`

The OSCORE crypto layer uses two Mbed TLS subsystems that are removed in 4.x:

| Old (3.x) | New (4.x) |
|-----------|-----------|
| `mbedtls/md.h` — `mbedtls_md_context_t`, `mbedtls_md_init/setup/free`, `mbedtls_md_hmac_starts/update/finish` | `psa/crypto.h` — `psa_import_key`, `psa_mac_compute(PSA_ALG_HMAC(PSA_ALG_SHA_256))`, `psa_destroy_key` |
| `mbedtls/ccm.h` — `mbedtls_ccm_context`, `mbedtls_ccm_init`, `mbedtls_ccm_setkey(MBEDTLS_CIPHER_ID_AES)`, `mbedtls_ccm_encrypt_and_tag`, `mbedtls_ccm_auth_decrypt`, `mbedtls_ccm_free` | `psa/crypto.h` — `psa_import_key`, `psa_aead_encrypt / psa_aead_decrypt` with `PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, tag_len)`, `psa_destroy_key` |

#### `HMAC_SHA256` helper

The 3.x implementation used a streaming `mbedtls_md_context_t`:

```c
// 3.x
mbedtls_md_context_t ctx;
mbedtls_md_init(&ctx);
mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
mbedtls_md_hmac_starts(&ctx, key, key_len);
mbedtls_md_hmac_update(&ctx, data, data_len);
mbedtls_md_hmac_finish(&ctx, hmac);
mbedtls_md_free(&ctx);
```

`mbedtls_md_context_t` and the `mbedtls_md_hmac_*` streaming API are removed from the
public headers in Mbed TLS 4.x. The replacement is a one-shot PSA call with a transient
key:

```c
// 4.x
psa_import_key(&attr, key, key_len, &key_id);
psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), data, data_len, hmac, ...);
psa_destroy_key(key_id);
```

The `HKDF_Extract` / `HKDF_Expand` / `HKDF_SHA256` functions that call this helper are
**unchanged**. They implement RFC 5869 HKDF directly and use `HMAC_SHA256` only as a
primitive — migrating them to `psa_key_derivation_*` with `PSA_ALG_HKDF` would have
required restructuring the iteration logic for no functional benefit.

#### `oc_oscore_encrypt` / `oc_oscore_decrypt` and `OSCORE_AEAD_MAX_PAYLOAD_LEN`

> **Note:** The approach described in this section was the initial migration solution.
> It was subsequently superseded by source-level analysis that confirmed in-place
> operation is safe for AES-CCM in TF-PSA-Crypto. See the section below for the
> current implementation.

The 3.x `mbedtls_ccm_encrypt_and_tag` API had this contract:

- Accepted **separate** output pointers for ciphertext and tag.
- **Supported in-place operation**: `plaintext == ciphertext_out` was valid.
- Callers in `oc_oscore_engine.c` relied on this: `coap_pkt->payload` was passed as
  both input and output, encrypting the CoAP payload buffer in-place.

The PSA replacement `psa_aead_encrypt` has a different contract:

- Writes **`ciphertext || tag` concatenated** into a single output buffer.
- The PSA specification **does not guarantee correctness** when input and output alias
  the same memory region.

Changing all callers in `oc_oscore_engine.c` to pass separate buffers would be a larger
refactor. Instead the fix is localised inside `oc_oscore_encrypt` and `oc_oscore_decrypt`:
PSA writes to an intermediate stack buffer, which is then `memcpy`-ed back to the caller's
buffer (which may be the same address as the input):

```c
uint8_t tmp[OSCORE_AEAD_MAX_PAYLOAD_LEN];
psa_aead_encrypt(key_id, alg, nonce, nonce_len, AAD, AAD_len,
                 plaintext, plaintext_len, tmp, sizeof(tmp), &out_len);
memcpy(output, tmp, out_len);   // output may equal plaintext
```

`OSCORE_AEAD_MAX_PAYLOAD_LEN` (1400 bytes) exists because the intermediate buffer must
have a compile-time size on embedded targets. The value covers the maximum OSCORE payload
in a CoAP/UDP datagram: IPv6 minimum MTU (1280 B) minus UDP header (8 B) and a typical
CoAP/OSCORE header overhead (~50 B), with a conservative margin. Payloads that would
overflow the buffer are rejected at the top of each function before any crypto operation
begins.

This constant is **permanent** — `psa_aead_encrypt` always requires a pre-allocated
output buffer, so the bound is not a temporary workaround but a fixed requirement of the
PSA API design.

#### In-place operation confirmed safe — `OSCORE_AEAD_MAX_PAYLOAD_LEN` removed

After the initial migration the CCM implementation in
`tf-psa-crypto/drivers/builtin/src/ccm.c` was audited to determine whether the 1400-byte
intermediate buffer was actually necessary. The conclusion is that it is not, and it was
removed.

**CCM encrypt path** (`mbedtls_ccm_update`, encrypt branch):

1. `mbedtls_xor(ctx->y, ctx->y, input, use_len)` — CBC-MAC reads `input` into internal
   state `ctx->y`. The `input` pointer is not written at this point.
2. `mbedtls_ccm_crypt(ctx, offset, use_len, input, output)` — CTR-mode XOR:
   `output[i] = input[i] ^ keystream[i]`. The keystream comes from AES-ECB of the
   counter register, which does not read `input` or `output`. Writing `output[i]`
   in-place is therefore safe even when `output == input`.
3. The tag is written by `mbedtls_ccm_finish` at `ciphertext + plaintext_length`,
   past the last written ciphertext byte. The caller's buffer (inside `msg->data`,
   a large fixed allocation) always has room there.

**CCM decrypt path** (`mbedtls_ccm_update`, decrypt branch):

The Mbed TLS implementation already handles the aliasing case explicitly. The source
comment reads: *"Since output may be in shared memory, we cannot be sure that it will
contain what we wrote to it. Therefore, we should avoid using it as input to any
operations."* Each 16-byte block is decrypted into a `local_output[16]` stack buffer,
the CBC-MAC XOR is performed on that local copy, then `memcpy` writes to `output`.
This per-block buffer was already present and incurs no additional cost.

**No overlap check exists** at any level of the call stack:

- `psa_aead_encrypt` / `psa_aead_decrypt` — when `MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS`
  is not defined (the normal embedded build), `LOCAL_INPUT_ALLOC` and `LOCAL_OUTPUT_ALLOC`
  simply assign the pointer: `input_copy = input`. No copy, no overlap check.
- PSA AEAD driver wrapper (`psa_crypto_aead.c`) — passes pointers straight through to
  `mbedtls_ccm_encrypt_and_tag` / `mbedtls_ccm_auth_decrypt`.
- `ccm.c` — no overlap or aliasing check of any kind.

**Result:** `OSCORE_AEAD_MAX_PAYLOAD_LEN`, the `tmp[]` buffer, the size guard checks,
and the trailing `memcpy` calls were removed from `oc_oscore_encrypt` and
`oc_oscore_decrypt`. `psa_aead_encrypt` and `psa_aead_decrypt` are called directly with
`output == plaintext` / `output == ciphertext`, restoring the original 3.x in-place
behaviour with no stack overhead.

### 2. `security/oc_oscore_engine.c`

The one call to `oc_random_get_ctr_drbg_context()` + `mbedtls_ctr_drbg_random()` (used to fill the 10-byte echo nonce in s-mode) is replaced with:

```c
psa_generate_random(rnd, sizeof(rnd));
```

`#include "psa/crypto.h"` is added at the top of the file. The `oc_random_get_ctr_drbg_context()` function and its declaration in `port/oc_random.h` were already removed during the RNG migration step (Step 5).

---

## Config File Migration (`knx_mbedtls_config.h` / `knx_psa_crypto_config.h`)

### 1. Stack includes in the PSA config file

`knx_mbedtls_config.h` included a KNX-IoT stack config header:

```c
#include <oc_config.h>      /* OC_PKI */
```

> **REMOVED.** PKI is not supported and `OC_PKI` was never defined by any build
> configuration, so the `OC_PKI`-guarded blocks and this include were deleted from
> `knx_mbedtls_config.h`. The include-directory plumbing described below is still
> required: `knx_psa_crypto_config.h` includes `port/oc_assert.h` for `oc_exit`.

This works because `port/CMakeLists.txt` adds the stack's include directories to all
tf-psa-crypto CMake sub-targets after `FetchContent_MakeAvailable(mbedtls)`.

In Mbed TLS 3.x there was a single `mbedcrypto` target. In Mbed TLS 4.x the crypto
library is split into many internal sub-targets, each of which compiles the config
files independently. The stack include dirs must therefore be added to every
sub-target explicitly (guarded with `if(TARGET …)` because not all drivers are
enabled in every build):

```cmake
set(MBEDTLS_INCLUDE_DIRS
    PRIVATE "${PROJECT_SOURCE_DIR}"
    PRIVATE "${PROJECT_SOURCE_DIR}/include"
    PRIVATE "${PORT_DIR}"                   # port/linux or port/windows — provides oc_config.h
)
target_include_directories(tfpsacrypto ${MBEDTLS_INCLUDE_DIRS})
target_include_directories(mbedtls     ${MBEDTLS_INCLUDE_DIRS})
target_include_directories(mbedx509    ${MBEDTLS_INCLUDE_DIRS})
foreach(_tgt builtin p256-m everest pqcp extras platform utilities)
    if(TARGET ${_tgt})
        target_include_directories(${_tgt} ${MBEDTLS_INCLUDE_DIRS})
    endif()
endforeach()
```

The same pattern is used in `zephyr/CMakeLists.txt` with `port/zephyr` as `PORT_DIR`.

### 2. Dual config file split (Mbed TLS 4.x requirement)

In Mbed TLS 4.x the configuration is split across two files.  Platform and memory
options that Mbed TLS 3.x accepted in `MBEDTLS_CONFIG_FILE` must now be defined in
`TF_PSA_CRYPTO_CONFIG_FILE`; if they appear in the wrong file
`mbedtls_config_check_user.h` emits a `#error` (which is treated as `-Werror`).

| Option group | 3.x location | 4.x location |
| --- | --- | --- |
| `MBEDTLS_PLATFORM_C`, `MBEDTLS_PLATFORM_MEMORY`, `MBEDTLS_PLATFORM_EXIT_ALT`, `MBEDTLS_PLATFORM_NO_STD_FUNCTIONS`, `MBEDTLS_PLATFORM_SNPRINTF_ALT` | `knx_mbedtls_config.h` | `knx_psa_crypto_config.h` |
| `MBEDTLS_PLATFORM_STD_CALLOC`, `MBEDTLS_PLATFORM_STD_FREE`, `MBEDTLS_PLATFORM_STD_EXIT`, `MBEDTLS_PLATFORM_STD_SNPRINTF` | `knx_mbedtls_config.h` | `knx_psa_crypto_config.h` |
| `MBEDTLS_MEMORY_BUFFER_ALLOC_C` (static-alloc path) | `knx_mbedtls_config.h` | `knx_psa_crypto_config.h` |

### 2. DRBG requirement

`MBEDTLS_PSA_CRYPTO_C` requires either `MBEDTLS_CTR_DRBG_C` or `MBEDTLS_HMAC_DRBG_C`
to be enabled (used internally to seed the PSA RNG).  The 3.x config omitted both
because the application managed its own `mbedtls_ctr_drbg_context`.  In 4.x the PSA
layer owns the RNG; `MBEDTLS_CTR_DRBG_C` is added to `knx_psa_crypto_config.h`.

### 3. Removed option: `MBEDTLS_OID_C`

`MBEDTLS_OID_C` was removed in Mbed TLS 4.0.  OID support is now unconditionally
compiled in whenever any X.509 module is enabled.  The define must not appear in
either config file.

In the old config, the automatic-dependencies cascade
`MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED` → `MBEDTLS_X509_CRT_PARSE_C` →
`MBEDTLS_X509_USE_C` → `MBEDTLS_OID_C` ran unconditionally and caused a build error
even though `KNX_TCP_TLS` was not active.  It was first fixed by guarding
`MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED` and the entire automatic-dependencies
block with `#ifdef KNX_TCP_TLS`.

> **SUPERSEDED.** `KNX_TCP_TLS` and the TLS/DTLS transport have since been removed
> from the stack. The guarded automatic-dependencies block and the TLS
> key-exchange defines (`MBEDTLS_KEY_EXCHANGE_PSK_ENABLED`,
> `MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED`, `MBEDTLS_PSK_MAX_LEN`,
> `MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED`) were deleted from
> `knx_mbedtls_config.h` outright, so the cascade can no longer occur.

### 4. Migrated TLS record size macro

`MBEDTLS_SSL_MAX_CONTENT_LEN` was split in Mbed TLS 4.x into two separate macros:

| 3.x                                          | 4.x                                           |
| -------------------------------------------- | --------------------------------------------- |
| `MBEDTLS_SSL_MAX_CONTENT_LEN (OC_PDU_SIZE)`  | `MBEDTLS_SSL_IN_CONTENT_LEN  (OC_PDU_SIZE)`   |
|                                              | `MBEDTLS_SSL_OUT_CONTENT_LEN (OC_PDU_SIZE)`   |

Both are set to `OC_PDU_SIZE` (same as before).  Adjust independently if in and out
sizes need to differ when TLS is activated.

### 5. Removed invalid options

The following options in the 3.x config were never valid Mbed TLS macros (or were
removed in 4.x) and have been deleted:

| Option | Reason |
| --- | --- |
| `MBEDTLS_X509_EXPANDED_SUBJECT_ALT_NAME_SUPPORT` | Not a standard Mbed TLS option in any version. |
| `MBEDTLS_SSL_BUFFER_MIN 512` | Not a standard Mbed TLS option.  TLS buffer sizing uses `MBEDTLS_SSL_IN/OUT_CONTENT_LEN` (4.x) — see §4 above. |
| `MBEDTLS_KEY_EXCHANGE_ECDH_ANON_ENABLED` | Not in Mbed TLS.  Anonymous ECDH cipher suites are not supported. |
| `MBEDTLS_SSL_SRV_RESPECT_CLIENT_PREFERENCE` | Removed in Mbed TLS 4.x. Use `mbedtls_ssl_conf_preference_order()` at runtime instead (Fixes #4398). |

---

## Zephyr `knx-iot-common.conf` Migration (Mbed TLS 4.x)

When `CONFIG_KNXIOT_MBEDTLS_BUILTIN=n` the Zephyr-provided Mbed TLS is used. In
Zephyr 4.4.0 this is Mbed TLS 4.1.0, which replaces the old `MBEDTLS_*` Kconfig
module toggles with `PSA_WANT_*` Kconfig symbols (defined in
`modules/mbedtls/Kconfig.psa.auto`).

The following symbols from the 3.x `knx-iot-common.conf` are no longer valid in
Zephyr 4.4.0 and must be replaced:

| Removed (3.x Kconfig) | Replacement (4.x Kconfig) |
| --- | --- |
| `CONFIG_MBEDTLS_ECP_C=y` | `CONFIG_PSA_WANT_ALG_ECDH=y` + `CONFIG_PSA_WANT_ECC_SECP_R1_256=y` |
| `CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED=y` | `CONFIG_PSA_WANT_ECC_SECP_R1_256=y` |
| `CONFIG_MBEDTLS_HKDF_C=y` | `CONFIG_PSA_WANT_ALG_HKDF=y` |
| `CONFIG_MBEDTLS_PKCS5_C=y` | `CONFIG_PSA_WANT_ALG_PBKDF2_HMAC=y` |
| `CONFIG_MBEDTLS_CIPHER_AES_ENABLED=y` | `CONFIG_PSA_WANT_KEY_TYPE_AES=y` |
| `CONFIG_MBEDTLS_CIPHER_CCM_ENABLED=y` | `CONFIG_PSA_WANT_ALG_CCM=y` |

Additional symbols required by the KNX-IoT stack that have no direct old equivalent
(select the full set of PSA key types and algorithms used by OSCORE and SPAKE2+):

Note: `PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC` is not user-settable — it is derived
automatically by Zephyr's `Kconfig.psa.logic` whenever any of the `IMPORT`, `EXPORT`,
`GENERATE`, or `DERIVE` key pair sub-features are selected. Do not set it directly.

```kconfig
CONFIG_PSA_WANT_ALG_SHA_256=y
CONFIG_PSA_WANT_ALG_HMAC=y
CONFIG_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE=y
CONFIG_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT=y
CONFIG_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT=y
CONFIG_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY=y
CONFIG_PSA_WANT_KEY_TYPE_HMAC=y
CONFIG_PSA_WANT_KEY_TYPE_DERIVE=y
CONFIG_PSA_WANT_KEY_TYPE_RAW_DATA=y
CONFIG_MBEDTLS_PSA_CRYPTO_C=y
CONFIG_MBEDTLS_ENTROPY_C=y
CONFIG_MBEDTLS_CTR_DRBG_C=y
```

Note: When OpenThread is used, many of these are auto-selected via Kconfig select
chains (`OPENTHREAD_ECDSA`). On non-OpenThread backends (e.g. Wi-Fi) they must be
listed explicitly in `knx-iot-common.conf`.

---

## SPAKE2+ Refactoring (Post-Migration Cleanup)

After the Mbed TLS 4.x migration was functional, the SPAKE2+ implementation was
refactored to make it generic and suitable for future upstream contribution to Mbed TLS.

### 1. File and Function Renames

The files were renamed to remove the `oc_` prefix, which denotes KNX-IoT-stack-specific
code — the SPAKE2+ implementation is generic:

| Old                         | New                      |
| --------------------------- | ------------------------ |
| `security/oc_spake2plus.c`  | `security/spake2plus.c`  |
| `security/oc_spake2plus.h`  | `security/spake2plus.h`  |

Renamed via `git mv` to preserve history.

All public API functions were renamed to drop the `oc_` prefix and use the `spake2plus_`
prefix consistently:

| Old name                                           | New name                                          |
| -------------------------------------------------- | ------------------------------------------------- |
| `oc_spake_init`                                    | `spake2plus_init`                                 |
| `oc_spake_free`                                    | `spake2plus_free`                                 |
| `oc_spake_parameter_exchange`                      | `spake2plus_parameter_exchange`                   |
| `oc_spake_get_w0_L_params`                         | `spake2plus_get_w0_L_params`                      |
| `oc_spake_gen_keypair`                             | `spake2plus_gen_keypair`                          |
| `oc_spake_calc_shareP`                             | `spake2plus_calc_shareP`                          |
| `oc_spake_calc_shareV`                             | `spake2plus_calc_shareV`                          |
| `oc_spake_calc_transcript_responder` (KNX wrapper) | removed — caller passes KNX constants directly    |
| `calc_transcript_responder`                        | `spake2plus_calc_transcript_responder`            |
| `calc_transcript_initiator`                        | `spake2plus_calc_transcript_initiator`            |
| `oc_spake_calc_confirmV`                           | `spake2plus_calc_confirmV`                        |
| `oc_spake_calc_confirmP`                           | `spake2plus_calc_confirmP`                        |
| `oc_spake_calc_K_shared`                           | `spake2plus_calc_K_shared`                        |
| `oc_spake_calc_K_shared_256`                       | `spake2plus_calc_K_shared_256`                    |
| `oc_initialise_spake_data` (in `oc_knx.c`)         | `oc_spake2plus_init_data`                         |

Internal-only static functions (`spake_calc_w0_w1`, `spake_calc_w0_L`) were also
renamed to `spake2plus_calc_w0_w1` / `spake2plus_calc_w0_L`.

### 2. KNX-IoT Constants Moved Out of the Generic Files

All KNX-IoT-specific constants were removed from `spake2plus.h` and moved to
`include/oc_knx.h` (the only caller). The generic implementation receives them as
function parameters:

| Constant | Old location | New location |
|----------|-------------|--------------|
| `KNX_IOT_SPAKE2PLUS_CONTEXT "knxpase"` | `oc_spake2plus.h` | `include/oc_knx.h` |
| `KNX_IOT_SPAKE2PLUS_ID_PROVER ""` | `oc_spake2plus.h` | `include/oc_knx.h` |
| `KNX_IOT_SPAKE2PLUS_ID_VERIFIER ""` | `oc_spake2plus.h` | `include/oc_knx.h` |
| `KNX_IOT_SPAKE2PLUS_SALT_LENGTH (32)` | was `KNX_SALT_LEN` in `.c` | `include/oc_knx.h` |
| `KNX_IOT_SPAKE2PLUS_RND_LENGTH (32)` | was `KNX_RNG_LEN` in `.c` | `include/oc_knx.h` |

The `SALT_LENGTH` and `RND_LENGTH` constants are used as array dimensions in `oc_pase_t`
(`salt[KNX_IOT_SPAKE2PLUS_SALT_LENGTH]`, `rnd[KNX_IOT_SPAKE2PLUS_RND_LENGTH]`) and
call sites use `sizeof()` to pass the lengths, keeping them in sync with the struct.

`app_get_password()` was removed from `spake2plus.c` entirely — the password is now
passed as an explicit parameter at the call site in `api/oc_knx.c`.

### 3. Preprocessor Macro Renames

| Old macro | New macro |
|-----------|-----------|
| `OC_SPAKE` | `KNX_IOT_SPAKE2PLUS` |
| `OC_SPAKE_IT` | `KNX_IOT_SPAKE2PLUS_ITERATIONS` |
| `KNX_SPAKE_ITERATIONS` (CMake) | `KNX_IOT_SPAKE2PLUS_ITERATIONS` |
| `KNXIOT_SPAKE_ITERATIONS` (Kconfig) | `KNXIOT_SPAKE2PLUS_ITERATIONS` |

The `#ifdef KNX_IOT_SPAKE2PLUS` / `#endif` guard was removed from `spake2plus.c` —
conditional compilation is now controlled entirely by whether `spake2plus.c` is included
in the CMake source list (guarded with `# TODO KNX_IOT_SPAKE2PLUS always on?`).

### 4. Variable Naming (Non-RFC Names)

Parameter and local variable names that used abbreviations were renamed to full words
with `_length` as a consistent postfix. Names that appear in RFC 9383 (e.g. `olen`,
`idProver`, `idVerifier`, `ttlen`) are kept unchanged to aid readability against the
specification.

| Old | New |
|-----|-----|
| `password_len` | `password_length` |
| `len_salt` | `salt_length` |
| `rand_len`, `salt_len` | `rand_length`, `salt_length` |
| `id_p_len`, `id_v_len` | `id_prover_length`, `id_verifier_length` |
| `len_input` | `input_length` |
| `output_len` (in `derive_K_shared`) | `output_length` |

### 5. RFC Reference Correction

Several comments in `include/oc_knx.h` and the key-translation table incorrectly
attributed the field names `shareP`, `shareV`, `confirmP`, `confirmV` to RFC 9382.
RFC 9382 defines **SPAKE2** (not SPAKE2+) and uses `pA/pB/cA/cB`. The correct
reference is **RFC 9383** (SPAKE2+), which uses the names matching the struct fields.
All comments have been updated accordingly.

### 6. `oc_knx.c` Caller Changes Explained

#### `&` removed from `spake_data.y` and `spake_data.pub_y`

In the 3.x code these fields were `mbedtls_mpi y` and `mbedtls_ecp_point pub_y`, so
`&spake_data.y` and `&spake_data.pub_y` yielded the correct pointer types
(`mbedtls_mpi *`, `mbedtls_ecp_point *`).

In the 4.x migration the fields are `uint8_t y[32]` and `uint8_t pub_y[65]`.
In C an array expression already decays to a pointer to its first element, so
`spake_data.y` is of type `uint8_t *` — which is exactly what `spake2plus_gen_keypair`
expects. Writing `&spake_data.y` would produce `uint8_t (*)[32]` (a pointer-to-array),
which is the wrong type. The `&` is therefore correctly absent.

#### Local `pB` variable and `oc_spake_encode_pubkey()` removed

The 3.x code used a local `mbedtls_ecp_point pB` as an intermediate:

```c
mbedtls_ecp_point pB;
mbedtls_ecp_point_init(&pB);
ret = oc_spake_calc_shareV(&pB, &spake_data.pub_y, &spake_data.w0);
// on success:
ret = oc_spake_encode_pubkey(&pB, g_pase.shareV);   // convert ecp_point → byte array
mbedtls_ecp_point_free(&pB);
```

In the 4.x migration `spake2plus_calc_shareV` (via the internal `calculate_pX`) writes
the encoded uncompressed point directly into `g_pase.shareV` (a `uint8_t[65]`).
The separate encode step is now internal to `calculate_pX` via `ecp_point_to_bytes`.

**Error-case safety:** `ecp_point_to_bytes` is only reached if all preceding
`MBEDTLS_MPI_CHK` steps succeed; on any failure the `goto cleanup` path skips it and
`g_pase.shareV` is left unwritten — identical to the 3.x behaviour where
`oc_spake_encode_pubkey` was never called on error. The `mbedtls_ecp_point_free`
cleanup that was the caller's responsibility in 3.x is now handled inside
`calculate_pX` itself via its own `goto cleanup` block.

#### `sizeof()` is safe for `salt` and `rnd`

`oc_pase_t` declares these fields as fixed-size arrays:

```c
uint8_t salt[KNX_IOT_SPAKE2PLUS_SALT_LENGTH];   // = uint8_t[32]
uint8_t rnd[KNX_IOT_SPAKE2PLUS_RND_LENGTH];     // = uint8_t[32]
```

Because `g_pase.salt` and `g_pase.rnd` are struct member arrays (not pointers),
`sizeof(g_pase.salt)` and `sizeof(g_pase.rnd)` evaluate to `32` at compile time —
always correct and always in sync with the actual buffer size. No separate length
constant is needed at the call site.

#### Why `rnd` keeps its abbreviated name

`rnd` is the KNX-IoT wire name for the random nonce field (CoAP integer key 15, as
shown in the key-translation table in the Doxygen block above `oc_pase_t`). Renaming
it would diverge from the specification mapping. The struct comment clarifies:
`// random nonce (wire name "rnd", KNX_IOT_SPAKE2PLUS_RND_LENGTH bytes)`.

### 7. CMakeLists and Kconfig

`spake2plus.c` is added unconditionally to `CORE_SOURCES` in both `CMakeLists.txt`
and `zephyr/CMakeLists.txt` (with a `TODO KNX_IOT_SPAKE2PLUS always on?` comment
matching the existing note on the compile-definitions line). The existing comment
blocks in the CMakeLists files that referred to `oc_spake2plus.c` have been updated
to `spake2plus.c`.
