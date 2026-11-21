# KNX IoT Point API Stack - Test Catalog

> **2140 unit tests** on `linux-test-asan-clang` (67 files in `tests/unit/`, counted by CTest on 2026-11-14, including the
> `test_dns_sd_mdns.cpp` cases registered under `if(UNIX)` only) and **297 runtime tests** (20 files in `tests/runtime/`, collected
> on 2026-11-11).
> The conformance tier is not listed here: the test tool
> (`tests/iot-test-tool/`) generates it from KNX's conformance-test template,
> one item per template sequence, with this stack's override files in
> `tests/conformance/`. All three tiers share `tests/common/`, the map is
> [`README.md`](README.md).
>
> Unit (2026-11-12): 2136/2136 passed on `linux-test-asan-clang` and `linux-test-gcc` (Docker), 2087/2087 on `windows-test-gcc`.
> Runtime and conformance: see "Last runtime run status" below.

## Contents

- [Last runtime run status](#last-runtime-run-status) (runtime and conformance tier)
- [Part 1: Unit tests](#unit-tests) (Google Test, `tests/unit/`)
- [Part 2: Runtime tests](#runtime-tests) (pytest, `tests/runtime/`)
  - [Skipped tests](#skipped-tests)
  - [Known bugs](#known-bugs)
- Conformance tier (EITT template, test tool): not listed here, see [`README.md`](README.md)

---

<a id="last-runtime-run-status"></a>
## Last runtime run status

| | Current run | Previous run | Earlier run |
|---|---|---|---|
| Date | 2026-11-09 (`oc_helpers` finding F-048) | 2026-11-03 (payload paths, findings F-030 ... F-034) | 2026-11-03 (4.13 + Size1, s-mode envelope) |
| **Unit tests** | **1913/1913** passed (`linux-test-asan`, Docker) | **1752/1752** passed (`windows-test-gcc`); `linux-test-asan` not run | **1747/1747** passed (`windows-test-gcc`); `linux-test-asan` not run |
| **Conformance tests** (test tool, KNX template) | **8 passed, 1 xfailed** (5.10, 361.76s) | **8 passed, 1 xfailed** (5.10, 361.64s) | **8 passed, 1 xfailed** (5.10): full run 7 passed + 5.6 failed (late 2.04 to an earlier request, token mismatch, in "Copy of AUTH PREPARATION"); 5.6 alone passed |
| **Runtime tests** | **288 passed, 5 skipped** (293 collected, 810.45s) | **288 passed, 5 skipped** (293 collected, 810.20s) | **287 passed, 5 skipped** (292 collected, 801.90s, with the Block1 transfer test) |
| Failed / errors | 0 / 0 | 0 / 0 | full run 2 / 0 (conformance 5.6, passed alone; runtime 766 B test that asserted the old RST behaviour, replaced), after the re-runs 0 / 0 |
| Runner | Docker `linux-test-asan` (ctest); `run-in-docker.ps1 -Tier conformance` and `-Tier runtime` | Docker `linux-test-gcc`, `run-in-docker.ps1 -Tier all -IncludeUncommitted` | Docker `linux-test-gcc`, `run-in-docker.ps1 -Tier all -IncludeUncommitted`, re-runs `-Tier conformance -Section 5.6` and `-Tier runtime` |
| Covers | F-048: string join size, exact `oc_url_cmp()`, bounded `_` search and prefix check in the URI wildcard helpers, add-item NULL guards, `unsigned char` ctype casts, compare/free of empty handles, `oc_helpers.h` contracts; single-loop `oc_conv_hex_string_to_byte_array()` | client response 513 ... 768 B without Block2; /p notification above the observer's block size (Block2); token updated in place (observers follow the new scope); datagram above OC_PDU_SIZE dropped (`TestDatagramAboveReceiveBuffer`); dead declaration `coap_remove_observers_on_dos_change` removed | request without Block1 above one block -> 4.13 with Size1 = block size (was RST); s-mode envelope limited to one block (`OC_S_MODE_ENVELOPE_BUDGET`); `test_payload_below_max_is_not_rejected_with_413` (766 B) replaced by `test_payload_of_one_block_is_not_rejected_with_413` (512 B); protected 650 B POST /fp/g in two Block1 blocks reassembled (`TestOscoreBlock1Transfer`) |
| Not in the run | `windows-test-gcc` ctest | ASan | ASan |

No stack C code was changed to make a test pass.

---

<a id="unit-tests"></a>
## Part 1: Unit Tests (Google Test / C++)

Built with GCC, run via CTest. 69 `.cpp` files in `tests/unit/`.

---

### test_oc_knx_hooks.cpp — KNX Hooks of the Lower Layers (3 tests)

**Source:** `src/resources/knx/oc_knx_hooks.c` (`src/messaging/coap/coap_knx_hooks.h`). The CTest `LayeringCheck.LowerLayersUseOnlyTheirKnxHooks` (`cmake/check_layering.cmake`, no `.cpp`) fails when `src/messaging/`, `src/security/` or `src/port/` include an `oc_knx*.h` or call `oc_knx_*()` / `oc_core_*()` instead of their hooks header.

| Test | What it verifies |
|------|-----------------|
| `SModeUnicastResult.ThreeMissingResponsesKeepTheAddress` | Three s-mode unicast requests without a response: the recipient stays resolved, count 3 |
| `SModeUnicastResult.FourthMissingResponseResolvesTheAddressAgain` | The fourth one sets the recipient back to unresolved and resets the count |
| `SModeUnicastResult.AResponseResetsTheMissingCount` | A 2.04 resets the count, three further misses keep the address |

---

### test_oc_base64.cpp — Base64 Encoding (14 tests)

**Source:** `src/util/oc_base64.c`

| Test | What it verifies |
|------|-----------------|
| `EmptyInput` | Empty input produces empty output |
| `SingleByte` | 1 byte → 4 base64 chars |
| `TwoBytes` | 2 bytes → correct `=` padding |
| `ThreeBytes` | 3 bytes → 4 chars (no padding) |
| `SixBytes` | 6 bytes → 8 chars |
| `OutputBufferTooSmall` | Returns -1 when output buffer is too short |
| `ValidFourCharNoPadding` | Known encoded string → correct bytes |
| `ValidWithOnePad` | Handles `=` padding correctly |
| `ValidWithTwoPads` | Handles `==` padding correctly |
| `InvalidLength` | Non-multiple-of-4 input rejected |
| `InvalidCharacter` | Returns -1 on non-base64 characters |
| `PaddingInWrongPosition` | Mid-string padding rejected |
| `BinaryData` | encode(decode(x)) round-trip for binary data |
| `AllByteValues` | Round-trip for all 256 byte values |

---

### test_oc_uuid.cpp — UUID Handling (19 tests)

**Source:** `src/util/oc_uuid.c`

| Test | What it verifies |
|------|-----------------|
| `UuidStrToUuid.KnownUuid` | Standard UUID string parses correctly |
| `UuidStrToUuid.UppercaseHex` | Uppercase hex digits accepted |
| `UuidStrToUuid.WildcardStar` | `*` produces all-zeros UUID |
| `UuidStrToUuid.ShorterThanUuidLenDoesNotOverread` | String shorter than 36 bytes leaves `id` zeroed, no OOB read |
| `UuidStrToUuid.HighBitByteDoesNotMisbehave` | High-bit byte with no canonical dashes is rejected, `id` zeroed |
| `UuidStrToUuid.TooFewDashesDoesNotOverwrite` | Non-canonical dash placement rejected before any byte write; stack canary intact |
| `UuidStrToUuid.InvalidHexDigitIsRejected` | Canonical dashes but a non-hex character → `id` zeroed |
| `UuidToStr.KnownUuid` | Known UUID → correct string with hyphens |
| `UuidToStr.AllZeros` | All-zero UUID → "00000000-..." |
| `UuidToStr.AllOnes` | All-0xFF UUID → "ffffffff-..." |
| `UuidToStr.BufferTooSmall` | Short buffer handled safely |
| `UuidToStr.WildcardStar` | All-zeros → "*" |
| `UuidToStr.NullUuidDoesNotCrash` | `NULL` uuid pointer leaves the buffer untouched |
| `UuidToStr.IdZeroButNotAllZeroRemainderFormatsNormally` | `id[0]==0x2a` with a non-zero remainder formats as normal hex, not "*" |
| `UuidRoundTrip.StringToBinaryToString` | str→uuid→str round-trip |
| `UuidGenerate.ProducesValidFormat` | `oc_gen_uuid` output is canonical 8-4-4-4-12 hex |
| `UuidGenerate.ProducesVersion4` | Generated UUID has version nibble set to 4 |
| `UuidGenerate.RoundTripsThroughString` | Generated UUID survives uuid→str→uuid |
| `UuidGenerate.ProducesDistinctValues` | Two generations do not collide |

---

### test_oc_list.cpp — Linked List (27 tests)

**Source:** `src/util/oc_list.c`

| Test | What it verifies |
|------|-----------------|
| `Init_ListIsEmpty` | New list has length 0, head/tail NULL |
| `Add_SingleItem` | One item: head == tail == item |
| `Add_MultipleItems_OrderPreserved` | Items appended in order |
| `Push_AddsToHead` | Item becomes new head |
| `Push_RemovesDuplicate` | Push existing item moves it to head |
| `Pop_RemovesHead` | Returns and removes first item |
| `Pop_UntilEmpty` | Repeated pop empties list |
| `Pop_EmptyList_ReturnsNull` | No crash on empty list |
| `Chop_RemovesTail` | Returns and removes last item |
| `Chop_SingleItem` | Single-item list → empty |
| `Chop_EmptyList_ReturnsNull` | No crash on empty list |
| `Head_EmptyList_ReturnsNull` | Returns NULL |
| `Tail_EmptyList_ReturnsNull` | Returns NULL |
| `HeadTail_SingleItem_AreSame` | Single item is both head and tail |
| `Remove_Head` | Removes first item, second becomes head |
| `Remove_Middle` | Removes middle item, list stays connected |
| `Remove_Tail` | Removes last item, previous becomes tail |
| `Remove_Nonexistent_NoOp` | No effect, no crash |
| `Length_EmptyList` | Returns 0 |
| `Length_AfterAddRemove` | Correct after add/remove |
| `Insert_AfterItem` | Item inserted after given item |
| `Insert_NullPrev_PushesToHead` | Equivalent to push |
| `Insert_AtTail` | Item inserted after tail |
| `Copy_SharesElements` | Copies all items to new list |
| `Copy_EmptyList` | Empty list copies safely |
| `ItemNext_WalkList` | Iteration via next pointers works |
| `ItemNext_Null_ReturnsNull` | NULL input returns NULL |

---

### test_oc_mmem.cpp — Managed Memory (9 tests)

**Source:** `src/util/oc_mmem.c`

| Test | What it verifies |
|------|-----------------|
| `AllocByte_ReturnsNonNull` | Byte allocation succeeds |
| `AllocByte_MemoryIsWritable` | Allocated memory can be written/read |
| `AllocInt_ReturnsNonNull` | Int allocation succeeds |
| `AllocFloat_ReturnsNonNull` | Float allocation succeeds; regression for missing `break` falling through to `DOUBLE_POOL` |
| `AllocFloat_MemoryIsWritable` | Allocated float memory can be written/read |
| `AllocDouble_ReturnsNonNull` | Double allocation succeeds |
| `AllocNull_ReturnsZero` | NULL/zero input returns 0 |
| `Free_ClearsSize` | Free sets size to 0 and ptr to NULL (no dangling pointer) |
| `MultipleAllocFree` | Multiple alloc/free cycles work |

---

### test_oc_helpers_alloc_fail.cpp — Allocation Failure in the String Layer (8 tests)

**Source:** `src/util/oc_mmem.c`, `src/util/oc_helpers.c`; linked with `-Wl,--wrap=malloc`, `__wrap_malloc()` fails the next call once a test arms it, and `-Wl,--wrap=free`, `__wrap_free()` overwrites the first byte of one armed block with 'X' before it is released

| Test | What it verifies |
|------|-----------------|
| `MmemAllocLeavesAnEmptyHandle` | a failed `malloc` in `oc_mmem_alloc()` returns 0 and leaves ptr NULL, size 0 (no length for a NULL buffer) |
| `NewStringLeavesAnEmptyString` | `oc_new_string()` on a failed `malloc` leaves an empty string instead of copying into NULL |
| `NewByteStringLeavesAnEmptyString` | same for `oc_new_byte_string()` |
| `ConcatStringsLeavesAnEmptyString` | same for `oc_concat_strings()` |
| `NewStringArrayLeavesAnEmptyArray` | `oc_new_string_array()` on a failed `malloc` leaves ptr NULL, size 0 |
| `NotArmedAllocationWorks` | without arming, the wrap passes the call to the real `malloc` |
| `StringCopyOfItselfKeepsTheValue` | `oc_string_copy(&s, s)` and `oc_string_copy_from_char(&s, oc_string(s))` keep "abc": the copy is made before the old (poisoned) block is freed, and the old block is still freed |
| `ByteStringCopyOfItselfKeepsTheValue` | same for `oc_byte_string_copy(&s, s)` |

---

### test_oc_helpers.cpp — String & Hex Utilities (99 tests)

**Source:** `src/util/oc_helpers.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `Uint64ToDec` | 4 | uint64 → decimal string (0, 42, MAX, power of 10) |
| `Uint64ToHex` | 5 | uint64 → hex string (0, small, large, MAX, leading zeros) |
| `ByteArrayToHex` | 4 | Binary → hex conversion, edge cases |
| `HexToByteArray` | 5 | Hex → binary, odd length, empty, round-trip |
| `UriWildcardInt` | 6 | Extracts integer from wildcard URI; prefix mismatch and zero-length resource rejected (F-048-4) |
| `UriWildcardString` | 4 | Extracts string from wildcard URI; prefix mismatch and zero-length resource rejected (F-048-4) |
| `UriFbValue` | 8 | Extracts FB number/instance from URI; `_` search bounded by the invoked length (F-048-3), prefix mismatch and zero-length resource rejected (F-048-4) |
| `Strnchr` | 3 | Character search with length limit |
| `ToLower` | 4 | String lowercase conversion |
| `ZeroContent` | 4 | Checks if buffer is all zeros |
| `OcStringTest` | 31 | String alloc/free/copy/compare/concat/url-compare (exact match, empty href/handle, F-048-2), hex-string conversion, is-hex-array checks (empty handle, non-ASCII byte, F-048-7), compare of empty handles (F-048-8) |
| `OcStringArrayTest` | 13 | String-array alloc, add-item (overflow/NULL string/empty array/NULL byte array, F-048-6), join (empty items, exact size, frees previous value, NULL arguments, F-048-1), byte-array add |
| `OcArrayPool` | 2 | Int-array allocation yields usable storage; free of NULL and empty handles is ignored (F-048-9) |
| `PrintUint64` | 3 | uint64 decimal/hex printing |

---

### test_c_timestamp.cpp — Timestamp Parsing (28 tests)

**Source:** `src/util/c-timestamp/`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `TimestampParse` | 9 | RFC 3339 parsing: UTC, offsets, fractional, invalid, leap day |
| `TimestampFormat` | 4 | Timestamp → string formatting, buffer too small |
| `TimestampRoundTrip` | 1 | parse → format → parse preserves value |
| `TimestampCompare` | 5 | Less/equal/greater comparisons (sec, nsec) |
| `TimestampValid` | 6 | Validates ranges (nsec, offset min/max) |
| `TimestampToTm` | 3 | Converts to struct tm (epoch, known date, invalid) |

---

### test_oc_rep.cpp — CBOR Representation (91 tests)

**Source:** `src/resources/ri/oc_rep.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `New/EncoderBuf` | 2 | Buffer initialization |
| `SetInt` | 5 | Integer encode/decode (positive, negative, large, wrong key, NULL) |
| `SetBool` | 2 | Boolean true/false |
| `SetDouble/Float` | 2 | Floating point |
| `SetTextString` | 2 | String encode (including NULL) |
| `SetByteString` | 1 | Binary data |
| `MultipleValues` | 1 | Mixed types in single map |
| `Arrays` | 3 | Int/bool/double arrays |
| `StringArray/ByteStringArray truncation` | 5 | Text/byte string array items at exactly the 32-byte slot limit round-trip unmodified; oversized items are truncated (not left as heap-uninitialized garbage) and never overflow the fixed-size slot (F-021 follow-up) |
| `ToJson` | 19 | JSON serialization: compact/pretty/size-query (3, pre-existing) plus per-type coverage of `oc_rep_to_json_format`'s switch: bool-false, double, text string, base64-encoded byte string, nested object, int/float/double/bool/string arrays (compact + pretty for string array), byte-string array (compact + pretty), object array (compact + pretty); the size query `(NULL, 0)` on a byte string returns exactly the written length without arithmetic on the NULL buffer |
| `AddLineToBuffer` | 3 | Buffer append helpers |
| `EncodeRaw` | 1 | Raw CBOR append |
| `FreeRep/Parse` | 2 | Cleanup and empty-map parse |
| `TextKey getters` | 6 | Text-keyed getters (int, bool, double, float, string, byte string NULL checks) |
| `GetString/ByteString` | 2 | NULL size parameter handling |
| `GetCborErrno` | 2 | CBOR errno reporting (clean encode, overflow) |
| `EncodeRawEncoder` | 1 | `oc_rep_encode_raw_encoder()` writes bytes and advances |
| `GetObject/Array` | 7 | Nested object + object-array getters (text/int keys, wrong key, absent mixed array) |
| `Parse empty array vs null` | 6 | `[]` -> `OC_REP_NIL`, null/undefined -> `OC_REP_NULL`, half float/simple value -> `OC_REP_UNSUPPORTED`, JSON `null` for the new types |
| `ParseRep nesting depth` | 7 | `KNX_CBOR_MAX_DEPTH`: arrays at the limit and siblings at the limit are accepted; one level deeper (arrays, also 400 nested arrays in one datagram, maps, behind a top-level tag, in the second item of an array that the type scan skips) is rejected with `CborErrorNestingTooDeep` and no tree; a truncated nested payload still reports `CborErrorUnexpectedEOF` (4.13) |

---

### test_oc_rep_alloc_fail.cpp — Allocation Failure in the CBOR Parser (8 tests)

**Source:** `src/resources/ri/oc_rep.c` (`oc_parse_rep`); linked with `-Wl,--wrap=malloc`, `__wrap_malloc()` fails the next call once a test arms it (rep nodes come from `calloc`, so it hits the first string/array buffer)

| Test | What it verifies |
|------|-----------------|
| `IntArrayAllocationFailureIsOutOfMemory` | `{0: [1, 2]}`: a failed int array allocation returns `CborErrorOutOfMemory` instead of writing through NULL |
| `StringArrayAllocationFailureIsOutOfMemory` | same for a string array |
| `TextStringAllocationFailureIsOutOfMemory` | a failed text string allocation returns `CborErrorOutOfMemory` (no NULL string for the handler) |
| `ByteStringAllocationFailureIsOutOfMemory` | same for a byte string |
| `KeyNameAllocationFailureIsOutOfMemory` | same for a text key name |
| `NestedFailureInAnObjectArrayIsNotDropped` | an OOM inside an object array element is not overwritten by the advance to the next element |
| `NestedFailureInAMixedArrayIsNotDropped` | same for a mixed array element |
| `NotArmedParseWorks` | without arming, the same mixed array payload parses |

---

### test_coap.cpp — CoAP Parser/Serializer (114 tests)

**Source:** `src/messaging/coap/coap.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `InitMessage` | 4 | CON/NON/ACK/RST + ClearsFields |
| `Token` | 3 | 4-byte, 8-byte, truncation at 8 |
| `ContentFormat` | 4 | Set/get, not-set default, and the `CONTENT_NONE` marker clearing the option instead of being stored - including a serialize/parse round trip proving it never reaches the wire (F-019) |
| `Accept` | 3 | Set/get, not-set default (caller supplied default survives), `CONTENT_NONE` clears the option (F-019) |
| `MaxAge` | 9 | Set/get, default value; option class: plain CoAP carries Max-Age, the OSCORE plaintext carries it (30 and 0xFFFFFFFF; 0 as empty value), the outer OSCORE message never does (30 and 0xFFFFFFFF, also not on an observe notification), an unset Max-Age is serialized in no mode, an outer Max-Age from a peer is still parsed |
| `ETag` | 2 | Set/get, not-set |
| `Observe` | 2 | Set/get option 7 |
| `UriPath` | 3 | Set/get, leading slash strip, not-set |
| `Block1/Block2` | 13 | Block options: set/get, invalid size/num, not-set; reserved SZX 7 size and non-power-of-two sizes rejected, every valid SZX size accepted (Block1 and Block2) |
| `Size1/Size2` | 3 | Size options |
| `Echo` | 6 | Set/get and not-set; OSCORE outer Echo ignored on requests and responses, inner Echo parsed, and an oversized inner Echo rejected with 4.02 |
| `Payload` | 2 | Set/get payload |
| `SetStatusCode` | 2 | Valid codes, overflow protection |
| `OptionHeader` | 4 | Delta encoding (small, 1-byte ext, 2-byte ext, count-only) |
| `RoundTrip` | 10 | Serialize→parse (empty, token, CF, payload, path, observe, ETag) + Block1/Block2 parse independence (F-014) |
| `Parse_WrongVersion` | 1 | Rejects non-CoAP-1.0 with `MESSAGE_IGNORE` (silently ignored, RFC 7252 3) |
| `Parse_Truncated*` | 5 | Malformed option headers rejected with `MESSAGE_FORMAT_ERROR` before any out-of-bounds read: 1-/2-byte extended delta, 1-/2-byte extended length, truncated option value |
| `Parse_NullData` / `Parse_TruncatedFixedHeader` | 2 | NULL data and `data_len` 0..3 rejected with `MESSAGE_IGNORE` (no usable header) before the fixed CoAP header is read |
| `Parse_TokenAnnouncedBeyondMessage` | 1 | Token length nibble 1..8 announcing more token bytes than the datagram carries is rejected with `MESSAGE_FORMAT_ERROR`; `packet->token` stays wiped (no stale heap bytes copied) |
| `Parse_TokenExactlyFitsMessage` | 1 | Positive boundary: datagram ending exactly after the announced token (`data_len == 4 + token_len`) parses and the token matches the wire |
| `Parse_ShortMessageDoesNotLeakBytesBehindTheDatagram` | 1 | Recycled-buffer regression: bytes past `data_len` pre-filled with a sentinel must never reach `packet->token` |
| `Parse_*Extended*` | 2 | Well-formed extended encodings decode correctly (delta nibble 13 -> Uri-Query, length nibble 13 -> 13-byte Uri-Path) |
| `Parse_Reserved*` / `Parse_PayloadMarker*` / `Parse_UriHostAndUriPortAreAccepted` | 6 | Reserved delta nibble 15 (with and without data) and reserved length nibble 15 rejected (RFC 7252 3.1); payload marker without payload rejected, with payload accepted; Uri-Host and Uri-Port options accepted |
| `CoapFloorBlockSize` | 5 | `coap_floor_block_size()`: valid sizes kept, non-power-of-two floored down, large values capped at SZX 6 (1024), small values raised to SZX 0 (16), the result is always accepted by the block setters |
| `Connection/QueryOptions` | 10 |
| `CoapPayloadLimitTest` | 6 | Payload vs `OC_MAX_APP_DATA_SIZE`: accepted below/at max-1 (incl. null-terminator), 4.13 at/above max, no silent truncation, empty payload |
| `CoapFullPduTest` | 1 | Datagram of exactly `OC_PDU_SIZE` with >328 bytes of options: parser null-terminator lands on the extra byte reserved by `oc_allocate_message()` (one-byte heap overflow regression) |

---

OSCORE Option (48 tests)

**Source:** `src/messaging/coap/oscore.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `PivToSsn` | 5 | Big-endian PIV bytes → uint64 SSN (1/3/5 bytes, zero-length, single zero) |
| `SsnToPiv` | 7 | uint64 SSN → PIV bytes (zero, small, 3-byte, max-4, length boundaries, last SSN below exhaustion, never more than 4 bytes) |
| `PivSsnRoundTrip` | 2 | Conversion integrity (small, large) |
| `OscoreOption` | 16 | Set/parse OSCORE option (PIV-only, PIV+KID, full, inner variants); inner parse rejects a PIV longer than 4 bytes or than the option value, a missing kid-context length byte, a kid context or kid too long or past the option value, and accepts each maximum length |
| `OscoreSerialize` | 2 | Serialization to wire format (PIV-only, full round-trip) |
| `OscoreIsOscoreMessage` | 13 | Detects OSCORE option presence (true, non-OSCORE option, no options, stops at the payload marker, reserved delta nibble 15 rejected,
| `OscoreSendError` | 3 | `oscore_send_error` builds+sends a CoAP error response (network send faked via `--wrap=coap_send_message`): CON request → ACK with cleared OSCORE flag, NON request with zero-length token → fresh-mid NON, secured=true leaves the OSCORE flag untouched |

---

### test_oc_oscore_crypto.cpp — OSCORE Crypto (15 tests)

**Source:** `src/security/oc_oscore_crypto.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `HkdfSha256` | 4 | Key derivation (basic, empty salt, short output, different IKM) |
| `AeadNonce` | 3 | Nonce construction (basic, XOR with IV, empty ID) |
| `ComposeAAD` | 3 | Additional Authenticated Data (basic, empty, different KID) |
| `OscoreEncrypt` | 5 | AES-CCM round-trip, wrong key/ciphertext/AAD, empty plaintext |

---

### test_oc_oscore_context.cpp — OSCORE Context (40 tests)

**Source:** `src/security/oc_oscore_context.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `ContextDeriveParam` | 4 | HKDF key derivation (sender key, IV, with context, uniqueness) |
| `OscoreContextTest` | 16 | Add/find/free contexts, bad params, kid_context, find-by-group-address (sender/recipient), LRU recipient eviction, free-by-AT-id, and the recipient/sender context builders that take their ID from the access token |
| `OscoreContextByToken` | 6 | `oc_oscore_find_context_by_token_mid`: match by token (returns the request PIV), MID fallback, optional out-parameters, unknown transaction → NULL, transaction without an access token → NULL; the response to an own request is matched to the SENDER context of the token (fixture: a sender context), also when a cached recipient context of the token comes first in the list |
| Access token and multicast lookup | 3 | multicast lookup skips the `at` of a unicast recipient (spec 6.3.2.1); `oc_oscore_find_context_by_access_token` with `sender_only` true/false; NULL or unknown token -> NULL |

---

### test_oc_knx_sec.cpp — Security Credentials (116 tests)

**Source:** `src/resources/knx/oc_knx_sec.c`; linked with `-Wl,--wrap=oc_core_get_core_resource_by_index` (counts the lookups of the list GETs, pass through)

| Group | Tests | What it covers |
|-------|-------|----------------|
| `AtProfileToString` | 5 | Profile enum → string (oscore, dtls, tls, pase, unknown) |
| `OscoreConfig` | 2 | Replay-window size is RFC default; OSN delay round-trips |
| `AuthAtEntry` | 3 | AT-table entry access (out-of-bounds NULL, in-bounds entry, positive table size) |
| `GetAtIndex` | 2 | Entry pointer → slot index (NULL → -1) |
| `AtTable` | 6 | Items-used count, find-by-osc-id, delete entry, delete NULL, find-and-remove PASE token; deleting a token removes the observers subscribed with it (`DeleteEntryRemovesTheObserversOfThatToken`, token rotation spec 3.5.4.1) |
| `AtSsnStorage` | 2 | SSN persistence round-trip; entry outside the table is skipped |
| `SecHandlers` | 24 | CoAP handlers of `/auth`, `/auth/o`, `/auth/o/osndelay`, `/auth/o/replwdo`, `/auth/at`, `/auth/at/*`: `DELETE /auth/at/{id}` ends the token's `/k` subscriptions (`AtEntryDeleteRemovesTheTokensObservers`); wrong-Accept rejection, invalid paging (`ps=0`, `pn=-1`), CBOR GET payloads, OSN-delay PUT (no payload → 4.00, valid → 4.04 CHANGED), AT-table DELETE, wildcard entry lookup (missing/unknown token → 4.00); the `/auth/o` and `/auth` list GETs (`AuthOListLooksUpEachEntryByIndex`, `AuthListLooksUpEachEntryByIndex`) answer 2.05 with their first entry and the one after it, one lookup by index per listed entry |
| `SecAcl` | 29 | `oc_knx_sec_check_acl`, the authorization gate, each case with its exact status (`OC_STATUS_OK`, 4.01 `UNAUTHORIZED` not decrypted, 4.03 `FORBIDDEN` scope / ga not covered, 4.05 `METHOD_NOT_ALLOWED` no handler slot): NULL resource and unsupported method → 4.05; per-method handler scope resolution (GET/POST/PUT/DELETE); OSCORE requirement (`OSCORE` alone and `OSCORE_DECRYPTED` alone both denied); scope matching (disjoint → deny, partial overlap → allow, missing access token → deny); `<ga>` per-group-address authorization incl. empty/NULL ga list, absent ga in payload, non-object payload, first/last list entry, broadcast address, and the F-026 regression (a foreign ga anywhere in the payload denies, in either order) |
| `SecAcl` notify | 8 | `oc_knx_sec_check_notify_acl`, the access check per `/k` notification (the full scope matrix; `CoapObserveKAccess` only shows it runs per observer): unsecured resource allowed without OSCORE, NULL resource and secured resource without OSCORE (`OSCORE` alone, or no OSCORE and no token) denied, deleted token and disjoint scope denied, `OC_ACL_G` allows any group address, `<ga>` scope allows only listed group addresses, empty list denies |
| `SecAtPost` | 29 | `/auth/at` rejects incomplete or malformed credentials: id + one scope, repeated mandatory property, short/all-zero master secret, and sender ID longer than the OSCORE limit; `cnf:osc:alg` 10 creates the token, any other value is rejected and not stored; a rejected scope update (`["if.unknown"]`) leaves an existing `<ga>` token unchanged; a `<ga>`-only update (2.04) keeps the OSCORE contexts (same context, SSN unchanged); an id-only delete in a scope-only request frees the deleted token's context; a profile + scope update re-initializes the contexts; deleting an entry (device reset path) frees its sender and recipient contexts; an update rejected after a valid `<ga>` scope or a valid master secret leaves the token unchanged; a repeated master secret in a full-token overwrite keeps the last one; a repeated scope `<ga>` then string frees both ga arrays (request and live); a full-token overwrite with a new master secret frees the token's cached recipient context, one with the same key keeps it (the response of a request protected with this token still gets encrypted); a partial update carrying `cnf` is rejected with 4.00 (spec 2.6.7.3) and keeps the old key and context; a scope-only update keeps the cached recipient context; a collection is atomic: one rejected later entry leaves the earlier token, its key and its sender context unchanged; more than 10 entries -> 4.13 (spec 2.6.3.3.2), 10 new tokens in one request land in 10 slots; the same id twice in one request (also delete and re-create) -> 4.00, nothing changed (spec 2.6.7.2, 3.5.4.1); a full token re-POSTed without salt and contextId leaves both empty, not the old values (spec 2.6.7.3, 3.6.2); a member of an unexpected type (CBOR null) or an empty scope array on an existing token -> 4.00, the token stays (only the id alone deletes, spec 2.6.7.2 / 3.5.4.2); an update carrying only an optional member (`sub`) is not "id only", 2.04 and the token stays |
| `AtTable` access token lookup | 2 | `oc_core_find_at_entry_by_access_token`: match, miss, prefix/longer id; empty or NULL id never matches an unused slot |

---

Replay Protection (14 tests)

**Source:** `src/security/oc_replay.c`

| Test | What it verifies |
|------|-----------------|
| `UnknownClient_ReturnsEcho` | First-seen client triggers echo challenge |
| `AddThenCheck_SameSSN_IsReplay` | Exact SSN reuse detected |
| `AddThenCheck_HigherSSN_IsSynced` | Higher SSN accepted |
| `AddThenCheck_LowerSSN_InWindow_IsSynced` | Lower SSN within window accepted |
| `FarOlderSSN_OutsideWindow_IsEcho` | SSN outside window triggers echo |
| `WindowSlides_OldSSN_Evicted` | Window advancement evicts old SSNs |
| `DifferentClients_IndependentRecords` | Separate tracking per client |
| `SameKID_DifferentContext_AreIndependent` | Context isolation |
| `FreeAll_ClearsState` | Free-all resets everything |
| `EmptyKID_ReturnsEcho` | Empty KID returns echo |
| `ReAdd_ResetsWindow` | Re-adding client resets window |
| `FullPool_EvictsOldestRecordOnOverflow` | Filling all 20 record slots then adding one more evicts the oldest record (deterministic: first-added client, ties broken by index) |
| `SsnWrap_IsEcho_ThenResyncedByAdd` | SSN wrap 2^32 - 1 -> 0 gives ECHO; after `oc_replay_add_client(0)` the record is re-initialised (0 replay, 1 synced) |
| `SsnMaxValue_IsSyncedFromBelow` | SSN 2^32 - 1 is accepted once from below, then detected as replay |

---


### test_oc_oscore_echo_tx.cpp — OSCORE Engine Security (69 tests)

**Source:** `src/security/oc_oscore_engine.c` (unified anchor/seen-responder echo ring and inbound OSCORE process path)

| Test | What it verifies |
|------|-----------------|
| `StoredSSN_FirstEcho_Accepted` | Echo whose PIV/SSN matches a sent multicast anchor is accepted |
| `MultipleStored_EachResponderAccepted` | Several pending SSN anchors each consume independently |
| `TwoResponders_DifferentKidCtx_BothAccepted` | Two responders with distinct `kid_context` for the same SSN both accepted |
| `SameResponder_SecondEcho_IsReplay` | Exact (ssn, kid, kid_ctx) replay from the same responder dropped after first consume |
| `UnknownSSN_NoStore_IsDropped` | Echo with no matching sent SSN dropped |
| `UnknownSSN_AfterStore_IsDropped` | Mismatching SSN dropped while another is pending |
| `WrongKid_SameSSN_IsDropped` | Matching SSN but wrong `kid` content dropped; genuine kid still accepted |
| `SameKid_DifferentSSN_BothAccepted` | Same kid, different SSNs are independent anchors, both accepted |
| `Attacker_ForgedKidCtxFlood_BeforeValidResponse_ValidStillAccepted` | Forged-`kid_ctx` flood before the genuine echo does not consume the anchor |
| `Attacker_ExactReplay_AfterValidResponse_Rejected` | Exact replay of an already-accepted response rejected on every repeat |
| `Attacker_FloodThenReplay_AllIllegalAttemptsRejected` | Combined flood-before + genuine + replay + flood-after all resolve correctly |
| `Attacker_RingExhaustion_AnchorEvicted_ValidResponseRejected` | 2×RING_SIZE forged probes evict the anchor; documents the DoS cost and mitigation note |
| `OldestEntry_CleanedAfterOverflow` | Ring keeps only the most recent RING_SIZE entries |
| `Clear_DropsPendingEntries` | `oc_oscore_free_all_echo_records` wipes all pending entries |
| `SsnWrap_AnchorsAtMaxAndZero_BothAccepted` | Anchors at SSN max and 0 (32-bit wrap) are independent, both accepted once |
| `SsnWrap_ZeroDoesNotMatchMaxAnchor` | An echo with SSN 0 does not consume the anchor at SSN max |
| `Anchor_GetByToken_ReturnsSameGroupObject` | `oc_oscore_echo_get_anchor()` by CoAP token returns the anchor's group object and service type |
| `GetAnchor_UnknownToken_ReturnsFalse` | Lookup by an unrelated token returns false and leaves the anchor untouched |
| `Anchor_FreeAll_DropsTheGroupObjectReference` | `oc_oscore_free_all_echo_records()` drops the anchors, the lookup then fails |
| `Anchor_ServiceTypeRoundTripsPerSlot` | Each slot keeps its own group object and service type |
| `WithinCapacity_AllSendersAndResponsesAccepted` | 32 anchors (half capacity) all store and consume without collision |
| `OverflowEviction_LateEchoRejected_NewAnchorAccepted` | Evicted anchor rejects a late echo; a fresh higher-SSN anchor still works |
| `OverflowMixed_EvictedBlSlot_DoesNotFalseReplay` | An evicted seen-responder slot does not cause a false replay reject on reuse |
| `MultiKid_IndependentSenders_AllAccepted` | Three senders with distinct kids and the same SSN value are fully independent |
| `MultiKid_WrongKidForAnchor_Rejected_CorrectKidAccepted` | Echo with another sender's kid for a matching SSN rejected; correct kid accepted |
| `MultiKid_Overflow_EvictedSenderDropped_OthersAccepted` | Ring overflow evicts one sender's anchor while surviving senders remain accepted |
| `Anchor_RingRollOverDropsOldestAnchor` | Ring roll-over past capacity overwrites the oldest anchor, the newer ones keep their group object |
| `InvalidOuterVersionIsRejectedAndMessageIsReleased` | Version-0 outer CoAP message is rejected and its event reference released |
| `OverlongTokenIsRejectedAndMessageIsReleased` | Outer token length beyond COAP_TOKEN_LEN is rejected before copying |
| `AckWithRequestCodeIsRejectedAndMessageIsReleased` | ACK carrying a request code is not accepted as an OSCORE carrier |
| `NonResetEmptyMessageIsRejected` | Non-RST empty OSCORE message is rejected |
| `ResetWithTokenIsRejected` | RST empty message carrying a token is rejected |
| `UnknownUnicastSenderReceivesUnauthorized` | Unknown unicast OSCORE kid receives an unsecured 4.01 |
| `MissingOscoreOptionRequestReceivesBadOption` | Request without the mandatory OSCORE option receives 4.02 |
| `RequestWithoutKidReceivesBadOption` | OSCORE request without a kid receives 4.02 |
| `RequestWithKidButWithoutPivReceivesBadOption` | OSCORE request with a kid but no PIV receives 4.02 |
| `ResponseWithoutMatchingContextIsIgnored` | Response without a matching OSCORE context is ignored |
| `EchoResponseWithoutAccessTokenIsIgnored` | Echo response without a matching access token is ignored |
| `UnknownMulticastSenderIsSilentlyDropped` | Unknown multicast kid is discarded without a reflection response |
| `AuthenticatedRequestIsDecryptedAndQueuedForRi` | Valid AEAD request is decrypted, marked OSCORE_DECRYPTED and queued for RI |
| `TamperedAuthenticatedRequestReceivesBadRequest` | Modified AEAD tag is rejected with 4.00 |
| `InnerOscoreOptionReceivesSecuredBadOption` | OSCORE option in authenticated inner options receives secured 4.02 |
| `OutboundUnicastRequestIsEncryptedAndSent` | Sender context encrypts a unicast request, advances SSN and dispatches the OSCORE frame |
| `OutboundMulticastRequestIsEncryptedAndSent` | Sender context encrypts a multicast NON request, advances SSN and dispatches the OSCORE frame |
| `OutboundUnicastToFullQueueReleasesEncryptedCopy` | A CON request is encrypted into a copy; the copy that finds the event queue full is released, not leaked (ASan) |
| `OutboundResponseIsEncryptedAndSent` | Recipient context encrypts a normal response without consuming a sender SSN |
| `OutboundObserveResponseCarriesMaxAgeEncrypted` | Protected observe notification: without Max-Age no outer Max-Age (0) is added; with Max-Age 30, Observe and OSCORE are outer, no outer Max-Age, and the protected frame is exactly 2 bytes longer (Max-Age in the ciphertext). The serializer cases are `test_coap.cpp` `MaxAge_*` |
| `ResponseToARequestThatReKeyedItsOwnTokenIsDropped` | A POST /auth/at that changes the key of the token protecting it is applied but gets no 2.04: its contexts freed, only the sender context rebuilt, no recipient context for the response (RFC 8613 8.3); key rotation per spec 3.5.4.1 uses a new token |
| `EmptyDecryptedPayloadReceivesBadRequest` | Authenticated request with an empty inner plaintext receives 4.00 |
| `OutboundAckRequestIsDropped` | ACK carrying a request code is dropped on the outbound path |
| `OutboundMulticastWithoutSModeFlagIsDropped` | Multicast message without the S-mode flag is dropped |
| `OutboundUnicastWithoutContextIsDropped` | Unicast message without an OSCORE context is dropped |
| `OutboundMalformedCoapIsDropped` | Malformed outbound CoAP is dropped |
| `OutboundUnicastEchoResponseIsEncryptedAndSent` | Unicast echo response is encrypted and sent |
| `OutboundMulticastEchoResponseIsEncryptedAndSent` | Multicast-caused echo response is encrypted and sent |
| `OutboundUnicastWithGroupAddressOnlyIsDropped` | A unicast request without the recipient's token (`access_token.outbound`) is not sent, no lookup by group address |
| `OutboundMulticastRequestNotSharedIsEncryptedInPlace` | Multicast request with `ref_count` 1 is encrypted in place, the handed message itself is sent (no clone) |
| `OutboundUnicastNonRequestNotSharedIsEncryptedInPlace` | Unicast NON request with `ref_count` 1 is encrypted in place and sent |
| `OutboundResponseNotSharedIsEncryptedInPlace` | Response with `ref_count` 1 is encrypted in place and sent |
| `OutboundUnicastConRequestSharedIsClonedAndStaysPlaintext` | Shared unicast CON request (`ref_count` 2, the CON transaction) is cloned; the original stays plaintext, only the engine's reference is released |
| `OutboundMulticastRequestSharedIsClonedAndStaysPlaintext` | Shared multicast request is cloned; the original stays plaintext |
| `MulticastRequestWithTokenWithoutGroupAddressIsSilentlyDropped` | A multicast OSCORE request whose token has no group rights (an `if.p` token: no group addresses, no `if.g.s`) is discarded before decryption and context creation, no reply (spec 2.6.9.1 + 2.5.9.6) |
| `MulticastRequestWithIfGsTokenIsDecrypted` | A multicast OSCORE request with an `if.g.s` token (no group address list, but all group addresses, spec 3.5.3) is decrypted and queued for RI, no echo; the `/k` ACL decides |
| `MulticastEchoResponseEncryptFailureFreesTheTemporaryContext` | An encrypt error frees the temporary 'Response Sender Context' of a multicast caused echo response (`--wrap=oc_oscore_encrypt`) |
| `InboundRequestWithFullQueueReleasesTheMessage` | decrypted inbound request, the hand-over to the CoAP engine is rejected (queue full): the message is released |
| `OutboundMulticastWithFullQueueReleasesTheMessage` | outbound multicast (encrypted in place), the hand-over for sending is rejected: handed to `oc_message_post` and released there (`--wrap=oc_message_post`) |
| `OutboundUnicastWithFullQueueReleasesTheMessage` | outbound unicast response, the same for the unicast send path |
| `ResponseOfASameKeyTokenRewriteIsSent` | After an `/auth/at` overwrite with the same key the response of the request is still encrypted and sent |
| `ResponseOfANewKeyTokenRewriteThroughItselfIsDropped` | After an overwrite with a new key (contexts freed and rebuilt) the response has no context and is dropped |

---

### test_smode_refcount.cpp — S-Mode Message Ref-Count Lifecycle (8 tests)

**Source:** `src/security/oc_oscore_engine.c`, `src/messaging/coap/transactions.c` (manual replay of add_ref/unref primitives)

| Test | What it verifies |
|------|-----------------|
| `M1_TransactionWithDataDoesNotTouchM1RefCount` | A transaction holding its own copy of the caller's plaintext (M1, test helper `new_transaction_with_copy`) leaves M1's ref_count at 1 |
| `M1_RefCountUnchangedEvenIfTransactionFails` | Caller's unconditional unref of M1 is the sole release regardless of transaction outcome |
| `M2_MulticastNon_FullLifecycle` | mc-NON: birth → add_ref → clear_transaction → echo-ring retain → send-ref drop → ring release, ends at 0 |
| `M2_MulticastNon_RingRolloverReleases` | Echo-ring roll-over past capacity releases an mc-NON M2 via slot eviction instead of `free_all` |
| `M2_UnicastCon_FullLifecycle` | uc-CON: birth → add_ref → OSCORE send-fn unref → ACK clear, ends at 0 |
| `M2_UnicastCon_RetransmitCycleStaysAtOne` | Each CON retransmit cycle (add_ref then send-fn unref) leaves M2 at 1 until final clear |
| `M2_UnicastNon_FullLifecycle` | uc-NON: birth → add_ref → send-fn unref → ~5s echo window → timeout clear, ends at 0 |
| `M1AndM2_IndependentLifetimes` | Releasing M1 early does not disturb M2's independent ref-count lifecycle |

---

### test_smode_send_refcount.cpp — S-Mode Ref-Count via Real `coap_send_transaction()` (8 tests)

**Source:** `src/messaging/coap/transactions.c`, exercised through the production `coap_send_transaction()` path with linker `--wrap` stubs for `oc_main_initialized`, `coap_send_message`, and `oc_etimer_restart`

| Test | What it verifies |
|------|-----------------|
| `Via_McNon_FullLifecycle` | mc-NON through the real send path: add_ref → wrapped send unref → immediate clear, M2 freed |
| `Via_UcNon_FullLifecycle` | uc-NON through the real send path: send keeps M2 at 1, retransmit-counter bump then timeout clears it |
| `Via_UcCon_FullLifecycle` | uc-CON through the real send path: send keeps M2 alive for ACK, clear on ACK frees it |
| `Via_UcCon_RetransmitCycle` | `COAP_MAX_RETRANSMIT` real send cycles hold M2 at 1; final timeout clear frees it |
| `HandOver_McNon_TransactionAdoptsMessage` | `coap_new_transaction_with_message` adopts the caller's message (no copy, mid/token set); the mc-NON send frees it with the transaction |
| `HandOver_UcCon_TransactionKeepsAdoptedMessage` | uc-CON: the adopted message stays the transaction's plaintext at ref 1 until the ACK clear |
| `NullTransactionIsIgnored` | `coap_send_transaction(NULL)` returns (no dereference; the check was a debug-only log) |
| `TransactionWithoutMessageIsIgnored` | A transaction without a message returns before its type is read from `t->message->data` |

---

### test_oc_knx_helpers.cpp - KNX Helpers (35 tests)

**Source:** `src/resources/knx/oc_knx_helpers.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `CollectAndRank` | 6 | Status code ranking (ok, override, lower-no-override, worst-wins, not-found, internal-error) |
| `NextPageTest` | 3 | Pagination URL construction (page 0, 1, large) |
| `FrameBufferTest` | 6 | Frame integer (pos/zero/neg) and `l=` total/ps query fragments |
| `EvaluateQueryPx` | 3 | `pn`/`ps` pagination query → page-index product |
| `QueryLProcessed` | 6 | `l=` query processing (ps-only, total-only, missing, extra-query bad request) |
| `ParseUint16` | 3 | `oc_parse_uint16_from_base10_string`: valid/leading zeros, rejects NULL, empty, `abc`, `2abc`, `-1`, `+1`, 65536, >5 chars (incl. zero-padded `065535`); no read past `value_len` |
| `ParseSint32` | 2 | `oc_parse_sint32_from_base10_string`: full `0..INT_MAX` range and leading zeros, rejects 2147483648, `-1`, trailing garbage, >10 chars (incl. zero-padded `02147483647`) |
| `ParseUint16Base16` | 3 | `oc_parse_uint16_from_base16_string`: hex incl. upper/lower case and leading zeros, rejects NULL value/result, empty, negative len, `1a2z`, `-1`, `+1`, >4 chars, `g`; no read past `value_len` |
| `ParseUint64` | 3 | `oc_parse_uint64_from_base16_string`: hex incl. full 64-bit range and upper/lower case, rejects NULL value/result, empty, `1a2zz`, `-1`, `+1`, >16 chars, `g`; no read past `value_len` |

---

### test_oc_endpoint.cpp — Endpoint Handling (42 tests)

**Source:** `src/core/oc_endpoint.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `EndpointCompare` | 5 | Full compare (same, different src/port/addr, multicast, NULL) |
| `EndpointCompareAddress` | 3 | Address-only compare (ignores port) |
| `EndpointCopy` | 3 | Deep copy, NULL src/dst safety |
| `IsLinkLocal` | 5 | fe80:: detection, global, loopback, NULL, non-IPv6 |
| `NewEndpoint` | 1 | Allocates a zeroed endpoint |
| `FreeEndpoint` | 1 | NULL free is a no-op |
| `EndpointToString` | 3 | coap:// URI formatting, NULL args, non-IPv6 error |
| `EndpointParsePath` | 5 | Path extraction, query strip, missing scheme/path errors |
| `EndpointListCopy` | 2 | Multi-node list copy breaks aliasing; NULL source no-op |
| `Ipv6AddressScope` | 5 | RFC 6724 scope classification: loopback, link-local, deprecated site-local, ULA (fc00::/7), global |
| `Ipv6EndpointScope` | 3 | Endpoint wrapper: delegates to address scope, NULL endpoint, non-IPv6 endpoint both return 0 |
| `SetLocalAddress` | 1 | NULL endpoint is a no-op (found-match path needs a live port-layer connectivity list) |
| `EndpointPrint` | 3 | Does not crash on a valid endpoint; a non-IPv6 or NULL endpoint prints and frees nothing |

---

### test_oc_knx_fp.cpp — Group Object & FP Tables (112 tests)

**Source:** `src/resources/knx/oc_knx_fp.c`. The file runs a second time without `OC_PUBLISHER_TABLE`, see `PublisherOff` below; the publisher tests are left out there.

| Group | Tests | What it covers |
|-------|-------|----------------|
| `CflagsAsString` | 7 | Comm-flag bitmask → "rwitu" string |
| `PrintCflags` | 1 | Smoke test — does not crash for any cflag mask |
| `CreateUnicastGroupAddressWithPort` | 1 | Builds a unicast `oc_endpoint_t` from a recipient table entry's stored IPv6 address/port/interface |
| `GoTableSearch` | 17 | GO-table size/bounds, find-first/next by GA (incl. negative-index underflow guard, commit b677b04f), empty-slot search, cflags/ga-len getters |
| `FpTableSizes` | 5 | Recipient/publisher table size + entry bounds, no-IID default |
| `FpFindIdFromPayload` | 5 | id-from-payload lookup (in-range, above-range, negative, no-match, NULL) |
| `GoTableHref` | 8 | href getter + find-first/next by href, sending-GA lookup; storing an entry from inside a handler hands the encoder back to the handler's response buffer |
| `RecipientTable` | 1 | Recipient index-from-id match/miss |
| `BelongsHref` | 4 | href ownership check, non-discoverable skipped, an entry without href (NULL) belongs to no resource |
| `FpHandlers` | 50 | CoAP handlers of `/fp/g`, `/fp/p`, `/fp/r` and their `/*` entry resources: a device-scope token may GET `/fp/g/*` (spec 1.1.0, F-080), wrong-Accept rejection, empty table → 2.05, invalid paging (`ps`/`pn`) → 4.00, populated link-format listing incl. comma separator and next-page indicator, entry GET (unknown id → 4.04, known id → 2.05 CBOR), entry DELETE outside loading state → 4.00; POST (loading state) with a repeated ga key keeps the last one: `/fp/p` and `/fp/r` `[1]` then `[]` → empty ga, `/fp/g` `[1]` then `[2]` → `[2]`; an empty array on a key other than ga (`{0: 1, 11: []}`) on an existing entry → 4.00, the entry unchanged, in all three tables (only the id alone deletes, spec 2.5.7.4.1); an update carrying only an unknown member (`{0: 1, 99: 5}`) is not "id only", 2.04 and the entry stays, in all three tables; `/fp/p` and `/fp/r`: `ia` and `grpid` in one request → 4.00 (a1), an update with only `ia` on a multicast entry switches it to unicast (`grpid` cleared), only `grpid` on a unicast entry switches it to multicast (`ia` and the stale `at` cleared, spec 2.5.7.4.2 Table 21, 6.3.2.1); a collection is atomic: one rejected later entry stores nothing, in all three tables; more than 10 entries (`KNX_POST_MAX_ENTRIES`, shared with `/auth/at`) → 4.13, with `/fp/g` and `/fp/p` confirming no entries were stored (spec 2.6.3.3.2); the same id twice in one request → 4.00; two new entries in one request land in two slots |
| `GroupTableStorage` | 7 | Recipient/publisher entry encode-decode round-trip (NON flag as boolean, empty/multiple GA arrays, absent-NON default) |
| `RecipientAccessToken` | 5 | `oc_is_unicast_recipient_access_token`: unicast entry naming the token -> true; multicast entry with `at`, unused slot, other/prefix/longer id, empty or NULL id -> false |
| `GroupMulticasts` | 1 | `oc_register_group_multicasts`: a writable group object whose ga has a publisher entry with `grpid` joins that group (`oc_connectivity_subscribe_mcast_ipv6` wrapped and counted) |

---

### test_oc_buffer_settings.cpp — Buffer/PDU Settings (44 tests)

**Source:** `src/core/oc_main.c` (declared in `include/oc_buffer_settings.h`)

Contract under test (D-001, a deliberate design change; `git log -p -S D-001 -- tests/FINDINGS.md` shows the note): the argument of
`oc_set_pdu_size()` is the **total CoAP PDU size**, i.e. payload plus the CoAP
header budget. Since the header split (RFC 8613 clause 4.1.1) that budget is
`OC_COAP_HEADER_BUDGET = COAP_MAX_OUTER_HEADER_SIZE + COAP_MAX_INNER_HEADER_SIZE`,
not a multiple of a single constant. The argument is stored verbatim, the payload
budget used to derive the block size is `pdu_size - OC_COAP_HEADER_BUDGET`, and the
accepted range is `OC_COAP_HEADER_BUDGET + 16 .. COAP_MAX_MESSAGE_SIZE`.

Current values: outer 54, inner 214, plain 268, `KNX_PAYLOAD_SIZE` 768,
default PDU 1036, `COAP_MAX_MESSAGE_SIZE` 1152, default block 512.

**Defaults (`PduDefaults`, 5 tests)**

| Test | What it verifies |
|------|-----------------|
| `DefaultPduReservesTwoCoapHeaders` | Default PDU == `KNX_PAYLOAD_SIZE + OC_COAP_HEADER_BUDGET` |
| `DefaultBlockSizeMatchesPayloadSizeCappedAt1024` | Default block == `EXPECTED_DEFAULT_BLOCK_SIZE` (512 at the current payload) and is a power of two. Name retains the historical 1024 cap; the value is now derived from `KNX_PAYLOAD_SIZE` and the RFC 7252 clause 4.6 ceiling |
| `DefaultBlockSizeIsAnEncodableRfc7959Size` | Default block size is a legal SZX 0..6 value (power of two, 16..1024) |
| `DefaultBlockSizeMatchesWhatSetPduSizeWouldDerive` | Static initializer agrees with the runtime setter |
| `DefaultPduExceedsPayloadSize` | Default PDU strictly larger than the payload budget |

**Accessors (`BufferSettings`, 10 tests)**

| Test | What it verifies |
|------|-----------------|
| `MaxAppDataSizeReturnsKnxPayloadSize` | `oc_get_max_app_data_size()` == `KNX_PAYLOAD_SIZE` |
| `MaxAppDataSizeIsStable` | Repeated calls return the same value |
| `SetPduSizeBelowMinimumReturnsError` | PDU below `OC_COAP_HEADER_BUDGET+16` returns -1 |
| `SetPduSizeBelowMinimumDoesNotChangeState` | PDU below `OC_COAP_HEADER_BUDGET+16` is refused and leaves PDU and block size unchanged |
| `SetPduSizeValidReturnsZero` | Valid PDU accepted |
| `GetPduSizeReturnsExactlyWhatWasSet` | `oc_get_pdu_size()` returns the stored value verbatim |
| `SetPduSizeFromGetPduSizeIsIdempotent` | Feeding the getter back into the setter is a fixed point (5 iterations) |
| `BlockSizeIsPowerOfTwoInRange` | Block size is a power of two in 16..1024 |
| `LargePduYieldsMaxBlockSize` | The largest accepted PDU (`MAXIMUM_PDU_ARG`) yields exactly `ON_WIRE_BLOCK_CEILING` (512 today) with no clamp needed |
| `SmallerPduYieldsSmallerBlockSize` | Smaller PDU → smaller block size |

**Worst-case OSCORE frame (`PduWorstCaseFrame`, 11 tests)**

| Test | What it verifies |
|------|-----------------|
| `MeasuredOuterHeaderFitsOuterBudget` | Serialized max-option outer frame ≤ `COAP_MAX_OUTER_HEADER_SIZE` |
| `MeasuredInnerHeaderFitsInnerBudget` | Serialized max-option inner frame ≤ `COAP_MAX_INNER_HEADER_SIZE` |
| `DefaultPduHoldsWorstCaseOscoreFrame` | Default PDU holds outer + inner headers + a full encrypted payload |
| `PayloadCarryingFrameStaysWithinMeasuredBudget` | A payload-carrying frame stays within the measured budget |
| `SetPduSizeToDefaultEquivalentReproducesDefaultPduSize` | Setting the default-equivalent argument restores the default PDU |
| `SetPduSizeToDefaultEquivalentReproducesDefaultBlockSize` | ...and restores the default block size |
| `PduBelowTwoHeadersPlusMinBlockIsRejected` | Guard rejects anything below `OC_COAP_HEADER_BUDGET + 16` (284 bytes) |
| `MinimumAcceptedPduYieldsMinimumBlockSize` | The smallest accepted PDU yields a 16-byte block |
| `GuardAndBlockBudgetUseSameHeaderMultiple` | Guard and payload-budget subtraction use the same header budget |
| `BlockSizeIsMonotonicInPduSize` | Block size never decreases as the PDU grows |
| `LargePduAlwaysHoldsWorstCaseFrame` | Any accepted large PDU still holds the worst-case frame |
| `InPlaceSerialization.EchoReRequestWithFullPayloadKeepsPayloadAndEcho` | Payload at `data + COAP_MAX_HEADER_SIZE` (largest one a packet carries), 8-byte token, Uri-Path, Content-Format and the largest Echo option serialized in place: payload and Echo come out unchanged (layout of the s-mode send and the regenerated 'echo re-request') |

**Header budgets (`CoapHeaderBudgets`, 7 tests)**

| Test | What it verifies |
|------|-----------------|
| `PlainIsTheSumOfOuterAndInner` | `COAP_MAX_HEADER_SIZE` == outer + inner |
| `OuterIsSmallerThanInner` | The Class U budget is the smaller of the two |
| `OuterCoversTheOscoreOption` | The outer budget leaves room for a full OSCORE option value |
| `InnerCoversEchoAndTheUris` | The inner budget covers Echo plus the KNX Uri-Path/Uri-Query maxima |
| `StringOptionGroupChargesOneExtensionPerLongPartOnly` | `COAP_STRING_OPTION_GROUP_SIZE` charges a length extension byte only for parts of 13+ characters, capped by both the character and the part budget |
| `SegmentHeavyUriPathFitsTheTightenedGroupBudget` | A measured count-heavy Uri-Path split (3 long + 3 short parts) stays inside the tightened group budget |
| `PlainFrameFitsThePlainBudget` | A flat inner+outer frame stays within `COAP_MAX_HEADER_SIZE` |

**Message size (`CoapMessageSize`, 3 tests)**

| Test | What it verifies |
|------|-----------------|
| `DefaultBlockKeepsDatagramWithinGuidance` | The default block keeps a full datagram within `COAP_MAX_MESSAGE_SIZE` |
| `DerivedBlockNeverExceedsTheCeiling` | The derived block never exceeds `OC_MAX_ON_WIRE_BLOCK_SIZE` (RFC 7252 clause 4.6) |
| `SetPduSizeRejectsBothOutOfRangeDirections` | Both `MINIMUM-1` and `MAXIMUM+1` → -1, `MAXIMUM` → 0 |

**Serialization modes (`CoapSerializationModes`, 4 tests)**

Pins the three thin wrappers in `src/messaging/coap/oscore.c` to the mode triple they
must forward. Verified non-vacuous: transposing one argument in
`oscore_serialize_plaintext()` makes `PlaintextWrapperUsesInnerOnlyMode` fail.

| Test | What it verifies |
|------|-----------------|
| `PlaintextWrapperUsesInnerOnlyMode` | `oscore_serialize_plaintext()` == `(inner, !outer, !oscore)` |
| `OscoreWrapperUsesOuterOnlyMode` | `oscore_serialize_message()` == `(!inner, outer, oscore)` |
| `PlainCoapWrapperUsesBothOptionSets` | `coap_serialize_message()` == `(inner, outer, !oscore)` |
| `TheThreeModesProduceDifferentFrames` | Inner and outer frames differ, guarding against a degenerate serializer |

**Message buffer (`PduMessageBuffer`, 2 tests + `PduZzzRestore`, 1 test)**

| Test | What it verifies |
|------|-----------------|
| `AllocatedMessageBufferMatchesConfiguredPduSize` | `oc_allocate_message()` sizes its buffer from `OC_PDU_SIZE` at the maximum accepted PDU |
| `AllocatedMessageBufferHoldsWorstCaseFrame` | The allocated buffer holds the worst-case OSCORE frame |
| `RestoreDefaultEquivalentPduSize` | Restores global PDU state for subsequent suites |

---

Core Resources & Device Info (57 tests)

**Source:** `src/resources/ri/oc_core_res.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `DeviceHostname` | 12 | Set stores the label (store first), overwrite; NULL, empty, over-`HNAME_MAX_SIZE` and with-domain (`.`) rejected (previous name kept); load uses the stored name, no or an invalid (old `.local`) stored name gives the default `knx-<serial>` and stores it; `oc_core_reset_device_hostname_to_default` sets and stores the default (returns 0); a failed store returns -1 and RAM still holds the default, at reset and at load without storage |
| `DeviceInfo` | 29 | Firmware/hardware/app version (hwv stored by reference), manufacturer/model/manufacturing-date setters, ia/iid/fid set-and-store range validation; set-and-store of ia/iid/fid/fwv/apv writes the value to storage, and a failed store keeps the new value in RAM |
| `CoreResourceByIndex` | 6 | Resource-by-index bounds (negative, out-of-range, first); every `oc_core_resource_t` value names the resource at that position in the registry (URI per index, with and without `OC_PUBLISHER_TABLE`), the table covers all `OC_NUM_CORE_RESOURCES`, no core resource is linked through `next` (the registry orders them) |
| `CheckUrnKnxQuery` | 2 | `urn:knx` query-value prefix match |
| `CheckResourceByRt` | 4 | Resource type match (exact, wildcard, mismatch, no-rt default) |
| `CheckResourceByIf` | 4 | Interface match (exact, wildcard, mismatch, no-if default) |

---

### test_oc_knx_dev.cpp — Device Programming Mode & Resource Handlers (57 tests)

**Source:** `src/resources/knx/oc_knx_dev.c`; linked with `-Wl,--wrap=oc_main_initialized`, `-Wl,--wrap=knx_dns_sd_update_service` and `-Wl,--wrap=oc_core_get_core_resource_by_index` (counts the lookups of the list GETs, pass through)

**Programming mode (`KnxDeviceProgrammingMode`, 6 tests)**

| Test | What it verifies |
|------|-----------------|
| `SetTrueStoresOnDevice` | `oc_knx_device_set_programming_mode(true)` sets `device->pm` |
| `SetFalseStoresOnDevice` | `oc_knx_device_set_programming_mode(false)` clears `device->pm` |
| `InProgrammingModeReflectsSetTrue` | `oc_knx_device_in_programming_mode()` returns true after set-true |
| `InProgrammingModeReflectsSetFalse` | Getter returns false after set-false |
| `GetterMatchesDeviceField` | Getter mirrors `device->pm` exactly |
| `TogglingIsIdempotentPerValue` | Repeated set of same value is stable |

**Device reset (`KnxDevResetObservers`, 2 tests)** — `oc_knx_device_reset` with erase code 2 (`ResetToDefaultStateRemovesAllObservers`) and 7 (`ResetToDefaultWithoutIaRemovesAllObservers`) removes every observer: subscriptions end with the access tokens they were made with.

**Resource handlers (`KnxDevHandlers`, 43 tests)** — GET/PUT handlers for the
device resources (`/dev/sn`, `/dev/hwv`, `/dev/fwv`, `/dev/hwt`, `/dev/model`,
`/dev/hostname`, `/dev/iid`, `/dev/pm`, `/dev/sa`, `/dev/da`, `/dev/fid`,
`/dev/port`, `/dev/mport`, `/dev/ap/pv`, `/dev/mid`, `/dev/ipv6`, dev/ap lists)
exercised directly at handler level: wrong-Accept → bad request, happy-path
content, empty-payload PUT → bad request, and array-size validation. The `/dev` and the app list GET
(`DevListLooksUpEachEntryByIndex`, `ApListLooksUpEachEntryByIndex`) answer 2.05 with their first entry and the one
at the next index and look up each listed entry once by index (core resources are not chained).
`/dev/hname`, `/dev/iid` and `/dev/fid` are read-only (PUT is optional in the
specification; IID and FID are written via `/.well-known/knx/ia`), so only their
GET handlers are tested plus a check that no PUT handler is registered.

**Coverage note:** `oc_knx_load_device`, `oc_knx_device_storage_reset`, and
`oc_knx_device_restart` still require a live request pipeline (storage + OSCORE
init / DNS-SD re-register) and are covered by the runtime suite
(`test_device_resources.py`, `test_reset.py`, `test_load_state_machine.py`).

---

### test_oc_clock.cpp — RFC3339 Clock Helpers (12 tests)

**Source:** `src/util/oc_clock.c`

| Test | What it verifies |
|------|-----------------|
| `ParseEpochZeroIsZeroTicks` | `1970-01-01T00:00:00Z` → 0 ticks |
| `ParseOneSecondAfterEpoch` | `...00:00:01Z` → `OC_CLOCK_SECOND` ticks |
| `ParseInvalidStringReturnsZero` | Garbage string → 0 |
| `ParseMalformedMonthReturnsZero` | Month 13 → 0 |
| `ParseEmptyStringReturnsZero` | Empty input → 0 |
| `EncodeEpochZero` | 0 ticks → `1970-01-01T00:00:00Z` |
| `EncodeOneSecondAfterEpoch` | `OC_CLOCK_SECOND` ticks → `...00:00:01Z` |
| `EncodeBufferTooSmallReturnsZero` | 5-byte buffer → 0 (error) |
| `RoundTripParseEncodeWholeSeconds` | parse→encode reproduces original string |
| `RoundTripEncodeParseIsStable` | encode→parse reproduces original ticks |
| `CurrentTimeFormatsParseableString` | `oc_clock_time_rfc3339()` emits a parseable string |
| `CurrentTimeBufferTooSmallReturnsZero` | Current-time small buffer → 0 |

---

### test_oc_knx.cpp — KNX Core (34 tests)

**Source:** `src/resources/knx/oc_knx.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `LsmStateString` | 7 | State enum → string (unloaded, loaded, loading, unloading, load-completing, unknown, error) |
| `LsmEventString` | 5 | Event enum → string (nop, start-loading, load-complete, unload, unknown) |
| `IsRedirectedRequestFrom` | 5 | URL routing classification (NULL, empty, /k, /p, other) |
| `KnxLsm` | 1 | `oc_knx_lsm_state()` returns the device LSM field |
| `KnxRuntime` | 3 | Runtime-ready true only when loaded and IID set |
| `KnxHandlers` | 9 | `/.well-known/knx`, `/a/lsm`, `/f` fingerprint GET handlers (JSON/CBOR/accept errors); `/a/lsm` POST unload removes every observer (`ALsmUnloadRemovesAllObservers`); POST start loading resets the unicast IPv6 resolvers (`ALsmStartLoadingResetsPendingUnicastResolvers`) |
| `KnxFingerprintStorage` | 4 | 4-byte fingerprint record: absent key starts at 0, load continues from the stored value, an older 8-byte record keeps its low half and is rewritten as 4 bytes, wrap at `UINT32_MAX` |

---

### test_oc_knx_fb.cpp — Functional Block Helpers (22 tests)

**Source:** `src/resources/knx/oc_knx_fb.c`

**Functional-block discovery (21 tests)**

| Group | Tests | What it covers |
|-------|-------|----------------|
| `CheckIfFunctionalBlocksNeedToAdd` | 7 | rt/if query + wildcard matching against `urn:knx:fb`/`ll` |
| `CountFunctionalBlocks` | 15 | Distinct FB counting, page-full behavior, `/f` listing, and `/f/{id}` datapoint pagination and unknown-block handling; without `ps` a `/f/{id}` page of long datapoint links holds as many as fit the buffer and `l=ps` reports that size (F-078) (handlers called with a bounded encoder, `test_helpers_guarded_get.h`); a GET with Observe 0 on `/f` and `/f/{fb}` (through `oc_ri_invoke_coap_entity_handler`) gets 2.05 without an Observe option and registers no observer |

---

### test_oc_timer.cpp — Timer Operations (7 tests)

**Source:** `src/util/oc_timer.c`

| Test | What it verifies |
|------|-----------------|
| `SetStoresInterval` | Interval stored correctly |
| `NotExpiredImmediately` | Large interval → not expired |
| `ExpiredWithZeroInterval` | Zero interval → immediately expired |
| `ExpiredWithPastStart` | Forced past start → expired |
| `RemainingDecreasesOverTime` | Remaining time decreases |
| `ResetAdvancesStartByInterval` | Reset shifts start forward |
| `RestartUsesCurrentTime` | Restart sets start to now |

---

### test_coap_receive_payload.cpp — Payload Limits, Client Transfers and Reject Replies (17 tests)

**Source:** `src/messaging/coap/engine.c` (`coap_receive`, called directly with a plain request; network faked with `--wrap` of `oc_main_initialized`, `coap_send_message`, `oc_etimer_restart`)

| Test | What it verifies |
|------|-----------------|
| `CoapReceivePayload.ConRequestAboveOneBlockGets413WithSize1` | CON request without Block1, payload one block + 88 B: piggybacked ACK 4.13 with Size1 = block size (RFC 7959 2.9.3), same MID and token; before: RST |
| `CoapReceivePayload.NonRequestAboveOneBlockGets413WithSize1` | NON request, payload one block + 1 B: NON 4.13 with Size1 = block size |
| `CoapReceivePayload.RequestOfExactlyOneBlockIsNotRejectedForItsSize` | exactly one block: processed further, no RST and no 4.13 |
| `CoapReceivePayload.ClientResponseAboveOneBlockReachesTheCallbackComplete` | client side: ACK 2.05 without Block2 with 513 and 767 payload bytes reaches the client callback complete (not cut at one block); the one-shot callback is released, nothing is sent |
| `CoapReceivePayload.ClientBlock2RequestsTheNextBlockAndDeliversTheCompleteBody` | a CON Block2 response (64 B, M=1) triggers an empty ACK and a CON GET for block 1 with the same token, URI and query; the final ACK block contributes the last 36 bytes, invokes the callback once with all 100 bytes, and releases callback, transaction and response buffer |
| `CoapReceivePayload.EmptyAckKeepsTheCallbackUntilTheSeparateResponse` | a tokenless empty ACK clears the request transaction without invoking or removing the callback; a later CON response with its own MID delivers the payload once, releases the callback and gets exactly one four-byte empty ACK |
| `CoapReceivePayload.ClientResponseOfMaxAppDataSizeIsRejectedBeforeTheCallback` | client side: a response of exactly 768 bytes fails in the parser (4.13), the callback is not called and stays registered; the rejected ACK is not answered (nothing sent) |
| `CoapReceivePayload.RejectedConSeparateResponseGetsAnEmptyReset` | client side: a CON separate response of 768 bytes (4.13) is answered with exactly one empty RST: code 0.00, the response's MID, no token (RFC 7252 4.2); the callback is not called and stays registered |
| `CoapReceivePayload.RejectedResetIsIgnored` | a RST whose parse fails (oversized payload, 4.13) gets no reply |
| `CoapReceivePayload.RejectedNonSeparateResponseIsIgnored` | client side: a NON separate response of 768 bytes (4.13) gets no reply (RFC 7252 4.3), the callback is not called and stays registered |
| `CoapReceivePayload.MalformedConRequestGetsAnEmptyReset` | a CON GET with option byte `0xF0` (reserved delta nibble, message format error) gets exactly one empty RST: code 0.00, same MID, no token (RFC 7252 4.2) |
| `CoapReceivePayload.ConRequestWithTokenLengthAboveEightGetsAnEmptyReset` | a CON GET with token length nibble 9 (format error) gets one empty RST with the same MID |
| `CoapReceivePayload.MalformedNonRequestIsIgnored` | a NON GET with a format error gets no reply (RFC 7252 4.3) |
| `CoapReceivePayload.ConMessageWithUnknownVersionIsIgnored` | a CON with version 2 gets no reply, not even a RST (RFC 7252 3) |
| `CoapReceivePayload.MessageShorterThanTheHeaderIsIgnored` | a 3-byte datagram gets no reply (no MID to reset) |
| `CoapReceivePayload.ConRequestWithUnknownCriticalOptionGetsAck402` | a well formed CON GET with an unknown critical option (9) keeps the error reply: ACK 4.02 Bad Option, same MID (RFC 7252 5.4.1) |
| `CoapReceivePayload.NonRequestWithUnknownCriticalOptionGetsNon402AndKeepsTheToken` | a NON GET with an unknown critical option gets NON 4.02 with the next locally generated MID, the complete eight-byte token and no payload |

---

### test_coap_receive_notify.cpp — Separate Responses and Notifications in coap_receive (3 tests)

**Source:** `src/messaging/coap/engine.c` (`coap_receive`), `src/resources/ri/oc_ri.c` (separate response branch, `oc_notify_observers()` after a PUT), `src/messaging/coap/separate.c`; app resource `/p/1` (observable, GET answers with a separate response, PUT answers 2.04); linked with `-Wl,--wrap=oc_main_initialized`, `-Wl,--wrap=oc_etimer_restart`, `-Wl,--wrap=coap_send_message` (records each sent message) and `-Wl,--wrap=calloc` (fails one armed allocation of a separate response store)

| Test | What it verifies |
|------|-----------------|
| `CoapReceiveNotify.PutReplyIsSentWhenTheNotificationStartsASeparateResponse` | with one observer, a CON PUT whose synchronous notification runs the separate GET handler still gets its own reply: exactly one ACK 2.04 with the PUT's MID and token (the notification can not clear the PUT's transaction) |
| `CoapReceiveNotify.AcceptedSeparateResponseSendsOnlyTheEmptyAck` | a CON GET answered with a separate response sends only the empty ACK (0.00, same MID) now; the handle is active and the request is stored |
| `CoapReceiveNotify.NotAcceptedSeparateResponseAnswers503` | the store allocation fails: the CON GET is answered now with one ACK 5.03 Service Unavailable, same MID and token; the handle stays inactive, no store |

---

### test_coap_receive_oscore_admission.cpp — Server Side OSCORE Replay and Echo Admission (12 tests) — fixture

**Source:** `src/messaging/coap/engine.c` (`coap_receive()` replay/Echo admission of `OSCORE_DECRYPTED` requests, `coap_send_response_with_empty_application_payload[_with_delay]()`, `coap_send_delayed_echo_response()`), `src/security/oc_replay.c`; app resource `/p/1` (GET, no scope); the request is plain CoAP with kid and PIV on the endpoint (no decryption); linked with `-Wl,--wrap=oc_main_initialized`, `-Wl,--wrap=oc_etimer_restart`, `-Wl,--wrap=coap_send_message` (records bytes and endpoint flags), `-Wl,--wrap=oc_set_delayed_callback_ms` (records the delayed Echo response, fired by the test), `-Wl,--wrap=coap_knx_echo_max_delay_ms`, `-Wl,--wrap=oc_clock_time` (fixed clock) and `-Wl,--wrap=malloc` (fails the armed allocation)

| Test | What it verifies |
|------|-----------------|
| `UnknownUnicastClientIsChallengedWithADelayedEchoResponse` | CON from a client without a replay record: nothing sent at once, one delayed callback with 0 ms; firing it sends ACK 4.01 with the request MID and token, an 8-byte Echo equal to the clock, flag `ECHO_CAUSED_BY_UC_SRC`; handler not called, no transaction, no record |
| `UnknownMulticastClientGetsAUnicastEchoResponseWithARandomDelay` | 8 multicast NON requests with maximum 50 ms: each delay is below 50; the replies are unicast NON 4.01 with the request token, Echo and `ECHO_CAUSED_BY_MC_SRC` |
| `MulticastEchoResponseIsNotDelayedWithoutAMaximum` | maximum 0 (`osn_delay`): a multicast challenge is scheduled with 0 ms |
| `EchoResponseIsSentAtOnceWhenTheDelayedContextCannotBeAllocated` | the delayed context allocation fails: ACK 4.01 with Echo is sent at once, no delayed callback |
| `ReplayedSsnGetsAnImmediate401WithoutEcho` | the SSN of the replay record again: immediate ACK 4.01 with the token, no Echo and no Echo source flag; handler not called |
| `ReplayedMulticastRequestIsDroppedSilently` | F-079 (skipped, open): a replayed multicast NON gets no reply, no delayed callback, handler not called; fails today with a unicast 4.01 |
| `SynchronisedClientReachesTheHandler` | the next SSN of a known client: no challenge, the handler answers ACK 2.05 |
| `EchoOfTheWrongLengthGets402` | a 4-byte Echo: ACK 4.02 with the token, no Echo; handler not called, no record |
| `EchoAtTheFreshnessLimitAdmitsTheClient` | an Echo exactly 10 s old is accepted: the handler answers 2.05, the next SSN passes without a challenge, the admitted SSN is then a replay |
| `StaleEchoGets401WithANewEcho` | an Echo one tick older than 10 s: immediate ACK 4.01 with a new Echo equal to the clock; handler not called, no record |
| `EchoFromTheFutureIsTreatedAsStale` | an Echo later than the clock: the unsigned difference exceeds the limit, 4.01 with Echo |
| `FreshEchoResynchronisesAClientLeftOfTheWindow` | a record at SSN 1000 and a fresh Echo with SSN 3: the handler runs, the record restarts at 3 (4 synced, 3 replayed) |

Open finding: F-079 (a replayed multicast request gets a unicast 4.01 instead of being dropped); `ReplayedMulticastRequestIsDroppedSilently` is skipped until it is fixed.

---

### test_coap_blockwise_server.cpp — Server Side Block-wise Transfer (11 tests)

**Source:** `src/messaging/coap/engine.c` (`coap_receive()`, Block1/Block2 server path), `src/resources/ri/oc_ri.c` (response buffer); app resource `/p/1` (GET 100 bytes CBOR, POST records the body); linked with `-Wl,--wrap=oc_main_initialized`, `-Wl,--wrap=oc_etimer_restart`, `-Wl,--wrap=coap_send_message`

| Test | What it verifies |
|------|-----------------|
| `Block1RequestIsReassembledAndHandledOnce` | POST in two blocks (64 + 36): block 0 -> 2.31 Continue (Block1 num 0), handler not called; block 1 -> handler called once with all 100 bytes, 2.04 with Block1 num 1 |
| `Block1RepeatedBlockDoesNotDoubleThePayload` | a repeated block 0 (new MID) does not double the body, the handler gets exactly 100 bytes |
| `Block1GapIsRejectedAndNotHandled` | block 0 then block 2 (gap): not taken, the handler is never called |
| `Block1FollowUpWithADifferentQueryDoesNotConsumeTheOriginalTransfer` | block 1 with a different query gets RST 0.00 and never calls POST; retrying with the original query completes the original body once and preserves its query |
| `UnblockedPostReplacesAnIncompleteBlock1Body` | an ordinary POST replacing an incomplete Block1 upload delivers only the fresh body, once, and gets ACK 2.04 with its own MID |
| `InitialBlock2PostDeliversItsBodyAndQuery` | a POST starting a Block2 exchange still delivers its complete request body and query to the handler, once, and gets ACK 2.04 |
| `Block2FollowUpWithTheSameQueryIsServedFromTheBuffer` | GET `/p/1?x=1`, block size 64: block 0 (M=1, ETag, CBOR); follow-up block 1 with the same query from the buffer: last 36 bytes, M=0, same ETag and Content-Format CBOR, handler called once |
| `Block2FollowUpCarriesTheHandlersContentFormat` | resource default octet-stream, the GET handler answers CBOR: block 0 and the follow-up block 1 both carry CBOR (the buffer takes the handler's format) |
| `Block2FollowUpWithoutTheQueryIsNotServedFromTheBuffer` | the response buffer is keyed by the query too: block 1 without the query is not served from it, handler not called again |
| `UnblockedGetReplacesAnIncompleteBlock2Response` | an ordinary GET replacing an unfinished Block2 download calls GET again and returns its complete 100-byte response, without a stale Block2 option |
| `DuplicateConRequestDoesNotInvokeTheHandlerTwice` | receiving the same plain CON twice invokes GET once and leaves no transaction; with the send wrapper not populating the response cache, no second response is sent |

**Engine coverage checkpoint:** eight characterization tests added against baseline
`a8b432feba580c61181120f6c67635061f5ada77`, without production changes.
Measured with `linux-coverage-gcc` and gcovr 8.8 over the full unit suite;
coverage counters cleared before the final run.

| `src/messaging/coap/engine.c` | Before | After | + OSCORE admission |
|-------------------------|--------|-------|--------------------|
| Lines | 346/601 (57.6%) | 391/601 (65.1%) | 450/601 (74.9%) |
| Branches | 235/560 (42.0%) | 270/560 (48.2%) | 306/560 (54.6%) |
| Functions | 11/13 (84.6%) | 11/13 (84.6%) | 13/13 (100%) |

The third column adds `test_coap_receive_oscore_admission.cpp` (11 tests,
base `7033e6ba`): full suite 2176/2176 passed, the new suite passed under GCC
and Clang ASan/UBSan (shuffled, repeat 3); the admission block is fully
covered in lines and branches.

Validation in Docker: full GCC coverage suite 2165/2165 passed (including
`LayeringCheck`); the two changed suites passed 28/28 under both GCC and
Clang ASan/LSan/UBSan. Runtime and conformance were not rerun: only unit tests
and this catalog changed. This is a first coverage increment, not complete
refactoring coverage: client Echo re-request, client Block1 recovery and
allocation/serialization failures remain follow-up areas.

---

### test_coap_engine.cpp — Duplicate Detection + Response Cache (13 tests)

**Source:** `src/messaging/coap/engine.c`

| Test | What it verifies |
|------|-----------------|
| `DuplicateDetection.FreshMessageReturnsFalse` | First message with a MID is not duplicate |
| `DuplicateDetection.SameMessageIsDuplicate` | Same MID+endpoint is duplicate |
| `DuplicateDetection.DifferentMidIsNotDuplicate` | Different MID → fresh |
| `DuplicateDetection.DifferentPortIsNotDuplicate` | Same MID, different port → fresh |
| `DuplicateDetection.DifferentAddressIsNotDuplicate` | Same MID, different addr → fresh |
| `DuplicateDetection.HistoryWrapsAround` | Circular buffer evicts oldest entries |
| `ClearRequestHistory.WipedMessageBecomesFreshAgain` | `oc_coap_clear_request_history()` makes a prior MID fresh again |
| `ClearResponseHistory.SafeOnEmptyCache` | `oc_coap_clear_response_history()` is safe on an empty cache |
| `ResponseCacheStore.PiggybackedAckIsCachedAndShrunk` | A piggybacked ACK is cached (the cache holds a reference) and its full PDU allocation is cut to the message bytes (`malloc_usable_size` < PDU size, glibc); after the caller's unref, a duplicate of the request re-sends the identical bytes (`oc_send_buffer` wrapped) |
| `ResponseCacheStore.EmptyAckIsNotCached` | Empty ACK is not cached (a duplicate re-sends nothing) |
| `ResponseCacheStore.NonAckIsNotCached` | Non-ACK message is not cached (a duplicate re-sends nothing) |
| `ResponseCacheStore.ShortMessageIsNotCached` | Too-short message is not cached (a duplicate re-sends nothing) |
| `ResponseCacheStore.OverwrittenSlotFreesItsMessage` | `2 * OC_RESPONSE_CACHE_SIZE + 1` responses: a cached message keeps the cache's reference until store number `OC_RESPONSE_CACHE_SIZE + 1` reuses its slot, then the reference is released; no message leaks (LeakSanitizer) |

---

### test_coap_transactions.cpp — Transaction Lifecycle (21 tests)

**Source:** `src/messaging/coap/transactions.c`

| Test | What it verifies |
|------|-----------------|
| `NewTransactionAllocates` | Creates with correct MID/token/message |
| `GetByMidFindsTransaction` | Lookup by MID works |
| `GetByMidReturnsNullWhenNotFound` | Returns NULL for unknown MID |
| `GetByMidSkipsSModeNon` | s-mode NON excluded from regular lookup |
| `GetByTokenFindsTransaction` | Lookup by token works |
| `GetByTokenReturnsNullWhenNotFound` | Returns NULL for unknown token |
| `GetByTokenSkipsSModeNon` | s-mode NON excluded |
| `GetAnyByMidFindsSModeNon` | "any" variant includes s-mode |
| `GetAnyByTokenFindsRegular` | "any" variant includes regular |
| `ClearRemovesTransaction` | Removes from list and frees |
| `ClearNullIsSafe` | No crash on NULL |
| `ZeroLengthNullTokenIsSafe` | A zero-length NULL token is accepted without calling `memcpy` with invalid arguments |
| `FreeAllClearsEverything` | Empties entire list |
| `FreeByEndpointSelectiveRemoval` | Only removes matching endpoint |
| `MultipleTransactionsCoexist` | Multiple tracked simultaneously |
| `ZeroLengthTokenNeverMatches` | A tokenless packet never matches a tokenless transaction (zero length compare guard) |
| `NewTransactionWithMessageAdoptsTheMessage` | `coap_new_transaction_with_message()` adopts the caller's message (no copy, ref_count stays 1), mid/token/endpoint set |
| `NewTransactionWithMessageRegistersInList` | The adopting transaction is registered in the list |
| `RegisterAsTransactionHandlerIsCallable` | Transaction-handler registration is callable |
| `InitEngineRegistersHandler` | Engine init registers the transaction handler |
| `NewTransactionBeyondLimitReturnsNullUntilOneIsCleared` | `COAP_MAX_OPEN_TRANSACTIONS` transactions are created, the next returns NULL and is not listed, creation works again after one is cleared |

---

### test_coap_observe.cpp — Observer Management + Notify (57 tests)

**Source:** `src/messaging/coap/observe.c`

| Test | What it verifies |
|------|-----------------|
| `AddObserverViaHandler` | Registers observer, count increments |
| `DuplicateObserverReplacesExisting` | Same endpoint+URI replaces |
| `RemoveByClient` | Removes all for an endpoint |
| `RemoveByClientNoMatch` | No-op for unknown endpoint |
| `RemoveByToken` | Removes matching token |
| `RemoveByTokenNoMatch` | No-op for unknown token |
| `RemoveByMid` | Removes by last message ID |
| `RemoveByResource` | Selective removal by resource pointer |
| `FreeAllObservers` | Clears all, count → 0 |
| `MultipleObserversSameResource` | Multiple tracked on one resource |
| `DeregisterViaHandler` | OC_OBSERVE_DEREGISTER through handler |
| `HandlerRejectsMissingObserveOptionAndBadCodes` | Rejects missing Observe option and unsuccessful GET responses |
| `RemovalByMidNoMatchReturnsZero` | Unmatched MID leaves the observer registered |
| `RegistrationRejectsMissingInvalidAndOverlongLifetime` | Rejects missing, malformed, and overlong `lt` values |
| `RegistrationAcceptsNonTrue` | Accepts `non=true` observe registration |
| `NotifyObserverCanFilterByEndpoint` | Endpoint-filtered notification does not notify another endpoint |
| `NotifyObserverBuildsAndSendsNotification` | Builds and sends a notification for a matching observer |
| `NotifyKObserversNullPayloadIsSafe` | `oc_knx_notify_k_observers(NULL, …)` is a no-op |
| `NotifyKObserversZeroLengthIsSafe` | Zero-length payload is a no-op |
| `NotifyKObserversNoObserversIsSafe` | Empty /k observer list completes safely |
| `NewTokenInTheFreedSlotDoesNotReachTheOldSubscriber` | Token A (`<ga>` [1]) deleted, token B (`if.g.s`) in the same table slot: the old subscriber of A gets no `/k` event with B's rights |
| `TokenUpdatedInPlaceNarrowsTheSubscriptionToTheNewScope` | POST /auth/at with the same id changes `<ga>` [1] to [2] (2.04): the observer stays, gets no `/k` event for GA 1, gets one for GA 2 (scope read at send time) |
| `TokenUpdatedInPlaceKeepingTheGroupAddressStillNotifies` | `<ga>` [1] updated to [1, 3]: events for GA 1 and GA 3 both reach the subscriber |
| `NotifyObserversAboveTheBlockSizeSendsTheFirstBlockAndKeepsTheRest` | observer with Block2 64, 100 B value: CON notification with Block2 0/M=1/64, Size2 100, ETag, Observe; GET block 1 returns the last 36 B with M=0, the same ETag and Content-Format application/cbor from the buffer (handler not called again), buffer freed after |
| `NotifyObserversAboveTheBlockSizeTwiceReplacesTheUnfinishedBuffer` | two notifications above the block size (value changes per call), block 1 of the first not fetched: both calls return, each goes out as block 0 of its own value with its own ETag; GET block 1 returns the last 36 B of the NEW value with the NEW ETag and M=0 (handler not called again); old buffer freed, none left after the last block |
| `RemoveObserversByAccessTokenRemovesOnlyThatTokensObservers` | `oc_knx_remove_observers_of_access_token`: removes every observer of that token (any client/port), keeps the others |
| `NotifyObserversNullResourceReturnsZero` | NULL resource → returns 0 |
| `NotifyObserversNoObserversReturnsZero` | Zero observers short-circuits → 0 |
| `GetObserveCounterIsAtLeastFirstNotificationValue` | Observe counter ≥ first-notification value |
| `GetObserveCounterIsStableWithoutNotifications` | Counter stable when no notifications sent |
| `RegistrationRejectedWhenObserverListIsFull` | With `COAP_MAX_OBSERVERS` unsecured observers registered, a new registration (also from the same address on a new port: no identity beyond the port) returns -1 and the count stays at the limit |
| `RefreshAcceptedWhenObserverListIsFull` | At the limit, a re-registration from an existing endpoint still succeeds (returns 1) |
| `ExpiredObserverFreesSlotWhenListIsFull` | At the limit, an observer whose lifetime elapsed is removed to make room for the new registration |
| `SameClientFromNewPortReclaimsItsSlotWhenListIsFull` | At the limit, the same OSCORE client (address, kid, kid context) on a new port takes over its oldest registration of the resource |
| `OtherClientDoesNotReclaimWhenListIsFull` | At the limit, a client with another kid is rejected and no observer is removed |
| `SameClientFromOtherAddressDoesNotReclaimWhenListIsFull` | At the limit, the same kid from another address is rejected |
| `SameClientOtherResourceDoesNotReclaimWhenListIsFull` | At the limit, the same client registering another resource is rejected |
| `SameClientTwoPortsAreTwoObserversBelowLimit` | Below the limit, the same client on two ports keeps two observers |
| `RegistrationRejectsNegativeLifetime` | `lt=-5` is rejected (-2), no observer |
| `BareNonKeepsConfirmableNotifications` | Only `non=true` selects NON notifications, a bare `non` keeps CON |
| `RejectedReregistrationKeepsExistingObservation` | An invalid re-registration (`lt=0`) is rejected and leaves the running observation |
| `ExpiredObserverRemovedOnNextRegistration` | Any registration drops expired observers, not only one into a full list |
| `RegistrationNeedsNoHeap` | Observers come from a static pool: a registration succeeds with every heap allocation failing |
| `RemovalByTokenReadsOnlyTheTokenLength` | Removal by token reads only `token_len` bytes of the given token (ASan) |
| `RegistrationRejectsNonBooleanUpdateOnlyOnK` | A non-boolean `u` is rejected on `/k` (`u=false` starts no update timer), any other resource ignores `u` |
| `NotifyDispatchedCountsQueuedNotification` | `coap_notify_observers_dispatched()` counts a queued notification |
| `BlockwiseHrefAllocationFailureSkipsOnlyThatObserver` | A failed href copy of the blockwise buffer skips only that observer, no write through NULL |
| `NotifyDispatchedIsZeroForNonMatchingEndpoint` | Endpoint filter without a match → 0 dispatched |
| `NotifyDispatchedIsZeroWhenBufferAllocationFails` | Notification buffer allocation fails → 0 dispatched |
| `NotifyDispatchedIsZeroWhenGetIsIgnored` | GET handler ignores the request → 0 dispatched |
| `CoapObserveKAccess.TwoGaTokensEachGetOnlyTheirGroupAddresses` | The access check runs per observer: tokens {1,2,3} and {3,4}, notifications for 1..5: each observer gets only its own group addresses, 3 reaches both, 5 neither (the scope matrix is `SecAcl.Notify*` in `test_oc_knx_sec.cpp`) |
| `CoapObserveKAccess.TokenNarrowedAfterRegistrationGetsOnlyNewGroupAddresses` | The check reads the token at notification time: narrowed from `OC_ACL_G` to `<ga>` {7} after the registration → only 7 is notified |
| `CoapObserveKUpdate.BareUSendsEachTransmittingGroupObjectOnce` | `/k` registration with a bare `u`: the update timer sends one notification per transmitting group object, one per run |
| `CoapObserveKUpdate.UpdateOnlySendsGroupAddressesOfTheToken` | The first update sends only the group addresses in the observer's `<ga>` token scope |
| `CoapObserveKUpdate.NoUpdateWithoutU` | Without `u` no update timer is started |

---

### test_oc_ri.cpp — Resource Interface (118 tests)

**Source:** `src/resources/ri/oc_ri.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `StatusCode` | 9 | oc_status_t → CoAP code mapping |
| `CountInterfaces` | 4 | Bit counting in interface mask |
| `CountScopes` | 3 | Scope bit counting |
| `InterfaceStringFullUrn` | 4 | Index → URN string lookup |
| `LsmStateString` | 6 | State enum → string |
| `LsmEventString` | 5 | Event enum → string |
| `StatusFromCoap` | 5 | CoAP code → oc_status_t (round-trips with StatusCode) |
| `ScopeMask` | 10 | Interface scope bit positions (if.i, if.a, if.swu, unknown, length mismatch, empty name, non-scope interfaces, internal `<ga>` unreachable by name, all known names round-trip) |
| `RiMask` | 7 | Scope/interface name framing (single/multiple bits, truncated URNs) |
| `PrintAclScopes` | 1 | ACL scope printer runs without crashing |
| `NewRequestFromInbound` | 1 | Inbound request rewires response and copies buffer |
| `QueryParsing` | 1 | NULL and empty query input is rejected before pointer arithmetic |
| `AcceptHeader` | 4 | Accept-header validation (exact, content-none, NULL, mismatch) |
| `QueryValue` | 7 | Query value lookup including key-only and empty-value cases |
| `QueryExists` | 4 | Query key existence including empty-query handling |
| `QueryNthKeyValue` | 4 | Nth query fragment, key-only, missing-fragment, and zero-index cases |
| `QueryNthKeyExists` | 2 | Nth query fragment key including key-only fragments |
| `RiAlloc` | 2 | Allocated resource/resource-data is zeroed |
| `RiAddResource` | 6 | Add-resource validation including mixed input/output interfaces |
| `RiDeleteResource` | 4 | Delete-resource including observer cleanup |
| `RiResourceLookup` | 1 | NULL and empty application-resource paths |
| `RiClientCb` | 9 | Client-callback find-by-mid/token, list traversal, validity, get-by-uri/endpoint/method |
| `RiEntityHandlerBlockwiseLifetime` | 2 | `oc_ri_invoke_coap_entity_handler`'s own internal blockwise scrub must not free the current request's buffer before the caller (`coap_receive`) is done with it |
| `RiEntityHandlerPaths` | 14 | Registered-resource GET, PUT, POST, DELETE, malformed CBOR, non-CBOR payload passed to the handler, and unsupported-method paths; every error code of the handler: 4.00 invalid CBOR, 4.13 truncated CBOR, 4.04 unknown path, 4.01 scoped handler without OSCORE, 4.03 decrypted request outside the token scope, 4.05 unsupported method and FETCH (the handler is not called on an error); deleting a periodic observed resource stops its periodic callback; the core resource lookup is one lookup by index per core resource, no walk over `next` (`CoreLookupIsByIndex`, `--wrap=oc_core_get_core_resource_by_index` counts them) |
| `RiEntityHandlerOrder` | 3 | Resource lookup and the payload-free scope check come before the payload is parsed: a malformed payload to an unknown path gets 4.04, to a secured method without OSCORE 4.01 (handler not called); a payload deeper than `KNX_CBOR_MAX_DEPTH` gets 4.00 and the handler is not called |

---

### test_oc_ri_timed_callbacks.cpp — RI Timed-Event List (5 tests)

**Source:** `src/resources/ri/oc_ri.c` (timed-event list, `poll_event_callback_timers`) via `oc_ri_add_timed_event_callback_ticks` / `oc_ri_remove_timed_event_callback`; linked with `-Wl,--wrap=oc_clock_time`, `oc_main_poll()` drives the list

| Test | What it verifies |
|------|-----------------|
| `CallbackThatRemovesItselfAndReturnsDoneRunsOnce` | a callback that removes itself and returns `OC_EVENT_DONE` runs once and is freed once (no double free) |
| `CallbackThatRemovesItselfAndReturnsContinueRunsOnce` | same with `OC_EVENT_CONTINUE`: the removed entry is not restarted, it never fires again |
| `CallbackThatArmsItselfAgainRunsAfterTheNewDelay` | a callback that removes itself and arms itself again with 2 s runs again 2 s later, not earlier |
| `CallbackThatRemovesAnotherCallbackStopsIt` | a callback that removes another pending callback keeps that one from running |
| `CallbackReturningContinueRepeatsUntilRemovedFromOutside` | normal path: `OC_EVENT_CONTINUE` repeats, a removal from outside stops it |

---

### test_oc_ri_periodic_observe.cpp — Periodic Observe List (4 tests)

**Source:** `src/resources/ri/oc_ri.c` (periodic observe callbacks on the observe list); observer registered through `coap_receive()` (GET + Observe 0 + `lt`), `oc_main_poll()` drives the list; linked with `-Wl,--wrap=oc_clock_time`, `oc_main_initialized`, `coap_send_message`, `oc_notify_observers` (the armed notification deletes its resource)

| Test | What it verifies |
|------|-----------------|
| `ResourceDeletedInItsNotificationReturningDoneFreesTheEntryOnce` | the periodic callback whose resource is deleted during its notification and returns `OC_EVENT_DONE` frees its entry once (no double free) |
| `ResourceDeletedInItsNotificationReturningContinueFreesTheEntryOnce` | same with `OC_EVENT_CONTINUE`: the removed entry is not restarted (use-after-free shows under ASan) |
| `DeregisterOfOneObserverKeepsThePeriodicNotificationsForTheOthers` | observers A and B, A deregisters (Observe 1, same token): the next periodic tick notifies B and not A |
| `DeregisterOfTheLastObserverRemovesThePeriodicCallback` | both observers deregister: the periodic callback is removed at once, `oc_notify_observers()` is not called again and nothing is sent |

---

### test_oc_abort.cpp — Abort / Exit / Assert (6 tests)

**Source:** `src/port/.../oc_assert.h` (`oc_abort`, `oc_exit`, `OC_ASSERT`) — GoogleTest death tests.

| Test | What it verifies |
|------|-----------------|
| `AbortImplRaisesSigabrt` | Abort implementation raises `SIGABRT` |
| `OcAbortWrapperTerminates` | `oc_abort()` terminates the process |
| `ExitImplExitsWithGivenStatus` | Exit implementation exits with the given status |
| `OcExitWrapperExitsWithStatus` | `oc_exit()` exits with the given status |
| `AssertFalseAborts` | `OC_ASSERT(false)` aborts |
| `AssertTrueIsNoOp` | `OC_ASSERT(true)` is a no-op |

---

### test_oc_blockwise.cpp — Blockwise Transfer (29 tests)

**Source:** `src/messaging/coap/oc_blockwise.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `BlockwiseDispatch` | 4 | Outgoing block slicing (offset beyond payload, advances offset, partial/mid slices) |
| `BlockwiseHandle` | 5 | Incoming block reassembly (sequential append, offset/size overflow, gap, duplicate) |
| `BlockwiseAlloc` | 13 | Request/response buffer alloc + lookup by href (length and content: a prefix such as `p` does not match `p/1`)/token/mid/client-cb (both request- and response-list variants of each `_by_token`/`_by_mid`/`_by_client_cb` wrapper), including a NULL empty-query lookup and a lookup without Uri-Path (NULL href: matches no stored href, never read) |
| `BlockwiseScrub` | 6 | Free/scrub buffers (incl. NULL-buffer no-op), ref-count-based reclamation, scrub-for-client-cb on both the request and response lists |

---

### test_oc_buffer.cpp — Message Buffer Pool (23 tests)

**Source:** `src/core/oc_buffer.c`

| Test | What it verifies |
|------|-----------------|
| `AllocateMessageReturnsInitialisedMessage` | Allocated message is initialised |
| `AllocateMessageDataIsWritableForFullPdu` | Data buffer is writable for a full PDU |
| `AllocateMessageReservesTerminatorByteBehindFullPdu` | `data[OC_PDU_SIZE]` is inside the allocation (extra byte for the CoAP null-terminator) |
| `AllocateMessageReturnsDistinctBuffers` | Successive allocations are distinct |
| `AddRefIncrementsCounter` | `oc_message_add_ref()` increments ref count |
| `AddRefNullIsNoOp` | `oc_message_add_ref(NULL)` is a no-op (F-004 RESOLVED) |
| `UnrefDecrementsWithoutFreeingWhenStillReferenced` | Unref decrements without freeing while referenced |
| `UnrefAtZeroFreesMessage` | Unref at zero frees the message |
| `UnrefNullIsNoOp` | `oc_message_unref(NULL)` is a no-op |
| `ReceiveMessageForwardsPlainMessageToCoapEngine` | Inbound plain messages are classified and forwarded to the CoAP engine |
| `ReceiveMessageForwardsOscoreMessageToOscoreLayer` | Inbound OSCORE messages are classified and forwarded to the OSCORE layer |
| `SendMessageRoutesPlainUnicastToNetwork` | Plain unicast messages reach the network transport |
| `SendMessageRoutesDiscoveryToDiscoveryTransport` | Discovery messages use the discovery transport |
| `SendMessageRoutesUnicastOscoreToOscoreLayer` | Unicast OSCORE messages use the unicast OSCORE event |
| `SendMessageRoutesMulticastOscoreToOscoreLayer` | Multicast OSCORE messages use the multicast OSCORE event |
| `EncryptedOscoreMessageIsSentToNetwork` | Encrypted OSCORE messages reach the wrapped network send |
| `EncryptedEventWithoutOscoreFlagIsDropped` | Encrypted events without the OSCORE flag are not sent |
| `ReceiveMessageWithFullQueueReleasesTheMessage` | `oc_receive_message()` with the process event queue full: the event is rejected and the message released |
| `SendMessageWithFullQueueReleasesTheMessage` | `oc_send_message()` with the process event queue full: the event is rejected and the message released |
| `RouteInboundPlainWithFullQueueReleasesTheMessage` | `message_buffer_handler` forwards an inbound plain message, the queue is full: released (`oc_message_post`) |
| `RouteInboundOscoreWithFullQueueReleasesTheMessage` | the same for an inbound OSCORE message (to the OSCORE layer) |
| `RouteOutboundOscoreMulticastWithFullQueueReleasesTheMessage` | the same for an outbound OSCORE multicast message |
| `RouteOutboundOscoreUnicastWithFullQueueReleasesTheMessage` | the same for an outbound OSCORE unicast message |

---

### test_oc_client_api.cpp — Client API (15 tests)

**Source:** `src/resources/ri/oc_client_api.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `ClientApiLF` | 12 | Link-format response parsing: entry count, entry URI, rt/if params, missing param, NULL/too-short payload guards, single-record (no trailing comma) fallback |
| `ClientApiDoUpdate` | 3 | `oc_send_well_known_message` real send path (network faked via `--wrap=coap_send_message`/`oc_main_initialized`/`oc_etimer_restart`, same pattern as `test_smode_send_refcount`): well-known GET NON and CON sent in one call (one message, the callback's mid and token, uri path and query as given), no callback → nothing allocated or sent. The s-mode send path is in `test_smode_issue.cpp` |

---

### test_oc_discovery.cpp — Discovery (`/.well-known/core`) (237 tests)

**Source:** `src/resources/ri/oc_discovery.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `DiscoveryBase` (add-payload) | 10 | Link-format framing (URI angle brackets, leading comma, rt truncation/urn:knx strip, content types) and the `include_if` flag in both directions (`if=` framed / omitted, no empty attribute slot left behind) |
| `DiscoveryBase` (check-request) | 7 | Discoverability + rt-query filtering, first-entry skipping, uninitialised core |
| `WellKnownCoreHandler` | 43 | Accept handling; rt/if/ep/d/l/pn/ps queries; PM, IA, sector errors (including no-matching-points and outside-runtime cases), next-page links, combined filters, multicast suppression |
| `WellKnownCorePmEndpoint` | 32 | Synchronized unicast/multicast PM on/off cases with exact, wildcard, prefix wildcard, internal-substring rejection, mismatching, empty, maximum-length, and overlong SN endpoints |
| `WellKnownCoreSerialNumberEndpoint` | 18 | Synchronized unicast/multicast exact, wildcard, prefix wildcard, internal-substring rejection, mismatching, empty, maximum-length, and overlong SN endpoints |
| `WellKnownCoreIndividualAddressLength` (parameterized) | 110 | `ia=` query address matching across `iid` length 0-10 × `ia` length 0-4 × unicast/multicast (11×5×2) |
| `WellKnownCoreInvalidSectorGa` (parameterized) | 16 | Invalid group-address sector queries (empty, overlong, above-maximum, wildcard depths 0-4) × unicast/multicast, all return 4.00 Bad Request |

---

### test_oc_etimer.cpp — Event Timers (13 tests)

**Source:** `src/util/oc_etimer.c`

| Test | What it verifies |
|------|-----------------|
| `SetAddsTimerToPendingList` | Set adds timer to the pending list |
| `SetRecordsOwningProcess` | Set records the owning process |
| `ExpirationTimeIsStartPlusInterval` | Expiration = start + interval |
| `ExpiredWhenOwnerCleared` | Timer expires when owner cleared |
| `StopRemovesTimerAndMarksExpired` | Stop removes timer and marks expired |
| `StopMiddleOfListKeepsOthers` | Stopping a middle timer keeps others |
| `AdjustShiftsStartTime` | Adjust shifts the start time |
| `ResetAdvancesStartByInterval` | Reset advances start by one interval |
| `ResetWithNewIntervalChangesInterval` | Reset with a new interval changes it |
| `RestartKeepsTimerPending` | Restart keeps the timer pending |
| `NextExpirationZeroWhenEmpty` | Next-expiration is 0 when none pending |
| `NextExpirationNonZeroWhenPending` | Next-expiration is non-zero when pending |
| `OcEtimerProcess.ExpiredTimersArePostedOnePerPassAndAllFire` | Several timers expired at once: one timer event per pass of the etimer process (the bounded event queue is not flooded), all of them fire |

---

### test_oc_knx_client.cpp — KNX Client Redirect (8 tests)

**Source:** `src/resources/knx/oc_knx_client.c`

| Test | What it verifies |
|------|-----------------|
| `NullRequestReturnsMinusOne` | NULL request → -1 |
| `ZeroLengthPathReturnsMinusOne` | Zero-length path → -1 |
| `KPathIsSmodeReturnsZero` | `/k` path classified as s-mode → 0 |
| `KWithLeadingCharacterStillMatchesFirstByte` | First-byte match drives classification |
| `PPathIsPropertyReturnsOne` | `/p` path classified as property → 1 |
| `PPointPathIsPropertyReturnsOne` | `/p/...` path → 1 |
| `OtherPathReturnsTwo` | Other path → 2 |
| `WellKnownPathReturnsTwo` | `/.well-known/...` → 2 |

---

### test_read_on_init.cpp — Read-on-Init Network Gate (9 tests — fixture)

**Source:** `src/resources/knx/oc_knx_fp.c` (`oc_init_datapoints_at_initialization()` and its timed callback). The timed-event registry, `oc_connectivity_get_network_scope()` and the s-mode senders are replaced with `--wrap`; the group object and recipient tables are filled with `test_helpers_tables.h`. Covers what the runtime class `TestReadOnInitNetworkGate` cannot run under the Docker runner.

| Test | What it verifies |
|------|-----------------|
| `CallbackPeriodIsTheDelayInClockTicks` | The callback is registered with `OC_CLOCK_MS_TO_TICKS(KNX_READ_ON_INIT_DELAY_MILLISECONDS)`, not the raw ms value (100 ticks = 100 us on Linux before the fix) |
| `SiteLocalScopeSendsTheRead` | Scope 5 (ULA): one multicast `r` on the sending GA, then done |
| `GlobalScopeSendsTheRead` | Scope 14 also opens the gate |
| `UnicastRecipientGetsAUnicastRead` | Recipient with grpid 0: one unicast `r` on the sending GA |
| `NoScopeWithholdsTheRead` | Scope 0: rescheduled, nothing sent |
| `ReadIsReleasedWhenScopeReachesSiteLocal` | Withheld (rescheduled) at scope 2, sent once scope reaches 5 |
| `ScopeDropAfterNetworkUpIsTolerated` | Once up, a drop to scope 2 does not stop the remaining reads |
| `GivesUpAfterMaxAttemptsWithoutSiteLocalScope` | `KNX_READ_ON_INIT_MAX_ATTEMPTS` reschedules, then done without sending |
| `NewInitializationResetsTheAttemptCounter` | A new initialization restarts the `KNX_READ_ON_INIT_MAX_ATTEMPTS` budget |

---

### test_oc_knx_publisher.cpp — Publisher of Output Datapoints, S-Mode and /p Observe (50 tests)

**Source:** `src/resources/knx/oc_knx_publisher.c` (publish procedure of output datapoints with the metadata `cov`, `hbt`, `mrt`, KNX IoT Point API 2.5.7.4.3 / 2.5.11.2 / 2.5.11.4 / 2.6.10.2). Clock, timed events, load state, resource lookup and the s-mode sender are replaced with `--wrap`; the sender double only returns the outcome a test sets (rc and dispatched flag), the real sender's group object, recipient and /p observer decisions are covered by `SmodeDispatch.*` in `test_smode_loopback_recursion.cpp`.

| Group | Tests | What it verifies |
|-------|-------|-----------------|
| `SendCheck` initial / change | 14 | First evaluation sends (also with hbt 0); unchanged re-evaluation quiet; accumulated small changes; float change at cov quiet (reference kept), above cov sends, decrease, cov 0, negative cov; NaN and infinity; int32 cov and full range; bool toggle |
| `SendCheck` heartbeat | 8 | Elapsed and restart, one tick early, restart after a change, change wins over heartbeat, `UINT16_MAX`, hbt 0 never sends, `oc_clock_time_t` wrap-around before/after |
| `SendCheck` mrt | 4 | Initial value not delayed; change held back until mrt elapsed, then sent against the last sent value; heartbeat shorter than mrt waits for mrt; mrt across clock wrap-around |
| `SendCheck` invalid | 3 | NULL entry, NULL value, unknown type → no send, state unchanged |
| `SendCheckTimer` | 14 | Start validation (NULL, no entries, count 0, period 0), period in ticks, restart, stop; one initial value per period, a change is not delayed by a pending initial value; failed send keeps the reference and is retried (initial and change), a failed initial value does not block the next; an entry the sender does not dispatch stays pending and the next entry still gets its initial value; only changed/due entries sent; nothing sent outside runtime, all values resent after a reload; callback without list stops |
| `SendCheckTimer` observe | 4 | The dispatched flag decides, not the return code: delivery to /p observers only (rc -1, dispatched) is committed and uses the period's initial-value slot; start writes `hbt` into `observe_period_seconds` (not for hbt 0, `OC_PERIODIC` or const resources) |
| `SendCheckTimer` delivery | 3 | Start rejects an entry without `resource_path` and fails when the timed callback cannot be allocated; an s-mode write without recipient or observer stays pending and is retried |

---

### test_oc_knx_p.cpp — KNX `/p` Properties Resource (13 tests)

**Source:** `src/resources/knx/oc_knx_p.c`

| Test | What it verifies |
|------|-----------------|
| `KnxPResource.DefinitionUriIsP` | Resource definition URI is `/p` |
| `KnxPGet.WrongAcceptReturnsBadRequest` | GET with wrong Accept → bad request |
| `KnxPGet.NoAppResourcesReturnsBadRequest` | GET with no app resources → bad request |
| `KnxPGet.ContentNoneAcceptIsAccepted` | GET with content-none Accept is accepted |
| `KnxPAppResources.GetReturnsRegisteredDatapointsWithPagination` | GET lists registered datapoints and emits pagination metadata |
| `KnxPAppResources.GetDefaultPageThatFitsKeepsThePageNumberOnlyLink` | `KNX_PAGE_SIZE + 1` short datapoints, `KNX_PAYLOAD_SIZE` buffer: a full default page and `p.next` `pn=1`, nothing written beyond the buffer |
| `KnxPAppResources.GetDefaultPageOfLongDatapointsFitsTheResponseBuffer` | F-078: realistic (69-byte) datapoint links, `KNX_PAYLOAD_SIZE` buffer: without `ps` a page holds as many as fit, `l=ps` reports that size, `p.next` `pn=1`, and page 1 continues where page 0 ended |
| `KnxPAppResources.GetDatapointLongerThanBufferReturnsInternalServerError` | A single link longer than the buffer → 5.00, empty payload, nothing written beyond the buffer |
| `KnxPAppResources.GetWithObserveIsAnsweredWithoutObserveOption` | GET with Observe 0 on `/p` (through `oc_ri_invoke_coap_entity_handler`, OSCORE client with `if.p`): 2.05 without an Observe option, no observer registered |
| `KnxPAppResources.PostDispatchesValueToMatchingPutHandler` | POST dispatches a collection value to the matching datapoint PUT handler |
| `KnxPPost.WrongAcceptReturnsBadRequest` | POST with wrong Accept → bad request |
| `KnxPPost.EmptyPayloadReturnsOk` | POST with empty payload → OK |
| `KnxPPost.UnknownHrefReturnsNotFound` | POST to unknown href → not found |

---

### test_oc_knx_sub.cpp — KNX `/sub` Delete (7 tests)

**Source:** `src/resources/knx/oc_knx_sub.c`

| Test | What it verifies |
|------|-----------------|
| `SetsDeletedStatus` | Delete sets the deleted status |
| `ReportsNoContentFormatAndZeroLength` | Reports no content-format, zero length |
| `RemovesSingleObserver` | Removes a single observer |
| `RemovesAllObserversAcrossResources` | Removes all observers across resources |
| `NoObserversStillSucceeds` | Delete with no observers still succeeds |
| `NullResponseDoesNotCrash` | NULL response does not crash |
| `ResourceDefinitionUriIsSub` | Resource definition URI is `/sub` |

---

### test_oc_knx_swu.cpp — Software Update (105 tests)

**Source:** `src/resources/knx/oc_knx_swu.c`; linked with `-Wl,--wrap=malloc` and `-Wl,--wrap=free` (pass through unless armed: capture a setter's string buffer, poison a block on free) and `-Wl,--wrap=oc_core_get_core_resource_by_index` (counts the lookups, pass through)

| Group | Tests | What it covers |
|-------|-------|----------------|
| `KnxSwuGetInt` | 10 | Integer-valued `/swu` resource GETs (protocol, method, result, state, bytes) + wrong-Accept |
| `KnxSwuGetString` | 5 | String-valued GETs (hwref, lastupdate, lastupdate as `{ "osv": true }` without a real-time clock) + wrong-Accept |
| `KnxSwuLastUpdateStorage` | 7 | `oc_swu_set_last_update()` stores the timestamp / the no-RTC marker; `oc_swu_read_last_update()` loads the stored value over the manufacturing date, keeps `{ "osv": true }` across a restart, reads a 63 character value, and falls back to the manufacturing date with nothing stored or no storage |
| `KnxSwuGetGated` | 10 | Download-gated GETs (pkgv, pkgname, update) returning not-found / bad-request / OK |
| `KnxSwuPut` | 11 | PUT validation per resource (wrong Accept, missing/non-typed payload, happy path, upgrade-cb invocation) |
| `KnxSwuABlock` | 8 | `/swu` block transfer (Accept, ps param, no-callback, fast-path changed) + `po=0` accepted, leading zero is decimal not octal, value is not read beyond its length |
| `KnxSwuABlockInvalidQuery` | 21 | Parameterised `po`/`ps`/`pkgs` rejection: non-numeric, trailing garbage, negative, zero (ps/pkgs), above INT_MAX, too many digits, empty → all 4.00 with the callback never invoked |
| `KnxSwuList` | 4 | List GET wrong-Accept, invalid page size (`ps=0`), invalid page number (`pn=-1`) — all rejected before the core resource table is touched; a valid list GET answers 2.05 with the swu sub resources and looks up each listed entry once by index |
| `KnxSwuABlockStateMachine` | 15 | Download state machine on `/a/swu`: the first block starts a download and clears stale metadata, an empty payload does not; received bytes accumulate and are reported only while downloading; offset 0 or a missing offset restarts an interrupted or finished download; a continuation block outside DOWNLOADING is rejected; the stack never moves to DOWNLOADED itself; restart after a failed update; update refused while updating |
| `KnxSwuABlockAppCompletion` | 3 | The application completes the download with its own counter; the stack counter matches it; update rejected until the application completes |
| `KnxSwuSetters` | 7 | Setter values become visible in matching GETs |
| `KnxSwuSetOwnValue` | 2 | `oc_swu_set_package_name()` / `oc_swu_set_last_update()` called with their own current buffer keep the value (the old, poisoned buffer is freed after the copy) |
| `KnxSwuCbReg` | 2 | Upgrade/download callback registration then trigger |

---

### test_oc_log.cpp — Hex Logging (4 tests)

**Source:** `src/port/.../oc_log.h` (`OC_LOGbytes` formatting)

| Test | What it verifies |
|------|-----------------|
| `FormatsSingleLineLowercaseHex` | Bytes formatted as single-line lowercase hex |
| `EmptyBufferProducesNoOutput` | Empty buffer produces no output |
| `SixteenBytesStayOnOneLine` | 16 bytes stay on one line |
| `WrapsAfterThirtyTwoBytes` | Output wraps after 32 bytes |

---

### test_oc_main.cpp — Main Callbacks / State (9 tests)

**Source:** `src/core/oc_main.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `MainCallbacks` | 7 | swu / factory-presets / reset / restart / programming-mode / lsm-change setter+getter, overwrite |
| `MainState` | 2 | Not-initialised before bootstrap; signal-event-loop without callbacks is a no-op |

---

### test_oc_main_init.cpp — DNS-SD Registration at Bootstrap (1 test)

**Source:** `src/core/oc_main.c`

| Test | What it verifies |
|------|-----------------|
| `MainInit.DnsSdRegistrationRunsOnceTheStackIsInitialized` | `oc_main_init()` calls `knx_dns_sd_update_service()` exactly once and only after `oc_main_initialized()` is true; before, the call was postponed and dropped, so a device without a later interface event never answered mDNS. Storage, network and crypto are replaced by linker `--wrap` |

---

### test_oc_network_events.cpp — Network Events (14 tests)

**Source:** `src/core/oc_network_events.c`

| Test | What it verifies |
|------|-----------------|
| `EventWhenProcessNotRunningUnrefsMessage` | Event with process not running unrefs the message |
| `EventWhenProcessNotRunningIsRepeatable` | Repeatable without leaking |
| `RunningProcessDrainsQueuedMessage` | Running process drains and receives queued messages |
| `InterfaceEventsArePostedAndDispatched` | Up then down before the loop runs dispatches only the last event (down) |
| `InterfaceEventBurstEndingWithUpDispatchesUp` | A down/up/down/up burst dispatches only up, never a trailing down |
| `InterfaceEventsInSeparateRunsAreAllDispatched` | Events in separate loop runs are all dispatched |
| `UnknownInterfaceEventIsIgnored` | Unknown interface event is ignored |
| `InterfaceEventWithFullQueueStaysPendingAndIsDispatchedLater` | an `INTERFACE_UP` that cannot be queued (queue full) stays pending, is posted again on a later run and dispatched |
| `AddressesHashIgnoresTheListOrder` | Address hash is independent of the list order, another set gives another hash, no addresses gives 0 |
| `ReportStateDispatchesOnlyChanges` | Reported state dispatches up for the first or changed addresses, down for the last lost, nothing for the same state |
| `InitialStateDispatchesNothing` | Initial state is remembered without an event |
| `MessageBeyondRxPendingLimitIsDropped` | A received message beyond `KNX_NET_MAX_RX_PENDING` is unref'd, the queued ones are delivered |

---

### test_oc_network_interface.cpp — Network Interface Enumeration (5 tests)

**Source:** `src/port/.../ipadapter` (`oc_get_network_interfaces`, filter)

| Test | What it verifies |
|------|-----------------|
| `EnumerateRejectsNullBuffer` | NULL buffer rejected |
| `EnumerateRejectsNonPositiveMax` | Non-positive max rejected |
| `EnumerateReturnsWithinBounds` | Returns a count within bounds |
| `EnumerateRespectsMaxInterfaces` | Respects the max-interfaces cap |
| `FilterSetAndGetRoundTrip` | Interface filter set/get round-trips |

---

### test_oc_process.cpp — Process / Event Loop (18 tests)

**Source:** `src/util/oc_process.c`

| Test | What it verifies |
|------|-----------------|
| `StartDeliversSynchronousInitEvent` | Start delivers a synchronous init event |
| `StartTwiceDoesNotReinitialize` | Starting twice does not reinitialise |
| `PostQueuesEventDeliveredByRun` | Posted event delivered by run |
| `PostSynchDeliversImmediately` | Synchronous post delivers immediately |
| `PostPropagatesData` | Post propagates the event data |
| `PollSchedulesPollEventDrainedByRun` | Poll schedules a poll event drained by run |
| `PollOnStoppedProcessIsIgnored` | Poll on a stopped process is ignored |
| `NEventsReflectsQueueDepth` | `oc_process_nevents()` reflects queue depth |
| `RunReturnsRemainingEventCount` | Run returns remaining event count |
| `AllocEventReturnsIncreasingIds` | Event allocation returns increasing ids |
| `AllocEventStartsAfterReservedRange` | Allocation starts after the reserved range |
| `ExitStopsRunningProcess` | Exit stops a running process |
| `BroadcastEventReachesRunningProcess` | Broadcast event reaches a running process |
| `ExitOnNeverStartedProcessIsNoOp` | Exiting a process never added to the list is a no-op (`exit_process`'s not-found branch) |
| `ExitNotifiesSiblingAndUnlinksFromListMiddle` | With two processes running, exiting the list head notifies the surviving sibling with `OC_PROCESS_EVENT_EXITED` and unlinks correctly |
| `PostBeyondCapacityGrowsQueueAndPreservesOrder` | Posting well past the initial ring capacity forces the realloc + wraparound-copy growth path in `oc_process_post`, preserving FIFO order |
| `PostAfterShutdownIsRejected` | after `oc_process_shutdown()` a post returns `OC_PROCESS_ERR_FULL` (no write into freed memory); after a new init posting works again |
| `PostAtTheMaximumIsRejectedAndTheQueueRecovers` | `OC_PROCESS_MAX_EVENTS` posts succeed, the next returns `OC_PROCESS_ERR_FULL` (no `oc_abort`); after one delivered event (order kept) posting works again |

---

### test_oc_random.cpp — Random (5 tests)

**Source:** `src/port/.../oc_random`

| Test | What it verifies |
|------|-----------------|
| `ValueProducesVaryingOutput` | `oc_random_value()` produces varying output |
| `FillReturnsZeroAndWritesBytes` | Fill returns 0 and writes bytes |
| `FillZeroLengthSucceeds` | Zero-length fill succeeds |
| `TwoFillsDiffer` | Two fills differ |
| `InitIsIdempotent` | Init is idempotent |

---

### test_oc_server_api.cpp — Server API (43 tests)

**Source:** `src/resources/ri/oc_server_api.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `ServerApiQuery` | 9 | Query value/exists lookups, empty and non-empty iteration, NULL request |
| `ServerApiResponse` | 9 | Response preparation (CBOR/JSON/link-format/no-format), ignore-request, missing-buffer guards |
| `ServerApiResource` | 25 | Resource allocation failure, new resource defaults to Content-Format CBOR (bind overrides it), add then `oc_delete_resource` (leaves the app list, NULL -> false), separate setup, delayed callbacks, bind/handler/interface/ACL/property and const/null guards |

---

### test_oc_storage.cpp — Persistent Storage (9 tests)

**Source:** `src/port/.../oc_storage.c`

| Group | Tests | What it covers |
|-------|-------|----------------|
| `OcStorageBeforeConfig` | 3 | Config rejects NULL/empty/overlong path; read/write/erase fail without config |
| `OcStorage` | 6 | Write→read round-trip (text/binary), size cap, missing file, erase, overwrite; each test has its own storage directory, removed in TearDown (`test_helpers_storage.h`) |

---

### test_oc_test_control.cpp — Test Control Trigger (4 tests)

**Source:** `src/resources/ri/oc_test_control.c`

| Test | What it verifies |
|------|-----------------|
| `NullPathReturnsBadRequest` | NULL path → bad request |
| `OverLongPathInvokesSetDpThenBadRequest` | Over-long path invokes set-dp then bad request |
| `OverLongPathWithoutCallbackStillBadRequest` | Over-long path without callback → bad request |
| `DeferredCbWithNoPendingReturnsDone` | Deferred trigger with nothing pending → done |

---

### test_separate.cpp — Separate Responses (8 tests)

**Source:** `src/messaging/coap/separate.c`, `src/resources/ri/oc_server_api.c` (separate response send); linked with `-Wl,--wrap=coap_send_message`, `-Wl,--wrap=oc_main_initialized`

| Test | What it verifies |
|------|-----------------|
| `AcceptNonRequestCreatesStore` | Accepting a non-request creates a store |
| `AcceptSameTokenAndObserveReusesStore` | Same token + observe reuses the store |
| `AcceptDifferentObserveCreatesSecondStore` | Different observe creates a second store |
| `AcceptConRequestSendsEmptyAckAndCreatesStore` | CON request sends the empty ACK (via `--wrap=coap_send_message`) and creates the store |
| `ResumeInitializesResponsePacket` | Resume initialises the response packet |
| `ResumeWithObserveZeroSetsObserveHeader` | Resume with observe 0 sets the observe header |
| `ClearRemovesMiddleStore` | Clear removes a middle store |
| `BlockwiseResponseBufferKeepsTheContentFormat` | A 100-byte separate response with block size 64 is sent (the build buffer is not taken for an earlier transfer); the transfer buffer keeps the rest (offset 64) with Content-Format CBOR |

---

### test_spake2plus.cpp — SPAKE2+ Handshake (29 tests)

**Source:** `src/security/spake2plus.c`

`Spake`: 22 tests — fixture (P-256 initialized per test; PSA initialized globally).

| Test | What it verifies |
|------|-----------------|
| `SpakeEncode.UintLittleEndian` | uint64 encoding uses eight little-endian bytes |
| `SpakeEncode.UintZero` | Zero encodes as eight zero bytes |
| `SpakeEncode.StringLengthPrefixed` | String bytes follow an eight-byte little-endian length |
| `SpakeEncode.StringEmpty` | Empty string encodes only its zero length |
| `SpakeEncode.PointLengthPrefixed` | Point bytes follow their encoded length |
| `SpakeLifecycle.InitThenFreeSucceeds` | P-256 initialization and cleanup succeed |
| `SpakeLifecycle.InitFreeIsRepeatable` | Three initialization/cleanup cycles succeed |
| `Spake.ParameterExchangeFillsBuffers` | Nonce generation fills the output with nonzero material |
| `Spake.GenKeypairProducesValidPoint` | Generated scalar is nonzero and public point has uncompressed prefix |
| `Spake.GenKeypairIsRandom` | Two generated private scalars differ |
| `Spake.GetW0LParamsDeterministic` | Identical password parameters reproduce w0 and L |
| `Spake.CalcShareProducesValidPoints` | Both shares have uncompressed prefixes and differ for the same public key |
| `Spake.KSharedDerivationsAreDeterministicAndDistinct` | Repeated 16-byte key derivation agrees; 16- and 32-byte outputs are nonzero |
| `Spake.FullHandshakeBothSidesAgree` | Responder transcript, both confirmation MACs and shared key are nonzero; confirmV is repeatable |
| `Spake.TranscriptInitiatorAgreesWithResponder` | Both transcript roles agree using a matched w1/L pair |
| `Spake.TranscriptInitiatorIsDeterministicAndContextSensitive` | Identical inputs reproduce the hash; changing context changes it |
| `Spake.PasswordExpansionMatchesKnxVector` | Configuration-client password, 32-byte salt and 1000 iterations produce exact w0 and uncompressed L |
| `Spake.SharesMatchKnxVector` | Fixed x*G/y*G and w0 produce the configuration-client shareP/shareV bytes |
| `Spake.BothRolesMatchKnxKeyScheduleVector` | Both roles match independent KNX-profile transcript, confirmP, confirmV and 16-byte shared-key answers |
| `Spake.ResponderMatchesRfc9383Vector` | RFC responder hash, confirmation MACs and 16-/32-byte shared keys match byte for byte |
| `Spake.InitiatorMatchesRfc9383Vector` | RFC initiator transcript hash matches byte for byte |
| `Spake.ResponderRejectsShareNotOnCurve` | Off-curve share is rejected without producing a transcript hash |
| `Spake.ShareAtInfinityIsRejected` | A share calculation yielding infinity is rejected |
| `Spake.TranscriptStripsLeadingZerosOfW0` | Leading-zero scalar encoding matches the recorded transcript hash |
| `Spake.ResponderWipesEphemeralPrivateKey` | Successful transcript computation clears the ephemeral scalar |
| `Spake.ResponderWipesEphemeralPrivateKeyOnFailure` | Failed transcript computation also clears the ephemeral scalar |
| `Spake.VerifyConfirmPAcceptsRfc9383Mac` | Correct RFC confirmation MAC is accepted |
| `Spake.VerifyConfirmPRejectsWrongMac` | Single-byte MAC mutation is rejected |
| `Spake.VerifyConfirmPRejectsMacOverOtherShare` | MAC bound to the wrong share is rejected |

The KNX dataset is shared with the configuration client's cryptographic tests:
password `LJFYEARVK56STM70`, salt `aabbccdd` repeated eight times, 1000
iterations, empty identities and context `knxpase`. Expected answers are fixed,
not recomputed by the C implementation under test. Python's compressed L is
expanded to the stack's uncompressed representation. The existing device fixture
keeps its password, salt `00..1f` and 50000 iterations unchanged.

Validated on 2026-11-16: all 29 cases passed with GCC and GCC ASan/UBSan
in Docker. The full runtime run passed 294 tests with 5 skips, including the
strengthened handshake assertions; conformance section 5.3.1 also passed.

---

### test_app_precalculated_spake.cpp — Precalculated SPAKE2+ Record (9 tests)

**Source:** `app_get_precalculated_spake_data()` (`include/oc_knx.h`) + `oc_spake2plus_init_data()` (`src/resources/knx/oc_knx.c`)

| Group | Tests | What it covers |
|-------|-------|----------------|
| `AppPrecalculatedSpake` | 7 | Record getter: non-NULL, valid contents, stable pointer, salt + iteration-count match, L is an uncompressed P-256 point, w0 non-zero |
| `AppSpakeRecord` | 1 | w0 and L re-derived from password + salt + iterations match the record |
| `AppPrecalculatedSpakeInit` | 1 | `oc_spake2plus_init_data()` succeeds with the valid stub record |

---

### test_dns_sd_mdns.cpp — DNS-SD Announcements and Query Responder (49 tests)

**Source:** `src/port/dns-sd_mdns.c`

Linker `--wrap` of `oc_network_event_handler_mutex_lock` / `_unlock` (count how deep the calling thread holds the mutex: `get_ip_context_for_device` returns an EMPTY endpoint list to a thread without the mutex, so every test also checks that the endpoint list is only walked under it), `sendto`, `recvmsg`, `get_ip_context_for_device`,
`oc_clock_time` and `oc_main_initialized`: no packet leaves the host, the
listener thread receives only the queries the test queues, one fake loopback
endpoint stands in for the connectivity layer, a test-controlled clock drives
the RI timed-event list through `oc_main_poll()`, and a test flag stands in for
the stack initialization (no `oc_main_init()`, the service update announces
nothing while it is false). The fixture sets the device hostname while the flag
is false, then runs initialized. The target is registered under `if(UNIX)`,
since the source is POSIX-only and `--wrap` is a GNU ld feature.

| Group | Tests | What it covers |
|-------|-------|----------------|
| `knx_dns_sd_update_service` | 14 | Record built from the device info: First announcement, RFC 6762 section 8.3 repeat at 1 s and only once, section 8.4 restart on a change, goodbye for the old record, no goodbye for unchanged content, NULL device, NULL serial, rollback on send failure, retry of a failed update after 1 s and 2 s that ends with the success, success on one of two interfaces, no interface (no retry), nothing before the stack is initialized |
| host name (`oc_core_set_device_hostname`) | 3 | No packet for a change before the stack is initialized, the first announcement after it carries the latest host name set before (no goodbye), a change afterwards sends the goodbye with the old name, then announces the new one |
| programming mode (`oc_knx_device_set_programming_mode`) | 3 | No packet for a change before the stack is initialized, the first announcement after it carries the `_pm` subtype set before (no goodbye), on and off afterwards each send the goodbye for the old record, then announce the new one with or without `_pm` |
| `knx_dns_sd_set_sleep_period` | 6 | SP in TXT, repeat after the change, TXT goodbye on clear, no goodbye for an unset SP, nothing before a publish, retry of a failed announcement |
| `knx_dns_sd_stop` | 3 | Goodbye and cancel of the pending repeat, cancel of a pending retry, nothing without a publish |
| getters | 2 | `knx_dns_sd_get_used_port`, `knx_dns_sd_get_current_record` before, after and past a publish |
| query responder | 11 | PTR for service type, serial, IA and `_pm` subtype (programming mode only), ANY, SRV, AAAA, TXT, foreign names, unhandled type, application-set host name in SRV target and AAAA |
| AAAA records per interface | 4 | RFC 6762 section 15: an announcement and the PTR, SRV and AAAA answers name only the addresses of the interface they leave on; a query from an interface without an own address gets no answer; an unknown receive interface gets every address |
| send buffer | 1 | `WorstCasePacketFitsTheSendBuffer`: the largest announcement fits the send buffer |
| receive interface from the sender | 2 | Without `IPV6_PKTINFO` (as on Windows) `mdns_ifindex_from_source()` takes the zone of a link-local sender as the interface, a ULA sender leaves it unknown |

---

### test_smode_issue.cpp — S-Mode Send Path (8 tests)

**Source:** `src/resources/knx/oc_knx_client.c` (`oc_issue_s_mode_message()`, driven through the public `oc_send_s_mode_multicast_message()`), network faked with linker `--wrap` (`oc_main_initialized`, `coap_send_message`, `oc_etimer_restart`; `oc_allocate_message` counted; `coap_new_transaction_with_message` can fail; `oc_knx_notify_k_observers` recorded)

| Test | What it verifies |
|------|-----------------|
| `SModeIssue.MulticastWriteSendsOneNonPostToK` | One message, sent as CoAP NON POST to `/k` with an 8-byte token; the payload is the s-mode envelope carrying the written value |
| `SModeIssue.MulticastReadSendsOneMessage` | Read request (no value): one message allocated and sent |
| `SModeIssue.NoTransactionReleasesTheMessage` | No transaction free: nothing sent, the single message is released (ASan/LSan: no leak) |
| `SModeIssue.WriteNotifiesKObserversAfterTheSend` | `/k` Group Message event (spec 2.6.9.3) after the s-mode message, payload = the sent envelope |
| `SModeIssue.NoTransactionNoKNotification` | No transaction, no s-mode message: no `/k` event either |
| `SModeIssue.ReadDoesNotNotifyKObservers` | A read (`r`) is sent but gives no `/k` event (only `st = w`) |
| `SModeIssue.EnvelopeLargerThanOnePacketIsNeverSentTruncated` | A ~590 B envelope (580 B value) is either sent complete or not at all, never cut at `OC_BLOCK_SIZE` (512 B); with the envelope budget `OC_S_MODE_ENVELOPE_BUDGET` it is not sent |
| `SModeIssue.UnicastConWriteSendsOneConPostAndNotifiesAfter` | Unicast write (own `at`, IPv6 resolved, CON): one message, CoAP CON POST, `/k` event after the send |

---

### test_oc_knx_client_off.cpp — Stack Without OC_CLIENT (2 tests + 1 build test)

**Source:** `src/resources/knx/oc_knx_client.c` (`ipv6_for_ia_is_resolved()` via `oc_send_s_mode_unicast_message()`), `src/messaging/coap/transactions.c`. Built in `tests/unit/client_off/` against its own stack library without `OC_CLIENT` (as `CONFIG_KNXIOT_CLIENT=n` on Zephyr and ESP-IDF); `ClientOff.StackBuildsAndLinksWithoutOcClient` builds and links it and is the fixture of the run `ClientOff.test_oc_knx_client_off`. The CI job `build-server-only` compiles the stack with the CMake option `OC_CLIENT_ENABLED=OFF`.

| Test | What it verifies |
|------|-----------------|
| `ClientOff.StackBuildsAndLinksWithoutOcClient` | The server-only stack compiles warning-free and links without unresolved client symbols |
| `ClientOff.UnresolvedUnicastRecipientFailsWithoutDiscovery` | Unicast write to an unresolved recipient: nothing handed over, the recipient is marked `FAILED` (no CoAP discovery exists) |
| `ClientOff.FailedUnicastRecipientIsNotRetried` | A second trigger leaves it `FAILED` and sends nothing |

---

### Stack Without OC_PUBLISHER_TABLE — Plain Sender (`PublisherOff`, 2 runs + 1 build test)

**Source:** `src/resources/knx/oc_knx_fp.c`. Built in `tests/unit/publisher_off/` against its own stack library without `OC_PUBLISHER_TABLE` (as `OC_PUBLISHER_TABLE_ENABLED=OFF` or `CONFIG_KNXIOT_PUBLISHER_TABLE=n`): `kis-common` leaves the definition out for targets with the property `KIS_NO_PUBLISHER_TABLE`. The test files that depend on the switch run a second time, their publisher tests left out: `PublisherOff.test_oc_knx_fp` runs `test_oc_knx_fp.cpp` and `PublisherOff.test_oc_core_res` runs `test_oc_core_res.cpp` (`CoreResourceByIndex` checks the registry without `/fp/p` and `/fp/p/*`).

| Test | What it verifies |
|------|-----------------|
| `PublisherOff.StackBuildsAndLinksWithoutPublisherTable` | The plain-sender stack and both test files compile warning-free and link: every publisher function declared in `oc_knx_fp.h` exists |
| `FpTableSizes.PublisherTableIsEmptyWithoutOcPublisherTable` | Size 0, no entry, an id or group address is never found (-1, NULL) |
| `FpHandlers.GoEntryGetIsAllowedForADeviceScopeToken` | Same scope for GET `/fp/g/*` as with the publisher table (F-080) |
| `GroupMulticasts.PlainSenderJoinsNoGroup` | Without a publisher table no group id is known: `oc_register_group_multicasts` joins no group |

---

### test_smode_loopback_recursion.cpp — S-Mode Write Loopback and Dispatch Result (16 tests)

**Source:** `src/resources/knx/oc_knx_client.c` (`oc_send_s_mode_mc_or_uc_message()`, `oc_send_s_mode_mc_or_uc_message_dispatched()`); the transmission is faked with `--wrap=coap_new_transaction_with_message` (records the serialized message or fails), `coap_send_transaction`, `coap_notify_observers_dispatched` and `oc_knx_notify_k_observers`

| Test | What it verifies |
|------|-----------------|
| `SmodeLoopback.RecursiveWriteFromPutHandlerIsBounded` | A PUT handler that sends an s-mode write on the same GA does not re-enter itself through the internal GO update (regression for an unbounded recursion) |
| `SmodeLoopback.SingleLevelLoopbackStillUpdatesOtherInputs` | An ordinary write still updates a different writable input on the same GA exactly once |
| `SmodeLoopback.OversizedValueIsNeitherSentNorLoopedBack` | F-047: a value larger than the buffer (size -1) gives rc -1, no send and no loopback PUT |
| `SmodeLoopback.EmptyValueIsNeitherSentNorLoopedBack` | F-047: a GET handler that encodes nothing (size 0) gives rc -1, no send and no loopback PUT |
| `SmodeDispatch.WriteThatIsNotSentDoesNotNotifyKObservers` | No transaction for the write: the `/k` observers are not notified (the write is repeated later) |
| `SmodeDispatch.SentWriteNotifiesKObserversWithTheSentEnvelope` | The `/k` event carries the envelope that was sent (the payload after the 0xFF marker of the sent message), although the send reuses the encoder buffer |
| `SmodeDispatch.WriteWithoutRecipientAndObserverIsNotDispatched` | rc 0 but not dispatched without recipient and observers; the old function keeps rc 0 |
| `SmodeDispatch.MulticastWriteIsDispatched` | Multicast write to a recipient → dispatched |
| `SmodeDispatch.WriteIsNotDispatchedWhenMessageCannotBeCreated` | Message creation fails → not dispatched |
| `SmodeDispatch.SendHandsTheEncoderBackToTheCaller` | A send from inside a handler that is encoding its response: the response continues on its own buffer |
| `SmodeDispatch.UnicastWithoutIndividualAddressIsNotDispatched` | Unicast recipient without IA → not dispatched |
| `SmodeDispatch.WriteWithoutTransmitFlagNotifiesObservers` | Loaded, group object without t-flag: write → -1, no s-mode, /p observers notified (dispatched) |
| `SmodeDispatch.WriteWithoutGroupObjectNotifiesObservers` | Loaded, no group object: write → -1, /p observers notified (dispatched) |
| `SmodeDispatch.WriteWithoutGroupObjectAndObserversIsNotDispatched` | No group object and no observers → not dispatched |
| `SmodeDispatch.ReadWithoutGroupObjectDoesNotNotifyObservers` | A read without group object notifies nobody |
| `SmodeDispatch.WriteBeforeLoadingDoesNotNotifyObservers` | Not loaded → -1, observers not notified |

---

### test_smode_read_answer_payload.cpp — S-Mode Read Answer Payload (1 test)

**Source:** `src/resources/knx/oc_knx.c` (`oc_core_knx_k_post_handler()`)

| Test | What it verifies |
|------|-----------------|
| `SmodeReadAnswer.SecondReadAnswerOnSameGaHasNoTrailingGarbage` | With two read-enabled GOs on one GA, every read answer carries exactly the length its own GET handler encoded (regression for stale buffer bytes in the second answer) |

---

### Runtime-covered source files (no unit tests)

`src/resources/ri/oc_test_control.c` and `src/resources/knx/oc_knx_p.c` — previously listed here as
runtime-only — now have dedicated unit test files
([test_oc_test_control.cpp](unit/test_oc_test_control.cpp),
[test_oc_knx_p.cpp](unit/test_oc_knx_p.cpp)) that exercise their handlers
directly. End-to-end behaviour over the live CoAP/OSCORE pipeline remains
covered by the runtime conformance suite (Part 2).

---

<a id="runtime-tests"></a>
## Part 2: Runtime Tests (Python / pytest)

Tests exercise the **full stack** over real CoAP/OSCORE on IPv6, against the
`runtime_test_server` device (`tests/common/runtime_test_server.c`), with the
test tool's client (`tests/iot-test-tool/transport/`). No mocks. They run in
Docker only (`tests/common/tools/run-in-docker.ps1 -Tier runtime`).

The runtime tier covers only behaviour the conformance template does not.
On 2026-09-11 every hand-written test the template already covers was
removed (the per-test mapping is in the message of commit 1edfc8ab, part
"runtime tier: drop template-covered tests, mark overlaps"), and the
remaining tests were named for their behaviour. A test that overlaps a
template case because it asserts materially more carries
`@pytest.mark.eitt_overlap(<id>)`, shown in the "Overlaps" column below;
list them with `pytest tests/runtime -m eitt_overlap --collect-only -q`.

The tables below are generated from the sources: one row per test function,
the text is the first sentence of its docstring (or its class's), and ×N
is the number of collected items of a parametrized test.

**DUT config:** Serial=`00fa10020800`, Password=`2X4W3TE0DFLLS19Y1FCH`, IA=`0x1101`, IID=`0x1199887766` (`tests/common/fixtures.py`)

---

### Expected behaviour: block-wise responses (RFC 7959)

Any response body larger than the DUT's configured application buffer
(`KNX_PAYLOAD_SIZE`, currently 768, which floors to a 512-byte block) is delivered
block-wise. This is normal, conformant behaviour and **not** truncation:

- The DUT sets **Block2 (option 23)** with the `M` ("more") bit on every block but the
  last, and **Size2 (option 28)** on the first block giving the total body length.
- Because a block ends at a fixed byte offset, the payload of a non-final block
  routinely ends mid-token, e.g. `...;rt="urn:knx:dpa.65500.201";i`. That is a block
  boundary, not a half-written buffer.
- Block2 is a **Class E** option under OSCORE, so on protected exchanges it is carried
  inside the encrypted inner message, never as an outer option.

The tool's `transport/coap_client.py` handles this for the test author:

| Helper | Behaviour |
|---|---|
| `get()` | Reassembles Block2 into one complete body before returning |
| `oscore_get()` | Same, with Block2 encoded as an inner Class E option |
| `request()` / `oscore_request()` | **One request, one block.** Use these only when a test deliberately wants a single block; pass `block2=` to select which |
| `multicast_get()` | Reassembles too: a responder's further blocks are asked for as EITT does, NON GET with Block2 sent by unicast to the responder from the socket the multicast request left from (the device keeps the rest of the body for exactly that address and port) |

Measured link-format sizes at `KNX_PAYLOAD_SIZE` 768 (512-byte blocks):

| Request | Blocks | Full body |
|---|---|---|
| `GET /.well-known/core` | 1 | 396 bytes (no Block2) |
| `GET /.well-known/core?if=*` | 2 | 688 bytes |
| `GET /.well-known/core?rt=*` | 2 | 688 bytes |
| `GET /dev` (OSCORE) | 2 | 553 bytes |

---

### test_blockwise_response_type.py — Block-wise Response Type (2 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestBlockwiseResponseType** | `test_plain_con_request_gets_every_block_as_piggybacked_ack` |  | CON request: block 0 and the last block both arrive as ACK 2.05. |
|  | `test_oscore_non_request_gets_every_block_as_non` |  | NON request (OSCORE, as EITT sends its NON rows): every block, the last one included, comes back NON per RFC 7252 5.2.3. |

---

### test_coap_header_budget.py — Worst-Case CoAP Header Budgets (9 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestInnerHeaderBudgetWorstCase** | `test_oscore_get_with_maximum_uri_query_is_answered` |  | Maximum Uri-Query on an OSCORE GET must produce a response. |
|  | `test_oscore_get_with_maximum_uri_path_is_answered` |  | Maximum Uri-Path on an OSCORE GET must produce a response. |
|  | `test_oscore_get_with_maximum_path_and_query_is_answered` |  | Both Class E option sets at their maximum in one request. |
|  | `test_dut_still_responsive_after_worst_case_inner_frame` |  | The DUT must survive the worst-case inner frame and keep serving. |
| **TestPlainHeaderBudgetWorstCase** | `test_plain_discovery_with_maximum_uri_query_is_answered` |  | Maximum Uri-Query on a plain GET must produce a response. |
|  | `test_plain_request_with_maximum_uri_path_is_answered` |  | Maximum Uri-Path on a plain GET must produce a response. |
|  | `test_plain_discovery_with_maximum_path_and_query_is_answered` |  | Both option sets at their maximum in one unprotected request. |
|  | `test_dut_still_responsive_after_worst_case_plain_frame` |  | The DUT must survive the worst-case plain frame and keep serving. |
| **TestOuterHeaderBudgetBlockwise** | `test_oscore_discovery_pages_are_all_delivered` |  | A multi-block OSCORE discovery response must arrive complete. |

---

### test_coap_payload_limit.py — Oversized Application Payload (7 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestOversizedPayloadRejected** | `test_payload_exactly_max_returns_413` |  | A payload of exactly MAX leaves no room for the null-terminator. |
|  | `test_payload_above_max_returns_413` |  | A payload clearly above MAX -> 4.13. |
|  | `test_payload_of_one_block_is_not_rejected_with_413` |  | A payload of one block (512 B) without Block1 must not be answered with 4.13 (above one block: 4.13 + Size1, before: 766 B was checked) |
|  | `test_dut_still_responsive_after_oversized_request` |  | The DUT must survive the oversized request and keep serving. |
| **TestDatagramAboveReceiveBuffer** | `test_datagram_above_receive_buffer_is_dropped_without_response` |  | 1252 B CON PUT datagram (above OC_PDU_SIZE): dropped by the Linux IP adapter (MSG_TRUNC), no response, no RST, no 4.13; GET /.well-known/core succeeds after |
| **TestOscoreRequestAboveOneBlock** | `test_oscore_payload_above_one_block_returns_413_with_size1` |  | Protected PUT without Block1, payload one block + 88 B (below MAX, so it passes the parser): 4.13 with Size1 = 512 (before: RST) |
| **TestOscoreBlock1Transfer** | `test_post_above_one_block_with_block1_is_reassembled` |  | Protected POST /fp/g of 650 B (36 entries) in two Block1 blocks (the retry after 4.13 + Size1): block 0 -> 2.31 Continue, last block -> 2.01, Block1 echoed; the first and the last entry read back (reassembled payload parsed) |

---

### test_device_resources.py — Device Resources (11 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestDevResourceList** | `test_dev_link_format_lists_sub_resources` | 5.2.5.1 | GET /dev → 2.05 with link-format listing all sub-resources. |
| **TestDevResourceRead** | `test_read_serial_number` | 5.2.6.1 | GET /dev/sn → serial number 00fa10020800. |
|  | `test_read_firmware_version` | 5.2.6.1 | GET /dev/fwv → firmware version [0, 0, 1]. |
|  | `test_read_model` | 5.2.6.1 | GET /dev/model → 'KNX Certification'. |
|  | `test_read_subnet_address` | 5.2.6.1 | GET /dev/sna → subnet address 17 (0x1101 >> 8 = 0x11 = 17). |
|  | `test_read_device_address` | 5.2.6.1 | GET /dev/da → device address 1 (0x1101 & 0xFF = 0x01 = 1). |
|  | `test_read_programming_mode` | 5.2.6.1 | GET /dev/pm → programming mode boolean. |
|  | `test_read_manufacturer_id` | 5.2.6.1 | GET /dev/mid → manufacturer ID 667. |
|  | `test_read_coap_port` | 5.2.6.1 | GET /dev/port → CoAP port integer. |
|  | `test_read_ipv6_address` | 5.2.6.1 | GET /dev/ipv6 → 16-byte IPv6 address. |
|  | `test_read_hostname` | 5.2.6.1 | GET /dev/hname → hostname 'knx-00fa10020800.local'. |

---

### test_discovery_mdns.py — mDNS Discovery (27 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestMdnsDiscoverySerialUnconfigured** | `test_browse_knx_service_by_serial` | 5.1.2.1 | Step 1-2: PTR query for _knx._udp.local -> find device by SN. |
|  | `test_srv_resolution_of_unconfigured_device` | 5.1.2.1 | Step 5-6: SRV query -> hostname + port. |
|  | `test_aaaa_resolution_of_unconfigured_device` | 5.1.2.1 | Step 7-8: AAAA query -> IPv6 address. |
|  | `test_coap_reachability_of_unconfigured_device` | 5.1.2.1 | Step 9-10: CoAP GET .well-known/core at discovered address → 2.05. |
| **TestMdnsDiscoverySerialConfigured** | `test_full_chain_by_serial_when_configured` | 5.1.2.2 | Full PTR -> SRV -> AAAA -> CoAP chain for configured device. |
| **TestMdnsDiscoveryIA** | `test_full_chain_by_individual_address` | 5.1.2.3 | Full discovery chain using IA subtype. |
| **TestMdnsDiscoveryIAUnconfigured** | `test_unconfigured_device_advertises_default_ia_subtype` | 5.1.2.3b | Factory-reset device should advertise _ia0-ffff subtype. |
| **TestMdnsDiscoveryPM** | `test_full_chain_via_programming_mode_subtype` | 5.1.2.4 | Full discovery chain via _pm subtype. |
|  | `test_programming_mode_subtype_withdrawn_when_disabled` | 5.1.2.4 | Disable PM → _pm subtype should no longer be advertised. |
| **TestMdnsUnsolicitedPM** | `test_programming_mode_toggle_announcements` | 5.1.2.5a | Toggle PM on→off→on and verify mDNS announcements appear. |
| **TestMdnsUnsolicitedIA** | `test_individual_address_change_announcement` | 5.1.2.5b | Change IA and verify new IA subtype appears in mDNS. |
| **TestMdnsSleepPeriod** | `test_sleep_period_not_present_by_default` |  | SP TXT record is absent when sleep period is 0 (default). |
|  | `test_sleep_period_200_appears_in_txt` |  | SP=200 appears in the TXT record after setting sp=200. |
|  | `test_sleep_period_20000_appears_in_txt` |  | SP=20000 appears in the TXT record after setting sp=20000. |
|  | `test_sleep_period_cleared_removes_txt` |  | Setting sp=0 after a non-zero value removes the TXT record. |
| **TestMdnsTransitionAudit** | `test_transition_ia_change` |  | IA/IID change: old _ia subtype in goodbye, new _ia subtype in re-announcement; SN, AAAA, and gap all verified. |
|  | `test_transition_pm_enable` |  | PM enabled: _pm subtype appears in re-announcement but not goodbye; SN, AAAA, and gap all verified. |
|  | `test_transition_pm_disable` |  | PM disabled: _pm subtype present in goodbye, absent in re-announcement; SN, AAAA, and gap all verified. |
|  | `test_transition_sleep_period_set` |  | SP set from 0 to 500: no goodbye expected (nothing to retract); SP=500 appears in re-announcement TXT; SN, AAAA, and gap verified. |
|  | `test_transition_sleep_period_clear` |  | SP cleared from 500 to 0: re-announcement without SP TXT; SN and AAAA verified. |
| **TestMdnsStateSync** | `test_state_sync_pm_sequence` |  | PM state is reflected correctly in mDNS across on/off cycle. |
|  | `test_state_sync_sleep_period_sequence` |  | Sleep-period TXT record stays in sync across set / clear cycle. |
|  | `test_state_sync_restart_preserves_state` |  | IA survives a restart; PM is always cleared by restart (spec). |
|  | `test_state_sync_factory_reset_clears_state` |  | Factory reset (erase_code=2) resets IA/IID to defaults, clears PM and SP. |
|  | `test_state_sync_restart_address_stability` |  | mDNS endpoint announced after restart is reachable by a fresh client. |
|  | `test_state_sync_factory_reset_address_stability` |  | mDNS endpoint announced after factory reset (erase_code=2) is reachable. |
|  | `test_state_sync_mdns_alive_in_unloaded` |  | mDNS keeps advertising when the LSM enters UNLOADED. |

---

### test_discovery_multicast.py — Multicast Discovery (2 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestMulticastProgrammingModeDiscovery** | `test_multicast_pm_query_silent_when_pm_off` | 5.1.1.5b | Overlaps EITT 5.1.1.5b: PM off, multicast ?if=urn:knx:if.pm → no response. |
| **TestMulticastIADiscovery** | `test_multicast_endpoint_query_silent_for_wrong_ia` | 5.1.1.9c | Overlaps EITT 5.1.1.9c: Multicast with wrong IA → no response (5s wait). |

---

### test_discovery_pagination.py — Unicast Discovery (9 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestDiscoveryPaginationManyFunctionalBlocks** | `test_wellknown_core_pagination_follows_next_links_over_all_fbs` |  | GET /.well-known/core?rt=*&ps=1 must paginate through every matching entry (core resources + app resources/FBs) via p.next, and a single request sized to that exact total must return the same set of resources with no further p.next. |
|  | `test_wellknown_core_pagination_negative_pn_returns_400` |  | GET /.well-known/core?rt=*&pn=-1 -> 4.00 Bad Request. |
|  | `test_wellknown_core_pagination_negative_ps_returns_400` |  | GET /.well-known/core?rt=*&pn=0&ps=-1 -> 4.00 Bad Request. |
|  | `test_wellknown_core_pagination_ps_zero_returns_400` |  | GET /.well-known/core?rt=*&pn=0&ps=0 -> 4.00 Bad Request. |
|  | `test_wellknown_core_pagination_negative_pn_and_ps_returns_400` |  | GET /.well-known/core?rt=*&pn=-1&ps=-1 -> 4.00 Bad Request. |
|  | `test_wellknown_core_pagination_non_numeric_pn_returns_400` |  | GET /.well-known/core?rt=*&pn=abc -> 4.00 Bad Request. |
|  | `test_wellknown_core_pagination_trailing_garbage_ps_returns_400` |  | GET /.well-known/core?rt=*&pn=0&ps=2abc -> 4.00 Bad Request. |
|  | `test_wellknown_core_pagination_out_of_int_range_pn_returns_400` |  | GET /.well-known/core?rt=*&pn=2147483648 -> 4.00 Bad Request. |
|  | `test_wellknown_core_pagination_overflow_pn_ps_returns_400` |  | GET /.well-known/core?rt=*&pn=100000&ps=100000 -> 4.00. |

---

### test_discovery_programming_mode.py — Extended Discovery (3 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestProgrammingModeDiscovery** | `test_pm_unicast_device_not_in_pm_returns_404` | 5.1.1.5d | Overlaps EITT 5.1.1.5d: Unicast, device NOT in PM → 4.04. |
|  | `test_pm_with_endpoint_device_not_in_pm_returns_404` | 5.1.1.6e | Overlaps EITT 5.1.1.6e: PM+ep, device NOT in PM → 4.04. |
|  | `test_pm_with_endpoint_wrong_serial_returns_404` | 5.1.1.6f | Overlaps EITT 5.1.1.6f: PM+ep, wrong SN → 4.04. |

---

### test_fingerprint.py — Fingerprint Resource (3 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestFingerprintChanges** | `test_fingerprint_changes_after_each_modification` | 5.2.4.1 | Fingerprint value must change after each table/param modification. |
| **TestFingerprintInvalidWrite** | `test_post_fingerprint_rejected` | 5.2.4.1b | Overlaps EITT 5.2.4.1b: POST /.well-known/knx/f → 4.05 Method Not Allowed. |
|  | `test_put_fingerprint_rejected` | 5.2.4.1c | Overlaps EITT 5.2.4.1c: PUT /.well-known/knx/f → 4.05 Method Not Allowed. |

---

### test_fp_tables.py — FP Table CRUD (13 tests, 26 collected)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestGroupObjectTableWrite** | `test_post_nonexisting_go_creates_entry` |  | POST with non-existing id creates new entry (2.01). |
| **TestPublisherTableWrite** | `test_update_multiple_publishers` |  | Create publishers, then POST same ids → 2.04. |
|  | `test_post_nonexisting_publisher_creates_entry` |  | POST with non-existing id creates new entry (2.01). |
| **TestRecipientTableUnicastAccessToken** | `test_ia_with_at_is_stored_and_read_back` |  | POST /fp/r with a direct unicast entry ('ia' + 'at', spec 2.5.7.4.2 Table 21, both "C u") is stored and reads back with 'at' under key 14. |
| **TestTableRepeatedKey** | `test_mixed_multicast_unicast_entries_are_created` ×2 |  | A repeated key in one entry of POST /fp/g, /fp/p, /fp/r: the last occurrence wins; the mandatory check counts which keys are present, not how often, so a repeated 'ga' cannot stand in for 'ia'/'grpid'. |
|  | `test_repeated_ga_without_target_is_rejected` ×2 |  | A repeated key in one entry of POST /fp/g, /fp/p, /fp/r: the last occurrence wins; the mandatory check counts which keys are present, not how often, so a repeated 'ga' cannot stand in for 'ia'/'grpid'. |
|  | `test_repeated_ga_with_grpid_last_wins` ×2 |  | A repeated key in one entry of POST /fp/g, /fp/p, /fp/r: the last occurrence wins; the mandatory check counts which keys are present, not how often, so a repeated 'ga' cannot stand in for 'ia'/'grpid'. |
|  | `test_rcp_repeated_at_last_wins` |  | A repeated key in one entry of POST /fp/g, /fp/p, /fp/r: the last occurrence wins; the mandatory check counts which keys are present, not how often, so a repeated 'ga' cannot stand in for 'ia'/'grpid'. |
|  | `test_ia_with_grpid_is_rejected` ×2 |  | A repeated key in one entry of POST /fp/g, /fp/p, /fp/r: the last occurrence wins; the mandatory check counts which keys are present, not how often, so a repeated 'ga' cannot stand in for 'ia'/'grpid'. |
|  | `test_go_repeated_ga_last_wins` |  | A repeated key in one entry of POST /fp/g, /fp/p, /fp/r: the last occurrence wins; the mandatory check counts which keys are present, not how often, so a repeated 'ga' cannot stand in for 'ia'/'grpid'. |
| **TestTableUnsupportedValueType** | `test_byte_string_value_is_rejected` ×4 |  | A value of a type the table handlers do not take (here a byte string under an unused key) is a 4.00 and nothing is stored, on /fp/g, /fp/p and /fp/r alike. |
| **TestTableGaNotNull** | `test_empty_array_ga_is_accepted` ×2 |  | An empty 'ga' is the empty array 7: [] (template 5.5.5.7a, allowed on /fp/p and /fp/r). |
|  | `test_non_array_ga_is_rejected` ×6 |  | An empty 'ga' is the empty array 7: [] (template 5.5.5.7a, allowed on /fp/p and /fp/r). |

---

### test_functional_blocks.py — Functional Blocks (2 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestFunctionalBlockList** | `test_read_fb_list` | 5.7.1.1 | GET /f returns link-format with at least two FB instances. |
| **TestFunctionalBlockDatapoints** | `test_read_fb_datapoints` | 5.7.2.1 | GET /f/417_1 returns link-format with datapoints /p/1 and /p/2. |

---

### test_generic_resources.py — Generic Protocol Behavior (15 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestPaginationEdgeCases** | `test_ps_zero_returns_400` |  | GET /fp/g?pn=0&ps=0 -> 4.00 (explicit ps=0 is always invalid). |
|  | `test_last_valid_page_exact_boundary` |  | GET /fp/g?pn=3&ps=1 → last entry, no p.next link. |
|  | `test_negative_pn_returns_400` |  | GET /fp/g?pn=-1&ps=2 -> 4.00 (a negative page number is invalid). |
|  | `test_negative_ps_returns_400` |  | GET /fp/g?pn=0&ps=-1 -> 4.00 (a negative page size is invalid). |
|  | `test_non_numeric_pn_returns_400` |  | GET /fp/g?pn=abc&ps=2 -> 4.00 (a non-numeric page number is invalid). |
|  | `test_trailing_garbage_ps_returns_400` |  | GET /fp/g?pn=0&ps=2abc -> 4.00 (trailing garbage is invalid). |
|  | `test_out_of_int_range_pn_returns_400` |  | GET /fp/g?pn=2147483648&ps=2 -> 4.00 (INT_MAX + 1 is invalid). |
|  | `test_overflow_pn_ps_returns_400` |  | GET /fp/g?pn=100000&ps=100000 -> 4.00 (pn * ps overflows int). |
|  | `test_leading_zero_ps_is_accepted` |  | GET /fp/g?pn=0&ps=00001 -> 1 entry (a leading zero is still a valid number). |
|  | `test_negative_five_digit_pn_returns_400` |  | GET /fp/g?pn=-12345&ps=2 -> 4.00 (a signed 6 char value is still negative). |
|  | `test_above_uint16_ps_returns_400` |  | GET /fp/g?pn=0&ps=65536 -> 4.00 (one above the 16 bit unsigned range). |
|  | `test_huge_pn_returns_400` |  | GET /fp/g?pn=999999&ps=2 → 4.00 (huge page number, still 4 entries). |
| **TestInvalidListMetadata** | `test_invalid_list_metadata_query_returns_404` | 5.10.1.5 | GET /fp/g?l=xxx (invalid metadata param) → 4.04 Not Found. |
| **TestDptMetadata** | `test_read_dpt_metadata_of_datapoint` | 5.10.4.1 | GET /p/1?m=dpt → {"dpt": ":dpt.switch"}. |
| **TestDefaultOptions** | `test_unknown_critical_option_returns_bad_option` | 5.10.5.3 | Send request with unknown critical CoAP option → 4.02 Bad Option. |

---

### test_group_comm.py — Group Communication (36 tests, 41 collected)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestUnicastWriteUnauthorized** | `test_unauthorized_ga_returns_forbidden` | 5.4.1.1.b | POST /k with ga=1 but AT scope only has [65535] → 4.03 Forbidden, /p/1 value unchanged. |
| **TestUnicastWriteDuplicateGroupAddress** | `test_control_authorized_ga_writes_only_its_own_datapoint` |  | Control: a plain single-ga write to the authorized 65535 changes /p/1 and leaves /p/4 alone. |
|  | `test_duplicate_ga_does_not_bypass_scope` |  | {7: 65535, ..., 7: 1} must not write /p/4: ga=1 is outside the token's scope. |
| **TestForeignGaBindingIsLive** | `test_authorized_write_to_ga_one_reaches_p4` |  | Control for TestUnicastWriteDuplicateGroupAddress. |
| **TestSiaOnlySyncMessage** | `test_unicast_sia_only_is_accepted` |  | Unicast POST /k with {4: sia} -> 2.04 Changed, not 4.04. |
|  | `test_unicast_sia_only_does_not_change_a_datapoint` |  | A 'sia' only message carries no ga and no value, so nothing moves. |
| **TestMulticastRead** | `test_multicast_read_gets_answer` | 5.4.1.3 | NON POST /k multicast with st:"r" → DUT responds with NON POST /k containing {sia:4353, s:{value:false, st:"a", ga:65535}}. |
| **TestUnicastRead** | `test_unicast_read_gets_answer` | 5.4.1.4 | CON POST /k with st:"r" → 2.04, DUT sends back CON POST /k with {sia:4353, s:{value:true, st:"a", ga:65535}}. |
| **TestTriggerMulticastWrite** | `test_trigger_multicast_write` | 5.4.1.6 | Trigger sensor on /p/3 → receive multicast s-mode write. |
| **TestUnicastWithoutAccessTokenNotSent** | `test_no_unicast_post_without_at` |  | A unicast recipient table entry without 'at' (14) has no credentials (spec 2.5.7.4.2 Table 21, 6.3.1.2): the DUT sends no unicast POST /k instead of guessing a token from the ga. |
| **TestMulticastSkipsUnicastRecipientToken** | `test_multicast_kid_is_not_unicast_token` ×2 |  | Spec 6.3.2.1 step 2: multicast takes the first OSCORE token that holds the ga AND is not the 'at' of a unicast recipient table entry. |
| **TestUnicastAndMulticastFromSameTables** | `test_unicast_and_multicast_use_their_own_token` ×2 |  | With a unicast and a multicast recipient in one RCP table, each send uses its own token: the unicast POST /k the recipient's 'at' (spec 2.5.7.4.2 Table 21, 6.3.1.2), the multicast the token holding the ga that is not a unicast 'at' (spec 6.3.2.1). |
| **TestInitFlagStartup** | `test_init_flag_sends_read_on_restart` | 5.4.1.9 | Restart device → receive multicast s-mode with st:"r". |
| **TestReadOnInitNetworkGate** | `test_read_on_init_up_from_start_sends_read` |  | ULA present before restart -> DUT sends the init read promptly. |
|  | `test_read_on_init_withheld_while_down` |  | Link-local only (scope 2) -> NO init read for >= 600 ms (6 cycles). |
|  | `test_read_on_init_released_after_network_up` |  | Network down from the start, then up after ~600 ms -> read fires. |
|  | `test_read_on_init_abandoned_after_max_retries` |  | Network never comes up -> read is abandoned after the 20-cycle cap. |
| **TestMulticastResponseUpdateOnly** | `test_answer_updates_update_only_go` |  | Set /p/1=true via /p, then multicast answer (st="a") false on a u-only GO. |
| **TestMulticastWriteWithIfGsToken** | `test_multicast_write_with_if_g_s_token_is_applied` |  | Multicast write true to ga 65535 protected with an `if.g.s` token (no ga list, all ga, spec 3.5.3 / 2.5.9.6) -> /p/1 becomes true. |
| **TestMulticastWriteWithoutGroupRights** | `test_multicast_write_without_group_rights_is_dropped` |  | Control: the same write with an `if.p` only token (no group rights) is discarded, /p/1 stays false. |
| **TestOwnGroupObjectUpdate** | `test_self_update_on_transmit` | 5.4.1.12 | Trigger sensor → DUT sends multicast write for ga=65535, DUT also updates /p/1 (receiving GO with ga=65535). |
| **TestLongGASend** | `test_sends_long_ga` | 5.4.1.14 | Trigger sensor → DUT sends multicast with ga=4294967295. |
| **TestUnicastConfirmable** | `test_unicast_sends_con` | 5.4.1.15 | Trigger sensor → DUT resolves PEER_IA via discovery, then sends CON POST /k (unicast to test host). |
| **TestUnicastUsesRecipientAccessToken** | `test_unicast_kid_is_recipient_access_token` ×2 |  | Unicast s-mode: the DUT encrypts with the access token the recipient table entry names in 'at' (14), not with the first token whose scope holds the ga (spec 2.5.7.4.2 Table 21, 2.6.9.2, 6.3.1.2 step 2). |
| **TestUnicastNonReResolution** | `test_unicast_non_re_resolution` |  | Trigger the sensor repeatedly; the DUT sends unicast NON POSTs that go unanswered. |
| **TestUnicastNonEchoReRequest** | `test_unicast_non_echo_re_request` |  | Unicast NON s-mode: a 4.01 Echo response to a NON POST /k makes the DUT send a re-request carrying the Echo option with a regenerated payload. |
| **TestUnicastNonEchoKidCtxReRequest** | `test_unicast_non_echo_kid_ctx_re_request` |  | Unicast NON s-mode, 4.01 Echo with a 10 byte kid context (EITT shape): accepted only against the echo ring anchor of the unicast send. |
| **TestUnicastConEchoKidCtxReRequest** | `test_unicast_con_echo_kid_ctx_re_request` |  | Unicast CON s-mode, 4.01 Echo with a 10 byte kid context (EITT shape): accepted only against the echo ring anchor of the unicast send. |
| **TestUnicastConEchoReRequest** | `test_unicast_con_echo_re_request` |  | Unicast CON s-mode, 4.01 Echo without kid context: the context is resolved through the CON transaction (group address + recorded PIV). |
| **TestUnicastConEchoReRequestResponse** | `test_response_to_re_request` ×3 |  | Unicast CON s-mode, 4.01 Echo, CON 'echo re-request': the peer's protected ACK 2.04 to the re-request is accepted, the DUT does not retransmit the re-request. |
| **TestUnicastDiscoveryMalformedLengths** | `test_unicast_discovery_iid_too_long` |  | IID of 12 hex chars exceeds the 10-char (5-octet) maximum; the IID/IA separator falls outside the parser search window, so the DUT must not resolve the recipient. |
|  | `test_unicast_discovery_iid_too_short` |  | An empty IID is invalid (all-zero collapses to a single '0'); the parsed IID does not match the device IID, so no POST follows. |
|  | `test_unicast_discovery_ia_too_long` |  | An IA of 5 hex chars exceeds the 4-char (2-octet) maximum; the first four chars ('2110') do not match PEER_IA (110f), so the DUT must not resolve the recipient. |
|  | `test_unicast_discovery_ia_too_short` |  | An empty IA is invalid (all-zero collapses to a single '0'); the parsed IA does not match PEER_IA, so no POST follows. |
|  | `test_unicast_discovery_sn_too_long` |  | A serial number longer than the parser search window pushes the 'knx://ia.' anchor out of reach, so the DUT cannot locate the IID/IA and must not resolve the recipient. |
|  | `test_unicast_discovery_sn_too_short` |  | A serial number shorter than the spec width of 12 hex chars. |

---

### test_ia_assignment.py — API Version & IA (3 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestIaAssignment** | `test_set_ia_and_iid` | 5.2.3.1 | Overlaps EITT 5.2.3.1: Setting Installation ID and Individual Address. |
|  | `test_get_ia_rejected` | 5.2.3.1b | Overlaps EITT 5.2.3.1b: GET /.well-known/knx/ia → 4.05 Method Not Allowed. |
|  | `test_set_ia_iid_and_fabric_id` | 5.2.3.2 | Overlaps EITT 5.2.3.2: Setting Fabric ID alongside IA and IID. |

---

### test_load_state_machine.py — Load State Machine (4 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestLsmTransitions** | `test_lsm_persist_loading` | 5.6.1.4 | LSM loading state (2) persists over reboot. |
|  | `test_lsm_persist_loaded` | 5.6.1.4 | LSM loaded state (1) persists over reboot. |
|  | `test_lsm_persist_unloaded` | 5.6.1.4 | LSM unloaded state (0) persists over reboot. |
| **TestLsmRead** | `test_read_lsm_all_states` | 5.6.2.1 | GET /a/lsm returns {3: <state>} for each LSM state. |

---

### test_observe.py — CoAP Observe / Notifications (19 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
|  | `test_observe_register_returns_current_value` |  | OBS-A1: a valid observe registration yields the current value. |
|  | `test_observe_value_change_notifies` |  | OBS-A2: each value change pushes a notification with an advanced seq. |
|  | `test_observe_deregister_stops_notifications` |  | OBS-A3: GET Observe=1 (same token) ends the relationship. |
|  | `test_observe_delete_sub_removes_subscription` |  | OBS-A3b: DELETE /sub is a third deregistration path. |
|  | `test_observe_resubscribe_replaces_by_ip_port` |  | OBS-A4: re-registering from the same IP+port replaces the prior sub. |
|  | `test_observe_missing_lt_rejected` |  | OBS-B1: an observe registration without lt is rejected with 4.00. |
|  | `test_observe_lt_zero_rejected` |  | OBS-B2: lt=0 is rejected with 4.00 (valid range is 1..86400). |
|  | `test_observe_expired_lt_stops_notifications` |  | OBS-B3: once the observe lifetime (lt) elapses the subscription is pruned, so a later value change yields no notification. |
|  | `test_observe_default_confirmable` |  | OBS-C1: default notifications are confirmable (CON). |
|  | `test_observe_non_true_non_confirmable` |  | OBS-C2: non=true yields non-confirmable (NON) notifications. |
|  | `test_observe_first_k_notification_sia_only` |  | OBS-D1: first /k notification is exactly {sia: <ia>} (2.5.9.1). |
|  | `test_observe_subsequent_k_notification_has_s_object` |  | OBS-D2: after an outbound s-mode w, the /k notification has the s obj. |
|  | `test_observe_k_deregister_stops_notifications` |  | OBS-D3: deregistering a /k observe returns 2.05 and stops notifications. |
|  | `test_observe_inbound_post_k_not_echoed` |  | OBS-D4: an inbound s-mode POST /k is not echoed to /k observers. |
|  | `test_observe_plain_get_k_no_subsequent` |  | OBS-D5: a plain GET /k (no Observe option) returns { sia } once and never produces subsequent push notifications; a repeated GET behaves identically to the first. |
|  | `test_observe_encrypted_notifications_decrypt` |  | OBS-E1: OSCORE notifications decrypt and the sequence advances. |
|  | `test_observe_notification_aad_binds_request_piv` |  | OBS-E2: a notification's AAD binds the original request PIV (regression). |
|  | `test_observe_independent_seq_per_observer` |  | OBS-F1: two observers each get their own notification + own seq. |
|  | `test_observe_stale_observer_pruned` |  | OBS-F2: a silent (CON, never-ACKing) observer is pruned, the other keeps receiving notifications. |

---

### test_parameters.py — Parameters (3 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestParameterList** | `test_read_parameter_list` | 5.8.2.1 | GET /p returns link-format listing including /p/p1 (parameter). |
| **TestParameterMetadata** | `test_read_metadata_id` | 5.8.3.2 | GET /p/p1?m=id returns only the id field. |
|  | `test_read_metadata_value` | 5.8.3.2 | GET /p/p1?m=value returns only the value field. |

---

### test_reset.py — Reset Commands (2 tests)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestFactoryReset** | `test_factory_reset_clears_all_state` | 5.2.2.1 | POST /.well-known/knx {2:'reset', 1:2} → full factory reset. |
| **TestResetCode7** | `test_reset_code_7_preserves_network_info` | 5.2.2.2 | POST /.well-known/knx {2:'reset', 1:7} → selective reset. |

---

### test_security.py — Security & OSCORE (74 tests, 81 collected)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestAuthResourceList** | `test_get_auth_without_oscore_returns_401` | 5.3.4.1 | GET /auth without OSCORE must return 4.01 Unauthorized. |
| **TestWriteAccessToken** | `test_write_at_and_verify` | 5.3.8.1 | POST /auth/at with a valid AT → 2.01, then verify via GET. |
|  | `test_write_at_with_group_scope` | 5.3.8.1 | POST /auth/at with integer (group) scope → 2.01. |
|  | `test_post_at_without_if_sec_scope_fails` | 5.3.8.1d | POST /auth/at with OSCORE but without if.sec scope → 4.03. |
|  | `test_overwrite_existing_at` | 5.3.8.4 | POST /auth/at with same id but new scope overwrites entry. |
|  | `test_create_multiple_ats_single_write` | 5.3.8.5 | POST /auth/at with array of 2 ATs → 2.01. |
|  | `test_update_multiple_ats` | 5.3.8.6 | POST /auth/at to update 2 existing ATs → 2.04. |
| **TestWriteAccessTokenEntryLimit** | `test_more_than_ten_tokens_in_one_post_returns_413` |  | POST /auth/at with 11 ATs (payload below one block) -> 4.13 from the handler (spec 2.6.3.3.2), none of them stored. |
|  | `test_ten_tokens_in_one_post_are_accepted` |  | POST /auth/at with 10 ATs (the limit) -> 2.01, all 10 stored. |
| **TestWriteAccessTokenMandatoryProperties** | `test_at_mandatory_create_with_id_only_rejected` |  | POST /auth/at with only the id -> 4.00, no entry created. |
|  | `test_at_mandatory_create_without_scope_rejected` |  | POST /auth/at without scope (9) -> 4.00, no entry created. |
|  | `test_at_mandatory_create_without_sender_id_rejected` |  | POST /auth/at without cnf:osc:id (8:4:0) -> 4.00, no entry. |
|  | `test_at_mandatory_create_without_master_secret_rejected` |  | POST /auth/at without cnf:osc:ms (8:4:2) -> 4.00, no entry. |
|  | `test_at_mandatory_create_with_empty_scope_array_rejected` |  | POST /auth/at with an empty scope array -> 4.00, no entry. |
|  | `test_at_mandatory_empty_scope_array_does_not_delete_entry` |  | POST [{id, 9: []}] on an existing AT must NOT delete it. |
|  | `test_at_mandatory_id_only_deletes_existing_entry` |  | POST [{id}] on an existing AT deletes it. |
|  | `test_at_mandatory_update_of_existing_entry_accepted` |  | POST [{id, 9: [...]}] on an existing AT updates the scope. |
|  | `test_at_mandatory_invalid_scope_names_rejected` ×3 |  | POST /auth/at with an invalid scope name -> 4.00, no entry. |
|  | `test_at_mandatory_mixed_scope_keeps_only_valid_names` ×4 |  | POST /auth/at with a mixed scope -> 2.01, only the valid bits are stored. |
| **TestWriteAccessTokenRepeatedKey** | `test_repeated_group_scope_last_wins` |  | POST /auth/at with a repeated key in one token (ADDITIONAL, non-EITT): accepted, the last occurrence wins, as on /fp/g, /fp/p and /fp/r. |
| `test_get_auth_at_without_oscore_returns_401` | 5.3.9.3a | GET /auth/at without OSCORE must return 4.01. |
|  | `test_get_auth_at_link_format` | 5.3.9.1 | GET /auth/at → 2.05 with link-format listing. |
| **TestReadAccessTokenById** | `test_get_at_by_id_without_oscore_returns_401` | 5.3.10.2a | GET /auth/at/{id} without OSCORE → 4.01. |
|  | `test_get_at_by_id` | 5.3.10.1 | GET /auth/at/RuntimeTest → 2.05 with CBOR AT details. |
|  | `test_get_nonexistent_at_returns_error` | 5.3.10.1 | GET /auth/at/nonexistent → 4.xx error (stack returns 4.00). |
| **TestDeleteAccessToken** | `test_delete_at` | 5.3.11.1 | Create an AT, delete it, verify it's gone. |
|  | `test_delete_nonexistent_at` | 5.3.11.1 | DELETE /auth/at/nonexistent → 4.xx error (stack returns 4.00). |
| **TestOscoreResourceList** | `test_get_auth_o_without_oscore_returns_401` | 5.3.12.1 | GET /auth/o without OSCORE must return 4.01. |
| **TestReplayWindowSize** | `test_get_replwdo_without_oscore_returns_401` | 5.3.13.1 | GET /auth/o/replwdo without OSCORE must return 4.01. |
|  | `test_get_replwdo` | 5.3.13.1 | GET /auth/o/replwdo → 2.05 with CBOR integer. |
| **TestOscoreDelay** | `test_get_osndelay_without_oscore_returns_401` | 5.3.15.1 | GET /auth/o/osndelay without OSCORE must return 4.01. |
|  | `test_get_osndelay` | 5.3.15.1 | GET /auth/o/osndelay → 2.05 with CBOR integer value. |
|  | `test_put_osndelay` | 5.3.16.1 | PUT /auth/o/osndelay with a new value → 2.04, then verify. |
| **TestOscoreEncryption32ByteMs** | `test_oscore_with_32_byte_master_secret` | 5.3.19.1 | Create AT with 32-byte MS, use its OSCORE context to PUT dev/pm. |
| **TestAccessControlByScope** | `test_limited_scope_rejected_for_post_auth_at` | 5.3.20.1 | AT with scope=["if.c"] cannot POST /auth/at (requires if.sec). |
|  | `test_limited_scope_rejected_for_dev_pm` | 5.3.20.1 | AT with scope=["if.c"] cannot PUT /dev/pm (requires if.p). |
|  | `test_if_p_scope_can_access_dev_pm` | 5.3.20.1 | AT with scope=["if.p"] can PUT /dev/pm → 2.04. |
|  | `test_if_d_scope_can_read_device_info` | 5.3.20.1 | AT with scope=["if.d"] can GET /dev/da → 2.05. |
| **TestAntiReplayWindow** | `test_old_ssn_within_window_accepted` | 5.3.17.1 | PUTs with old SSNs within replay window are accepted. |
| **TestMessageIntegrity** | `test_corrupted_auth_tag_rejected` | 5.3.18.1 | OSCORE message with corrupted auth tag is rejected. |
|  | `test_different_auth_tag_rejected` | 5.3.18.1 | OSCORE message with completely different auth tag is rejected. |
| **TestEmptyMessageIsNotOscore** | `test_empty_message_with_oscore_option_rejected` ×3 |  | EMPTY CON/NON/ACK carrying an OSCORE option is never processed. |
|  | `test_empty_reset_does_not_break_oscore` |  | An EMPTY RST stays valid and must not disturb the OSCORE path. |
|  | `test_empty_reset_with_token_rejected` |  | An EMPTY RST that announces a token is refused. |
| **TestEchoChallenge** | `test_echo_on_new_context` | 5.3.17.7 | New security context gets echo-challenged on first request. |
| **TestOscoreContextId** | `test_context_ids_with_master_salt` | 5.3.19.6 | PUT dev/pm succeeds with each context ID + master salt. |
| **TestSecondarySpake** | `test_secured_spake_post_rejected` | 5.3.1.4a | Secured POST to /.well-known/knx/spake with pw field → 4.00. |
| **TestGroupOscoreMulticast** | `test_receive_device_multicast` | 5.3.17.6 | Overlaps EITT 5.3.17.6: Trigger sensor → receive multicast s-mode message. |
| **TestGroupOscoreMasterSaltCtxId** | `test_group_oscore_with_salt_and_ctx_id` | 5.3.19.5 | Overlaps EITT 5.3.19.5: Multicast s-mode with master salt + context ID. |
| **TestGroupAntiReplayWindow** | `test_group_anti_replay_window` | 5.3.17.3 | Overlaps EITT 5.3.17.3: Verify anti-replay window for group messages. |
| **TestSyncDelayEcho** | `test_sync_delay_echo` | 5.3.17.4 | Overlaps EITT 5.3.17.4: Change context ID → echo challenge → valid reply. |
| **TestInvalidEchoReply** | `test_invalid_echo_reply` | 5.3.17.5 | Overlaps EITT 5.3.17.5: Invalid echo value rejected by device. |
| **TestSpake2PlusResetTypes** | `test_spake_across_reset_types` | 5.3.1.3 | Walk through all 5 steps of 5.3.1.3 sequentially. |
| **TestEchoPaseToken** | `test_echo_on_pase_at_post` | 5.3.17.8 | Factory reset → SPAKE2+ → POST auth/at with PASE key → echo. |
| **TestSpake2PlusProtocol** | `test_spake_wrong_password_fails_verification` | 5.3.1.2 | SPAKE2+ with wrong password: confirmV verification fails. |
|  | `test_spake_wrong_confirm_p_rejected` | 5.3.1.2b | SPAKE2+ with correct password but wrong confirmP → 4.00. |
|  | `test_spake_full_handshake` | 5.3.1.1 | Exact 2.04 responses, CBOR maps, 32-byte nonce, provisioned salt/50000 iterations, uncompressed 65-byte shareV, 32-byte confirmV, empty step-3 payload and usable temporary OSCORE key. |
| **TestSpake2PlusStateMachine** | `test_spake_state_credential_before_parameter` |  | Credential request (step 2) in IDLE state → 4.00. |
|  | `test_spake_state_verification_before_parameter` |  | Verification request (step 3) in IDLE state → 4.00. |
|  | `test_spake_state_repeated_parameter_mid_handshake` |  | A second parameter request after step 1 is a legal restart of step 1. |
|  | `test_spake_state_parameter_missing_id` |  | Parameter request carrying only rnd (no id) → 4.00 (cardinality). |
|  | `test_spake_state_parameter_missing_rnd` |  | Parameter request carrying only id (no rnd) → 4.00 (cardinality). |
|  | `test_spake_state_ordered_handshake_completes` |  | Ordered step 1→2→3 is accepted end-to-end and yields a working key. |
|  | `test_spake_state_parameter_restart_then_completes` |  | A restarted step 1 (S1 in PARAMS_SENT) can drive a full handshake. |
|  | `test_spake_state_parameter_after_credential_restarts` |  | A parameter request (S1) in CREDENTIALS_SENT restarts step 1. |
|  | `test_spake_state_repeated_credential_request` |  | A second credential request (S2) in CREDENTIALS_SENT → 4.00. |
|  | `test_spake_state_verification_after_parameter` |  | A verification request (S3) in PARAMS_SENT → 4.00 (skips step 2). |
|  | `test_spake_state_restart_from_credentials_completes` |  | A restart from CREDENTIALS_SENT (S1 in CREDS) drives a full handshake. |
| **TestSpake2PlusBruteForce** | `test_spake_lockout_block_after_ten_failures` |  | 10 failed attempts arm the block; the next attempt returns 5.03. |
|  | `test_spake_lockout_factory_reset_clears_block` |  | A factory reset clears the brute-force block and counter. |
|  | `test_spake_lockout_counter_decreases_over_time` |  | While blocked, the counter ticks down every 6 s (Max-Age shrinks). |
|  | `test_spake_lockout_unblocks_after_timeout` |  | The counter reaches zero after ~60 s and the device unblocks itself. |
|  | `test_spake_lockout_partial_step_does_not_reset_counter` |  | A partial PASE step (step 1) does NOT reset the consecutive counter. |
|  | `test_spake_lockout_full_handshake_resets_counter` |  | A completed handshake succeeds below the threshold and resets it. |

---

### test_swu.py — Software Update (7 tests, 28 collected)

| Class | Test | Overlaps | What it checks |
|-------|------|----------|----------------|
| **TestSwuLastUpdateBeforeUpdate** | `test_lastupdate_is_mfg_date_before_any_update` |  | Before the first update /swu/lastupdate is the manufacturing date. |
| **TestSwuFirmwareUpdate** | `test_push_based_firmware_update` | 5.2.9.1 | Full PUSH-based firmware update cycle matching EITT 5.2.9.1. |
| **TestSwuLastUpdateAfterUpdate** | `test_lastupdate_changes_after_swu_update` |  | The DUT stamps a new timestamp when the update completes. |
|  | `test_lastupdate_survives_reboot` |  | /swu/lastupdate keeps its value across a device restart. |
| **TestSwuReadOnlyPutRejected** | `test_put_readonly_swu_rejected` ×5 | 5.2.10.1b | PUT /{path} → 4.xx (read-only SWU resource must reject write). |
| **TestSwuBlockQueryValidation** | `test_invalid_block_query_returns_400` ×18 |  | PUT /a/swu with an invalid po/ps/pkgs → 4.00. |
|  | `test_leading_zero_is_accepted` |  | PUT /a/swu?po=00&ps=008 → the values are decimal coded, not octal. |

---

<a id="skipped-tests"></a>
## Skipped tests

Reasons are taken from the `pytest.skip()` / `skipif` sites in the test
sources. The full runs of 2026-11-02 skip exactly these five:

| Test | Skip mechanism | Outcome |
|------|----------------|---------|
| `test_spake_lockout_unblocks_after_timeout` | Static `@pytest.mark.skipif(os.environ.get("RUN_SLOW_TESTS") is None, ...)` | **Passes** with `run-in-docker.ps1 -RunSlowTests`: waits out the full 10 x 6 s brute-force lockout (~60 s). Measured 2026-11-02: `1 passed in 70.85s` |
| `TestReadOnInitNetworkGate::test_read_on_init_up_from_start_sends_read` | Class setup, `_roi_network_control_available()` probes `ip -6 addr add ... dev veth-dut` | **Cannot run on the netns harness:** `veth-dut` lives in the network namespace `dut` (`Cannot find device "veth-dut"` from the test's namespace), and the DUT keeps its ULA `fd11:9988:7766::1` because the tests talk to it on that address, so a link-local-only "network down" state cannot be produced. Left skipped (decision 2026-11-02) |
| `TestReadOnInitNetworkGate::test_read_on_init_withheld_while_down` | same | same |
| `TestReadOnInitNetworkGate::test_read_on_init_released_after_network_up` | same | same |
| `TestReadOnInitNetworkGate::test_read_on_init_abandoned_after_max_retries` | same | same |

Conditional skips that did NOT trigger in those runs (they skip only on a timing
miss or in partial runs):

| Test | Skip mechanism | Note |
|------|----------------|------|
| `test_unicast_discovery_iid_too_short`, `test_unicast_discovery_sn_too_long`, `test_unicast_discovery_sn_too_short` | `_assert_rejected()` -> `if not result.get("got_get")` | Wait up to 20 s for the DUT's discovery GET; under cumulative load they skipped in earlier runs, alone they pass in 9-16 s |
| `test_init_flag_sends_read_on_restart` | `if len(received) == 0` | Skipped in earlier runs (`POST /test/restart` re-initialises in-process, no cold boot) |

Running them alone:

```powershell
.\tests\common\tools\run-in-docker.ps1 -Tier runtime -IncludeUncommitted -k 'discovery_iid_too_short'
.\tests\common\tools\run-in-docker.ps1 -Tier runtime -IncludeUncommitted -RunSlowTests -k 'lockout_unblocks'
```

The `-k` expression must be a single quoted token; a multi-word expression
such as `-k 'a or b'` is split by PowerShell before it reaches pytest and
collects nothing.

`test_lastupdate_is_mfg_date_before_any_update` sits in the first class of
`test_swu.py`, so it runs before `test_push_based_firmware_update`; its
`pytest.skip()` guard only applies to partial `-k` runs where an update
precedes it.

<a id="known-bugs"></a>
## Known Bugs

Open findings are in [`FINDINGS.md`](FINDINGS.md).
