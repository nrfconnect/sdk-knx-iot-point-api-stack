#!/usr/bin/env python3
"""Generate the libFuzzer seed corpora into the build tree.

Committing ~30 opaque .bin blobs makes the seeds unreviewable and unmaintainable.
Everything here is expressed as structure instead, so a reviewer can see what a
seed represents and a new seed is a few readable lines.

Deterministic by construction (no randomness): the same revision always produces
byte-identical seeds, so a fuzz finding stays reproducible.

Usage: make_corpus.py <output-dir>
"""

import pathlib
import struct
import sys

# ── CoAP (RFC 7252) ───────────────────────────────────────────────────────────

CON, NON, ACK, RST = 0, 1, 2, 3


def coap_option(delta, value):
    """Encode one option with the nibble + extension-byte scheme of RFC 7252 3.1."""

    def nibble(n):
        if n < 13:
            return n, b""
        if n < 269:
            return 13, bytes([n - 13])
        return 14, struct.pack(">H", n - 269)

    dn, dx = nibble(delta)
    ln, lx = nibble(len(value))
    return bytes([(dn << 4) | ln]) + dx + lx + value


def coap(msg_type, code, mid, token=b"", options=b"", payload=b""):
    header = (1 << 6) | (msg_type << 4) | len(token)
    msg = bytes([header, code]) + struct.pack(">H", mid) + token + options
    if payload:
        msg += b"\xff" + payload
    return msg


def oscore_option_value(piv=b"\x01", kid=b"\x00", kid_context=None):
    """RFC 8613 6.1: flag byte, then partial IV, kid context and kid."""
    flags = len(piv) & 0x07
    if kid is not None:
        flags |= 0x08
    if kid_context is not None:
        flags |= 0x10
    value = bytes([flags]) + piv
    if kid_context is not None:
        value += bytes([len(kid_context)]) + kid_context
    if kid is not None:
        value += kid
    return value


# ── mDNS (RFC 1035 wire format) ───────────────────────────────────────────────
KNX_SERVICE = "_knx._udp.local."
KNX_INSTANCE = "0000000000000001._knx._udp.local."
KNX_HOSTNAME = "knx-0000000000000001.local."


def dns_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_header(qd=0, an=0, ns=0, ar=0, flags=0, ident=0):
    return struct.pack(">HHHHHH", ident, flags, qd, an, ns, ar)


def dns_question(name, qtype, qclass=1):
    return dns_name(name) + struct.pack(">HH", qtype, qclass)


def dns_record(name, rtype, rclass, ttl, rdata):
    return name + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata)) + rdata


TYPE_PTR, TYPE_TXT, TYPE_AAAA, TYPE_SRV, TYPE_ANY = 12, 16, 28, 33, 255
CACHE_FLUSH_IN = 0x8001


# ── Corpora ───────────────────────────────────────────────────────────────────


def corpus_coap_parse():
    """coap_parse_udp_message(): every inbound non-OSCORE datagram."""
    return {
        "get_wellknown_core.bin": coap(
            CON, 1, 0x1234, b"\xaa\xbb",
            coap_option(11, b".well-known") + coap_option(0, b"core")),
        "get_wellknown_knx.bin": coap(
            CON, 1, 0x0001, b"\x01",
            coap_option(11, b".well-known") + coap_option(0, b"knx")
            + coap_option(6, bytes([60]))),
        "ack_2_05_cbor.bin": coap(
            ACK, 69, 0x1234, b"\xaa\xbb", coap_option(12, bytes([60])),
            b"\xa1\x01\x05"),
        "empty_ack.bin": coap(ACK, 0, 0x1234),
        "empty_rst.bin": coap(RST, 0, 0x1234),
        # Block1 + Size1: exercises the extended option-length encoding.
        "non_post_block1.bin": coap(
            NON, 2, 0x4242, b"\x11\x22\x33\x44",
            coap_option(11, b"p") + coap_option(0, b"1")
            + coap_option(1, bytes([0x06])) + coap_option(59, b"\x00\x40"),
            b"\xa1\x61\x73\xf5"),
        "observe_dev_sn.bin": coap(
            CON, 1, 0x7FFF, b"\x09",
            coap_option(6, b"") + coap_option(5, b"dev") + coap_option(0, b"sn")),
    }


def corpus_oscore_options():
    """coap_oscore_parse_options() in outer mode: the pre-auth OSCORE option."""
    return {
        "short_empty.bin": b"",
        "short_one_byte.bin": b"\x40",
        "short_two_bytes.bin": b"\x40\x02",
        "short_three_bytes.bin": b"\x40\x02\x10",
        "oscore_min.bin": coap(
            CON, 2, 0x1000, b"\xde\xad", coap_option(9, oscore_option_value()),
            bytes(range(1, 9))),
        "oscore_kidctx.bin": coap(
            CON, 2, 0x1001, b"",
            coap_option(9, oscore_option_value(
                piv=b"\x00\x01\x02", kid=b"\x11\x22",
                kid_context=b"\xfa" + bytes(7))),
            b"\xaa" * 24),
        # Uri-Host is a Class U option and must be accepted alongside OSCORE.
        "oscore_urihost.bin": coap(
            NON, 2, 0x1002, b"\x01\x02",
            coap_option(3, b"knx.local")
            + coap_option(6, oscore_option_value(piv=b"\x7f")),
            b"\xbb" * 16),
        # Zero-length OSCORE option value: the flag byte itself is missing.
        "oscore_empty_value.bin": coap(
            CON, 2, 0x1003, b"\x05", coap_option(9, b""), b"\xcc" * 8),
    }


def corpus_oc_rep():
    """oc_parse_rep(): CBOR to oc_rep_t tree construction and teardown."""
    seeds = {
        "map_int_int.bin": b"\xa1\x01\x05",
        "map_str_bool.bin": b"\xa1\x61\x73\xf5",
        # {"sia":1,"s":{"st":"w","ga":1,"value":true}} — the KNX s-mode shape.
        "smode.bin": (b"\xa2"
                      b"\x63sia\x01"
                      b"\x61s"
                      b"\xa3"
                      b"\x62st\x61w"
                      b"\x62ga\x01"
                      b"\x65value\xf5"),
        "array_of_maps.bin": b"\x82\xa1\x01\x02\xa1\x03\x04",
        "nested_map.bin": b"\xa1\x01\xa1\x02\xa1\x03\x18\x2a",
        "byte_string.bin": b"\xa1\x01\x45\x01\x02\x03\x04\x05",
        "text_and_float.bin": (b"\xa2\x61\x61\x63\x61\x62\x63"
                               b"\x61\x62\xfb\x40\x09\x21\xfb\x54\x44\x2d\x18"),
        "neg_and_null.bin": b"\xa2\x01\x38\x63\x02\xf6",
        "indefinite_array.bin": b"\x9f\x01\x02\x03\xff",
    }

    # Regression seeds for the defects the fuzzing campaigns found. Keep them
    # even though tests/unit/ also covers them: the fuzzer uses them as a
    # starting point for further mutation.
    seeds.update({
        # Array with reserved additional-info 29: cbor_parser_init() fails while
        # cbor_value_is_valid() still reports true -> read past in_payload_size.
        "reserved_addl_info.bin": b"\x9d",
        # Second key of the map is itself a map -> CborErrorIllegalType inside
        # the loop, leaving a partially built subtree behind.
        "malformed_map_key.bin": (b"\xa2\x64sia\x01\x61s\xa3"
                                  b"\x62st\x61w\x62ga\x01\x65value\xf5"),
        # Map announcing a value that the payload does not contain.
        "truncated_map.bin": b"\xa1\x61\x73\xb8",
        # Indefinite array of two float32 values: reaches oc_new_float_array(),
        # where FLOAT_POOL used to fall through into DOUBLE_POOL in
        # oc_mmem_alloc() and leak the float allocation (sec-hardening F-020).
        "float_array.bin": b"\x9f\xfa\xff\xff\xff\xff\xfa\xfa\xfa\xfa\xfa\xff",
        # Array of one text string longer than STRING_ARRAY_ITEM_MAX_LEN (32):
        # cbor_value_copy_text_string() overwrote its length out-parameter with
        # the untruncated string length on OutOfMemory, and that was used
        # unclamped as the NUL-terminator write index (sec-hardening F-021).
        "array_string_too_long.bin": b"\x81\x78\x64" + b"A" * 100,
    })
    return seeds


# ── New harnesses (round 2 of fuzz coverage recommendations) ─────────────────


def corpus_query_string():
    """oc_ri_get_query_nth_key_value() / oc_ri_get_query_value(): raw Uri-Query."""
    return {
        "ga_po_ps.bin": b"ga=1&po=0&ps=64",
        "pkgs_only.bin": b"pkgs=1024",
        "if_pm.bin": b"if=urn:knx.if.pm",
        "empty.bin": b"",
        "bare_equals.bin": b"=",
        "many_amps.bin": b"&&&a=&=b&&",
        "no_value.bin": b"ga",
        "trailing_amp.bin": b"ga=1&",
    }


def corpus_blockwise_reassembly():
    """oc_blockwise_handle_block(): attacker-chosen block offset + data."""

    def block(offset, payload):
        return struct.pack("<I", offset) + payload

    return {
        "first_block.bin": block(0, b"\x01\x02\x03\x04"),
        "second_block.bin": block(4, b"\x05\x06\x07\x08"),
        "large_offset.bin": block(0xFFFFFFF0, b"\xaa\xbb"),
        "zero_len.bin": block(0, b""),
        "offset_only.bin": struct.pack("<I", 16),
    }


def corpus_hex_and_base64():
    """oc_conv_hex_string_to_byte_array() + oc_base64_decode(), split input."""
    return {
        "hex_and_b64.bin": b"deadbeef" + b"QUJDRA==",
        "odd_hex.bin": b"abc" + b"====",
        "invalid_hex.bin": b"zz" + b"AA==",
        "empty_b64.bin": b"00",
        "long_hex.bin": b"0123456789abcdef" * 4,
        # sec-hardening F-022 regression: sscanf("%2x") scanned past the buffer length on a
        # non-NUL-terminated input, causing an out-of-bounds read.
        "hex_no_terminator_overread.bin": b"0126\x178"
        + b"1abcdefdef0142356789abcdef0173456789abcdef0123456781abcdef",
    }


def corpus_timestamp():
    """timestamp_parse(): hand-rolled ISO-8601-ish text parser."""
    return {
        "basic.bin": b"2024-01-01T00:00:00Z",
        "with_offset.bin": b"2024-06-15T12:30:45+02:00",
        "with_fraction.bin": b"2024-06-15T12:30:45.123456Z",
        "empty.bin": b"",
        "garbage.bin": b"not-a-timestamp",
        "truncated.bin": b"2024-01-01T",
        # sec-hardening F-023 regression: inverted bounds check (`cur + 5 < end` instead of
        # `cur + 5 > end`) let a truncated timezone offset read past the end
        # of the buffer.
        "truncated_offset_overread.bin": b"2024-06-15T12:30:45+0",
    }


def corpus_endpoint_string_parse():
    """oc_endpoint_string_parse_path(): the 'ep=knx://...' link-format value."""
    return {
        "sn_wildcard.bin": b"knx://sn.*",
        "sn_full.bin": b"knx://sn.000000000000/",
        "ia_path.bin": b"knx://ia.5.10/p/1",
        "empty.bin": b"",
        "no_scheme.bin": b"sn.000000000000",
    }


def corpus_swu_query_params():
    """oc_parse_sint32/uint16_from_base10/16_string(): po/ps/pkgs values."""
    return {
        "zero.bin": b"0",
        "max_int32.bin": b"2147483647",
        "negative.bin": b"-1",
        "overflow.bin": b"2147483648",
        "hex.bin": b"0xffff",
        "leading_zeros.bin": b"00001",
        "garbage.bin": b"abc",
        "empty.bin": b"",
    }


def corpus_group_object_table():
    """oc_core_find_next_go_table_index_with_ga(): GA search over the table."""

    def record(entry_id, gas):
        return (struct.pack("<i", entry_id) + bytes([len(gas)])
                + b"".join(struct.pack("<I", g) for g in gas))

    return {
        "single_match.bin": (struct.pack("<I", 7) + record(1, [7])),
        "no_match.bin": (struct.pack("<I", 99) + record(1, [1, 2, 3])),
        "multi_entry.bin": (struct.pack("<I", 5)
                            + record(1, [1, 2]) + record(2, [5, 6])),
        "empty_ga.bin": (struct.pack("<I", 1) + record(1, [])),
        "target_only.bin": struct.pack("<I", 42),
    }


def corpus_oscore_context_lookup():
    """oc_oscore_find_context_by_kid_and_kid_context(): kid/kid_context lookup.

    The harness seeds contexts with recipient IDs {0xAA,0x00}, {0xAA,0x01} and
    {0xBB,0x02} (the last with ID context {0xFA,0xCE})."""
    return {
        "match_no_context.bin": bytes([2, 0xAA, 0x00]),
        "match_with_context.bin": bytes([2, 0xBB, 0x02, 0xFA, 0xCE]),
        "no_match.bin": bytes([2, 0xCC, 0xCC]),
        "zero_len_kid.bin": bytes([0]),
        "max_len_kid.bin": bytes([16] + [0x41] * 16),
    }


def corpus_discovery_filter():
    """oc_discovery_sn_matches(): 'ep=knx://sn....' filter incl. wildcards."""
    return {
        "wildcard_all.bin": bytes([0]) + b"knx://sn.*",
        "full_match.bin": bytes([1]) + b"knx://sn.00fa12345678",
        "partial_wildcard.bin": bytes([1]) + b"knx://sn.00fa*",
        "too_short.bin": bytes([0]) + b"knx://sn",
        "no_wildcard_mismatch.bin": bytes([2]) + b"knx://sn.000000000000",
    }


def corpus_spake2plus_wire():
    """spake2plus_calc_transcript_responder(): attacker's shareP_enc point.

    Must be exactly kPubKeySize (65) bytes - the harness rejects any other
    length before parsing, so every seed keeps that size under mutation."""
    uncompressed_point_prefix = b"\x04"
    return {
        "well_formed_prefix.bin": uncompressed_point_prefix + bytes(64),
        "all_ff.bin": b"\xff" * 65,
        "all_zero.bin": b"\x00" * 65,
        "bad_prefix.bin": b"\x02" + bytes(64),
    }


def corpus_uuid_parse():
    """oc_str_to_uuid(): hand-rolled UUID string parser, no length param."""
    return {
        "well_formed.bin": b"1628fbcc-13ce-4e37-b883-1fd8d2ad945d",
        "wildcard_star.bin": b"*",
        # sec-hardening F-024 regression: shorter than 36 bytes, previously read past the
        # end of the buffer.
        "too_short.bin": b"short",
        "no_dashes.bin": b"1628fbcc13ce4e37b8831fd8d2ad945d",
        "empty.bin": b"",
        "one_byte.bin": b"a",
        # sec-hardening F-025 regression: high-bit byte (0xce) passed to isalpha() as a
        # signed char, and only 1 dash instead of 4 - overflowed uuid->id.
        "high_bit_and_too_few_dashes.bin": (
            b"q628fb13ce-4ed\xce\xc9" b"d2a2ad5d8d\xce\xc9" b"d2a2ad5d"),
    }


def corpus_oscore_full_decrypt():
    """oc_oscore_decrypt(): AEAD unwrap on attacker ciphertext/tag/AAD."""
    return {
        "min_tag8.bin": bytes([0, 0]) + bytes(8),
        "min_tag16.bin": bytes([0, 1]) + bytes(16),
        "with_aad.bin": bytes([4, 0]) + b"aad!" + bytes(8),
        "garbage_ciphertext.bin": bytes([0, 0]) + b"\xff" * 32,
    }


def corpus_replay_window():
    """oc_replay_check_client(): anti-replay sliding-window arithmetic."""
    return {
        "ssn_zero.bin": struct.pack("<Q", 0) + b"\x00",
        "ssn_one.bin": struct.pack("<Q", 1) + b"\x01",
        "ssn_max.bin": struct.pack("<Q", 0xFFFFFFFFFFFFFFFF) + b"\x01",
        "sequence.bin": (struct.pack("<Q", 1) + b"\x01"
                          + struct.pack("<Q", 2) + b"\x01"
                          + struct.pack("<Q", 1) + b"\x00"),
    }


def corpus_oscore_aad_nonce():
    """oc_oscore_compose_AAD() / oc_oscore_AEAD_nonce(): wire kid/piv."""
    return {
        "empty_id_piv.bin": bytes([0, 0]),
        "max_id.bin": bytes([7, 0]) + bytes(7),
        "max_piv.bin": bytes([0, 5]) + bytes(5),
        "both.bin": bytes([7, 5]) + bytes(12),
    }


def corpus_oscore_echo_tx():
    """Stateful OSCORE echo-ring anchor and responder operations."""
    def record(operation, ssn, kid_len, kid, kid_ctx_len, kid_ctx):
        return (bytes([operation]) + struct.pack("<Q", ssn)
                + bytes([kid_len]) + kid.ljust(7, b"\x00")[:7]
                + bytes([kid_ctx_len]) + kid_ctx.ljust(10, b"\x00")[:10])

    kid = b"\x01\x02\x03"
    context = b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9"
    return {
        "store_then_consume.bin": (record(0, 10, len(kid), kid, len(context), context)
                                    + record(1, 10, len(kid), kid, len(context), context)),
        "replay_same_responder.bin": (record(0, 10, len(kid), kid, len(context), context)
                                       + record(1, 10, len(kid), kid, len(context), context)
                                       + record(1, 10, len(kid), kid, len(context), context)),
        "mixed_lengths.bin": record(0, 0, 0, b"", 0, b"") + record(
            1, 0, 7, b"\xff" * 7, 10, b"\xff" * 10),
    }


def corpus_core_res_wildcard():
    """oc_check_resource_by_rt() / oc_check_resource_by_if(): rt=/if= query."""
    return {
        "rt_exact.bin": b"rt=urn:knx:dpa.201.61",
        "rt_wildcard.bin": b"rt=urn:knx:dpa.201.*",
        "if_wildcard.bin": b"if=urn:knx:if.s*",
        "no_match.bin": b"rt=urn:knx:dpa.999.1",
        "bare_wildcard.bin": b"rt=*",
        "empty_value.bin": b"rt=",
    }


def corpus_at_x_get_query():
    """oc_core_auth_at_x_get_handler(): /auth/at/{id} wildcard segment."""
    return {
        "simple_id.bin": b"abc123",
        "with_slash.bin": b"abc/def",
        "empty.bin": b"",
        "long_id.bin": b"a" * 64,
    }


def corpus_spake2plus_initiator():
    """spake2plus_calc_transcript_initiator(): attacker's shareV_enc point.

    Must be exactly kPubKeySize (65) bytes - the harness rejects any other
    length before parsing, so every seed keeps that size under mutation."""
    uncompressed_point_prefix = b"\x04"
    return {
        "well_formed_prefix.bin": uncompressed_point_prefix + bytes(64),
        "all_ff.bin": b"\xff" * 65,
        "all_zero.bin": b"\x00" * 65,
        "bad_prefix.bin": b"\x02" + bytes(64),
    }


def corpus_knx_lsm_post():
    """oc_core_a_lsm_post_handler(): POST /a/lsm event-dispatch CBOR body."""
    return {
        "event_startloading.bin": bytes([0xA1, 0x02, 0x01]),
        "event_loadcomplete.bin": bytes([0xA1, 0x02, 0x02]),
        "event_unload.bin": bytes([0xA1, 0x02, 0x04]),
        "event_out_of_range.bin": bytes([0xA1, 0x02, 0x39, 0x27, 0x0F]),
        "empty_map.bin": bytes([0xA0]),
    }


def corpus_auth_at_post():
    """oc_core_auth_at_post_handler(): POST /auth/at credential provisioning."""
    def complete_entry(secret, sender_id=b"\x01"):
        return bytes([0xA1, 0x00, 0xA4,
                      0x00, 0x63]) + b"tok" + bytes([0x09, 0x81, 0x66]) + b"if.sec" + bytes([
                          0x18, 0x26, 0x02,
                          0x08, 0xA1, 0x04, 0xA2,
                          0x00, 0x40 + len(sender_id)]) + sender_id + bytes([
                          0x02, 0x40 + len(secret)]) + secret

    return {
        "empty_map.bin": bytes([0xA0]),
        "id_only.bin": bytes([0xA1, 0x00, 0x62]) + b"01",
        "mixed_array_scope.bin": bytes([0xA1, 0x09, 0x9F, 0x01, 0xFF]),
        "nested_object.bin": (bytes([0xA1, 0x00, 0xA1, 0x00, 0x62]) + b"01"),
        "short_master_secret.bin": complete_entry(bytes(range(1, 16))),
        "zero_master_secret.bin": complete_entry(bytes(16)),
        "long_sender_id.bin": complete_entry(bytes(range(1, 17)), bytes(range(8))),
    }


def corpus_mdns():
    """mdns_socket_listen(): unauthenticated packets from anyone on the link."""
    ptr = dns_record(dns_name(KNX_SERVICE), TYPE_PTR, 1, 4500,
                     dns_name(KNX_INSTANCE))
    srv = dns_record(dns_name(KNX_INSTANCE), TYPE_SRV, CACHE_FLUSH_IN, 120,
                     struct.pack(">HHH", 0, 0, 5683) + dns_name(KNX_HOSTNAME))
    txt_rdata = b"".join(
        bytes([len(kv)]) + kv
        for kv in [b"sn=0000000000000001", b"ia=1", b"iid=5", b"pm=0"])
    # 0xc00c is a compression pointer back to the first name in the packet.
    txt = dns_record(b"\xc0\x0c", TYPE_TXT, CACHE_FLUSH_IN, 4500, txt_rdata)
    aaaa = dns_record(dns_name(KNX_HOSTNAME), TYPE_AAAA, CACHE_FLUSH_IN, 120,
                      b"\xfe\x80" + bytes(13) + b"\x01")

    return {
        "query_ptr_knx.bin": dns_header(qd=1) + dns_question(KNX_SERVICE, TYPE_PTR),
        # Unicast-response bit (0x8000) set in the question class.
        "query_any_instance.bin": (dns_header(qd=1)
                                   + dns_question(KNX_INSTANCE, TYPE_ANY, 0x8001)),
        "query_ptr_subtype.bin": (dns_header(qd=1)
                                  + dns_question("_pm._sub._knx._udp.local.",
                                                 TYPE_PTR)),
        "response_full.bin": (dns_header(an=1, ar=3, flags=0x8400)
                              + ptr + srv + txt + aaaa),
        # Compression pointer that refers to itself: loop-guard check.
        "response_ptr_loop.bin": (dns_header(an=1, flags=0x8400)
                                  + dns_record(b"\xc0\x0c", TYPE_PTR, 1, 120,
                                               b"\xc0\x0c")),
        # Shorter than the 12-byte header.
        "short_header.bin": b"\x00\x00\x84\x00\x00",
        # sec-hardening F-026 regression: a question name that consumes the datagram right
        # up to its declared length, leaving no room for the trailing
        # qtype/qclass fields - mdns_socket_listen() read 2-4 bytes past the
        # FUZZ_MDNS_BUF_SIZE (2048) receive buffer. 31 full 63-byte labels +
        # one 50-byte label + terminator = 2036 bytes, +12-byte header = 2048.
        "question_name_fills_datagram.bin": (
            dns_header(qd=1)
            + b"".join(bytes([63]) + b"a" * 63 for _ in range(31))
            + bytes([50]) + b"b" * 50
            + b"\x00"),
    }


CORPORA = {
    "coap_parse": corpus_coap_parse,
    "oscore_options": corpus_oscore_options,
    "oc_rep": corpus_oc_rep,
    "mdns": corpus_mdns,
    "query_string": corpus_query_string,
    "blockwise_reassembly": corpus_blockwise_reassembly,
    "hex_and_base64": corpus_hex_and_base64,
    "timestamp": corpus_timestamp,
    "endpoint_string_parse": corpus_endpoint_string_parse,
    "swu_query_params": corpus_swu_query_params,
    "group_object_table": corpus_group_object_table,
    "oscore_context_lookup": corpus_oscore_context_lookup,
    "discovery_filter": corpus_discovery_filter,
    "spake2plus_wire": corpus_spake2plus_wire,
    "uuid_parse": corpus_uuid_parse,
    "oscore_full_decrypt": corpus_oscore_full_decrypt,
    "replay_window": corpus_replay_window,
    "oscore_aad_nonce": corpus_oscore_aad_nonce,
    "oscore_echo_tx": corpus_oscore_echo_tx,
    "core_res_wildcard": corpus_core_res_wildcard,
    "at_x_get_query": corpus_at_x_get_query,
    "spake2plus_initiator": corpus_spake2plus_initiator,
    "knx_lsm_post": corpus_knx_lsm_post,
    "auth_at_post": corpus_auth_at_post,
}


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    root = pathlib.Path(sys.argv[1])
    total = 0
    for name, builder in CORPORA.items():
        directory = root / name
        directory.mkdir(parents=True, exist_ok=True)
        seeds = builder()
        # Drop seeds removed from this script so a stale build tree cannot keep
        # feeding inputs that no longer exist here.
        for stale in directory.glob("*.bin"):
            if stale.name not in seeds:
                stale.unlink()
        for filename, data in seeds.items():
            (directory / filename).write_bytes(data)
        total += len(seeds)
        print(f"{name}: {len(seeds)} seeds")

    print(f"{total} seeds written to {root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
