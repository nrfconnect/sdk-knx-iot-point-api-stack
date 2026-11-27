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
    """oc_ri_get_query_nth_key_value() / oc_ri_get_query_value(): raw Uri-Query,
    every value also through the oc_knx_helpers number parsers."""
    return {
        "ga_po_ps.bin": b"ga=1&po=0&ps=64",
        "pkgs_only.bin": b"pkgs=1024",
        "if_pm.bin": b"if=urn:knx.if.pm",
        "empty.bin": b"",
        "bare_equals.bin": b"=",
        "many_amps.bin": b"&&&a=&=b&&",
        "no_value.bin": b"ga",
        "trailing_amp.bin": b"ga=1&",
        "po_negative.bin": b"po=-1&ps=0",
        "pkgs_overflow.bin": b"pkgs=2147483648",
        "pkgs_max.bin": b"pkgs=2147483647",
        "hex_value.bin": b"ep=0xffff",
        "leading_zeros.bin": b"lt=00001",
        "bare_number.bin": b"2147483647",
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


# ── Full-stack harnesses (fuzz_stack.h) ───────────────────────────────────────

# uncompressed P-256 generator, a valid shareP point
P256_G = bytes.fromhex(
    "04"
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")


def cbor_bstr(b):
    """CBOR byte string header for lengths < 256."""
    if len(b) < 24:
        return bytes([0x40 + len(b)]) + b
    return bytes([0x58, len(b)]) + b


def rec16(*parts):
    """[len_hi][len_lo][data] records."""
    return b"".join(struct.pack(">H", len(p)) + p for p in parts)


def oprec(op, data):
    """[op][len_hi][len_lo][data] record."""
    return bytes([op]) + struct.pack(">H", len(data)) + data


def corpus_spake_post():
    """POST /.well-known/knx/spake: step 1 (id + rnd), 2 (shareP), 3 (confirmP)."""
    step1 = b"\xa2\x00\x61a\x0f" + cbor_bstr(bytes(range(32)))
    step2 = b"\xa1\x0a" + cbor_bstr(P256_G)
    step3 = b"\xa1\x0e" + cbor_bstr(bytes(32))
    return {
        "step1.bin": rec16(step1),
        "step1_2.bin": rec16(step1, step2),
        "step1_2_3.bin": rec16(step1, step2, step3),
        "step2_first.bin": rec16(step2),
        "step3_first.bin": rec16(step3),
        "empty_map.bin": rec16(b"\xa0"),
    }


def corpus_coap_inbound():
    """Inbound datagram sequences: [sel][len_hi][len_lo][datagram]."""
    def rec(sel, dgram):
        return bytes([sel]) + struct.pack(">H", len(dgram)) + dgram

    wk = coap_option(11, b".well-known")
    spake = wk + coap_option(0, b"knx") + coap_option(0, b"spake") + coap_option(1, bytes([60]))
    core = coap(CON, 1, 0x0101, b"\x01", wk + coap_option(0, b"core"))
    return {
        "get_core.bin": rec(0x00, core),
        "get_core_twice.bin": rec(0x00, core) + rec(0x00, core),
        "get_knx.bin": rec(0x10, coap(CON, 1, 0x0102, b"\x02", wk + coap_option(0, b"knx"))),
        "discovery_mc.bin": rec(0x01, coap(NON, 1, 0x0103, b"\x03", wk + coap_option(0, b"core")
                                           + coap_option(4, b"ep=knx://sn.*"))),
        "discovery_sn_prefix.bin": rec(0x01, coap(NON, 1, 0x0108, b"\x07", wk + coap_option(0, b"core")
                                                  + coap_option(4, b"ep=knx://sn.00fa*"))),
        "discovery_sn_short.bin": rec(0x01, coap(NON, 1, 0x0109, b"\x08", wk + coap_option(0, b"core")
                                                 + coap_option(4, b"ep=knx://sn"))),
        "ia_post.bin": rec(0x00, coap(CON, 2, 0x0104, b"\x04", wk + coap_option(0, b"knx")
                                      + coap_option(0, b"ia") + coap_option(1, bytes([60])),
                                      b"\xa3\x0c\x01\x18\x1a\x01\x18\x19\x01")),
        # Block1 (option 27) num 0 more, then num 1 last, 16-byte blocks
        "blockwise.bin": (rec(0x20, coap(CON, 2, 0x0105, b"\x05", spake + coap_option(15, b"\x08"),
                                         b"\xa2\x00\x61a" + bytes(12)))
                          + rec(0x20, coap(CON, 2, 0x0106, b"\x05", spake + coap_option(15, b"\x10"),
                                           b"\x0f\x50" + bytes(16)))),
        "oscore.bin": rec(0x00, coap(CON, 2, 0x0107, b"\x06", coap_option(9, oscore_option_value()),
                                     bytes(range(1, 17)))),
        "ack_rst.bin": rec(0x00, coap(ACK, 0, 0x0101)) + rec(0x00, coap(RST, 0, 0x0102)),
    }


def corpus_knx_k_post():
    """POST /k: [sel][{4:sia, 5:{6:st, 7:ga, 1:value}}]."""
    def smode(st, ga, value=None):
        inner = b"\x06\x61" + st + b"\x07" + bytes([ga])
        if value is not None:
            inner += b"\x01" + value
        return b"\xa2\x04\x19\x12\x34\x05" + bytes([0xa2 if value is None else 0xa3]) + inner

    return {
        "write_ga1_true.bin": b"\x00" + smode(b"w", 1, b"\xf5"),
        "write_ga3_int.bin": b"\x00" + smode(b"w", 3, b"\x18\x2a"),
        "write_ga3_str.bin": b"\x01" + smode(b"w", 3, b"\x63abc"),
        "answer_ga3_double.bin": b"\x00" + smode(b"a", 3, b"\xfb\x40\x09\x21\xfb\x54\x44\x2d\x18"),
        "read_ga2.bin": b"\x01" + smode(b"r", 2),
        "read_ga3.bin": b"\x00" + smode(b"r", 3),
        "write_ga4_unknown.bin": b"\x00" + smode(b"w", 4, b"\xf4"),
        "sync_sia_only.bin": b"\x00\xa1\x04\x19\x12\x34",
    }


def corpus_fp_table_post():
    """fp/g, fp/r, fp/p create/read/delete sequences: [op][len_hi][len_lo][data]."""
    got = (b"\x82"
           b"\xa4\x00\x01\x0b\x64/p/1\x07\x82\x01\x02\x08\x18\x90"
           b"\xa4\x00\x02\x0b\x64/p/2\x07\x81\x03\x08\x18\x48")
    got_update = b"\x81\xa4\x00\x01\x0b\x64/p/3\x07\x83\x05\x06\x07\x08\x18\x18"
    got_nil_ga = b"\x81\xa4\x00\x01\x0b\x64/p/1\x07\xf6\x08\x18\x10"
    id_only = b"\x81\xa1\x00\x01"
    rcp_mc = b"\x81\xa3\x00\x01\x07\x82\x01\x02\x0d\x05"
    rcp_uc = b"\x81\xa5\x00\x02\x07\x81\x03\x0c\x19\x01\x01\x0e\x63tok\x18\x1a\x01"
    pub = b"\x81\xa3\x00\x01\x07\xf6\x0d\x05"
    return {
        "got_create.bin": oprec(0, got),
        "got_create_update.bin": oprec(0, got) + oprec(0, got_update),
        "got_create_list_get_delete.bin": (oprec(0, got) + oprec(3, b"") + oprec(6, b"1")
                                           + oprec(9, b"1") + oprec(3, b"")),
        "got_nil_ga.bin": oprec(0, got) + oprec(0, got_nil_ga),
        "got_id_only_delete.bin": oprec(0, got) + oprec(0, id_only),
        "rcp_mc_uc.bin": oprec(1, rcp_mc) + oprec(1, rcp_uc) + oprec(4, b"") + oprec(7, b"2"),
        "rcp_update_delete.bin": oprec(1, rcp_uc) + oprec(1, rcp_mc) + oprec(10, b"2"),
        "pub_create_get.bin": oprec(2, pub) + oprec(5, b"") + oprec(8, b"1") + oprec(11, b"1"),
        # regressions: a repeated key stood in for a missing mandatory one
        "got_no_href.bin": oprec(0, b"\x81\xa4\x00\x01\x07\x81\x01\x08\x14\x08\x14") + oprec(3, b""),
        "rcp_ga_twice_no_grpid.bin": oprec(1, b"\x81\xa3\x00\x01\x07\x81\x01\x07\x81\x02") + oprec(4, b""),
        "rcp_grpid_twice.bin": oprec(1, b"\x81\xa4\x00\x01\x07\x81\x01\x0d\x05\x0d\x06") + oprec(7, b"1"),
    }


def auth_at_entry(tok, scope=b"\x81\x66if.sec", kid=b"\x01"):
    """POST /auth/at body: [{0:tok, 9:scope, 38:2, 8:{4:{0:kid, 2:ms}}}]."""
    return (bytes([0x81, 0xa4, 0x00, 0x60 + len(tok)]) + tok
            + b"\x09" + scope + b"\x18\x26\x02"
            + b"\x08\xa1\x04\xa2\x00" + cbor_bstr(kid)
            + b"\x02" + cbor_bstr(bytes(range(1, 17))))


def corpus_auth_handlers():
    """auth/at + auth/o sequences: [op][len_hi][len_lo][data]."""
    a = auth_at_entry(b"tok1")
    b_ga = auth_at_entry(b"tok2", scope=b"\x82\x01\x02", kid=b"\x02")
    return {
        "post_empty_map.bin": oprec(0, b"\xa0"),
        "post_id_only.bin": oprec(0, b"\x81\xa1\x00\x62" + b"01"),
        "post_mixed_array_scope.bin": oprec(0, b"\x81\xa2\x00\x62" + b"01" + b"\x09\x9f\x01\xff"),
        "post_short_secret.bin": oprec(0, a[:-17] + cbor_bstr(bytes(range(1, 16)))),
        "post_long_kid.bin": oprec(0, auth_at_entry(b"tok3", kid=bytes(range(8)))),
        "get_x_slash.bin": oprec(0, a) + oprec(3, b"abc/def"),
        "get_x_long.bin": oprec(3, b"a" * 64) + oprec(4, b""),
        "post_get_list.bin": oprec(0, a) + oprec(1, b""),
        "post_get_x.bin": oprec(0, a) + oprec(3, b"tok1"),
        "post_delete_x.bin": oprec(0, a) + oprec(0, b_ga) + oprec(4, b"tok1") + oprec(1, b""),
        "post_twice_delete_all.bin": oprec(0, a) + oprec(0, a) + oprec(2, b"") + oprec(3, b"tok1"),
        "osndelay.bin": oprec(5, b"\xa1\x01\x19\x03\xe8") + oprec(6, b"") + oprec(7, b"") + oprec(8, b""),
        "osndelay_bad.bin": oprec(5, b"\xa1\x01\x3a\x7f\xff\xff\xff"),
    }


def corpus_dev_put():
    """Device writes: [op][len_hi][len_lo][data]; op % 6 selects, op bit 3 = runtime."""
    ia = b"\xa3\x0c\x01\x18\x1a\x01\x18\x19\x01"
    return {
        "pm_true.bin": oprec(0, b"\xa1\x01\xf5") + oprec(5, b""),
        "pv.bin": oprec(1, b"\x83\x01\x02\x03") + oprec(5, b""),
        "pv_out_of_range.bin": oprec(1, b"\x83\x1a\x00\x01\x00\x00\x02\x03"),
        "restart.bin": oprec(2, b"\xa1\x02\x67restart"),
        "reset_2.bin": oprec(3, ia) + oprec(2, b"\xa2\x02\x65reset\x01\x02") + oprec(5, b""),
        "reset_7_runtime.bin": oprec(0x09, ia) + oprec(0x0E, b"\xa2\x02\x65reset\x01\x07") + oprec(5, b""),
        "ia_runtime.bin": oprec(0x09, b"\xa3\x0c\x19\x01\x02\x18\x1a\x1b" + bytes([0, 0, 0, 1, 0, 0, 0, 0])
                                + b"\x18\x19\x02"),
        "iid.bin": oprec(0x04, b"\xa1\x01\x05") + oprec(5, b""),
        "hname.bin": oprec(0x10, b"\xa1\x01\x64host") + oprec(5, b""),
    }


def corpus_observe_register():
    """Observe sequences: [op][ep][len][data]; ep bit 1 = unsecured /p/o or <ga> /k, bit 2 = other port,
    bit 3 = other kid, bit 7 = /k instead of /p/o; op bit 3 = fail an allocation."""
    def rec(op, ep, data=b""):
        return bytes([op, ep, len(data)]) + data

    def obs(token, observe, query=b"lt=86400", mid=0x1000):
        opts = coap_option(6, bytes([observe]) if observe else b"")
        opts += coap_option(5, b"p") + coap_option(0, b"o")
        if query:
            opts += coap_option(4, query)
        return coap(CON, 1, mid, token, opts)

    reg = obs(b"\x11\x22", 0)
    # /k from peer 0 plus /p/o from peers 0..6 fills COAP_MAX_OBSERVERS (8)
    full = rec(0, 0x80, obs(b"\x80", 0, b"lt=60")) + b"".join(
        rec(0, peer << 4, obs(bytes([0x40 + peer]), 0)) for peer in range(7))
    return {
        "limit_takeover.bin": full + rec(0, 0x84, obs(b"\x84", 0, b"lt=60")) + rec(5, 0x80, b"\xa1\x01\xf5"),
        "limit_reject.bin": full + rec(0, 0x8C, obs(b"\x8c", 0, b"lt=60")) + rec(0, 0x70, obs(b"\x70", 0)) + rec(4, 0),
        "register_notify.bin": rec(0, 0, reg) + rec(4, 0),
        "register_refresh.bin": rec(0, 0, reg) + rec(0x10, 0, obs(b"\x99", 0)) + rec(4, 0),
        "register_deregister.bin": rec(0, 0, reg) + rec(0, 0, obs(b"\x11\x22", 1)),
        "register_no_lt.bin": rec(0, 0, reg) + rec(0, 0, obs(b"\x44", 0, b"")),
        "register_big_lt.bin": rec(0, 0, obs(b"\x55", 0, b"lt=99999999999")),
        "register_non.bin": rec(0, 0x10, obs(b"\x66", 0, b"lt=60")) + rec(0, 0x10, obs(b"\x67", 0, b"lt=60&non=true")),
        "k_observers.bin": rec(0, 0x80, obs(b"\x33", 0, b"lt=60")) + rec(5, 0x80, b"\xa1\x01\xf5"),
        "remove_paths.bin": (rec(0, 0, reg) + rec(0, 0x10, obs(b"\x33", 0, b"lt=60"))
                             + rec(2, 0, b"\x11\x22") + rec(3, 0x10, b"\x10\x00")
                             + rec(1, 0)),
        "unsecured_rejected.bin": rec(0, 0x02, reg) + rec(4, 0x02),
        "blockwise_notify.bin": rec(0, 0, reg) + rec(4, 0, b"\x02\x00") + rec(4, 0, b"\x02\xbc"),
        "lifetime_expiry.bin": rec(0, 0, obs(b"\x77", 0, b"lt=1")) + rec(6, 0, struct.pack("<I", 2000)) + rec(4, 0),
        "con_timeout.bin": rec(0, 0, reg) + rec(4, 0) + b"".join(rec(6, 0, struct.pack("<I", 60000)) for _ in range(6)),
        "rst_last_mid.bin": rec(0, 0, reg) + rec(4, 0) + rec(7, 0) + rec(4, 0),
        "ack_last_mid.bin": rec(0, 0x80, obs(b"\x33", 0, b"lt=60")) + rec(5, 0x80, b"\xa1\x01\xf5") + rec(0x17, 0x80),
        "malloc_fail_notify.bin": rec(0, 0, reg) + rec(0x0C, 0, b"\x01\x00") + rec(0x1C, 0x80, b"\xa1\x01\xf5"),
        "malloc_fail_register.bin": rec(0x08, 0, reg) + rec(0x18, 0, reg) + rec(4, 0),
    }


def corpus_publisher():
    """oc_knx_publisher_check(): [type][cov][hbt][mrt][now] then [dt][value] steps."""
    def header(t, cov, hbt, mrt, now):
        return bytes([t]) + cov + struct.pack("<HHI", hbt, mrt, now)

    def step(dt, value):
        return struct.pack("<I", dt) + value

    def i(v):
        return struct.pack("<i", v)

    def f(v):
        return struct.pack("<f", v)

    nan = b"\x00\x00\xc0\x7f"
    return {
        "bool_toggle.bin": header(0, i(0), 60, 5, 0) + step(1, i(0)) + step(3, i(1)) + step(3, i(1)) + step(61, i(1)),
        "int_cov.bin": header(1, i(10), 0, 0, 100) + step(1, i(0)) + step(1, i(5)) + step(1, i(11)) + step(1, i(-100)),
        "float_nan.bin": header(2, f(0.5), 30, 2, 0) + step(1, f(1.0)) + step(3, nan) + step(3, nan) + step(3, f(1.0)),
        "wrap.bin": header(1, i(0), 10, 1, 0xFFFFFFF0) + step(1, i(1)) + step(0x20, i(1)) + step(0x20, i(2)),
        "invalid_type.bin": header(3, i(0), 1, 1, 0) + step(5, i(1)),
    }


def corpus_storage_load():
    """Persisted table entries, then requests: op < 0x80 store (op % 4 table, op >> 2 index), else op % 7 request."""
    got = b"\xa4\x00\x01\x0b\x64/p/1\x07\x82\x01\x02\x08\x18\x90"
    got_nil_ga = b"\xa4\x00\x02\x0b\x64/p/2\x07\xf6\x08\x18\x48"
    grt = b"\xa6\x00\x01\x0c\x19\x01\x01\x07\x82\x02\x03\x0d\x05\x0e\x63tok\x63non\xf5"
    gpt = b"\xa3\x00\x01\x07\x82\x01\x03\x0d\x05"

    def at(tok, kid=b"\x01", ms=bytes(range(1, 17)), ctx=b""):
        return (b"\xa6\x00" + bytes([0x60 + len(tok)]) + tok + b"\x09\x19\x01\x00\x18\x26\x02"
                + b"\x19\x03\x48" + cbor_bstr(kid) + b"\x19\x03\x4a" + cbor_bstr(ms)
                + b"\x19\x03\x4e" + cbor_bstr(ctx))

    k_write = b"\xa2\x04\x19\x12\x34\x05\xa3\x06\x61w\x07\x01\x01\xf5"
    k_read = b"\xa2\x04\x19\x12\x34\x05\xa2\x06\x61r\x07\x01"
    lists = oprec(0x81, b"") + oprec(0x82, b"") + oprec(0x83, b"") + oprec(0x84, b"")
    return {
        "got_k_write.bin": oprec(0, got) + oprec(0x80, k_write) + oprec(0x80, k_read),
        "got_two_entries.bin": oprec(0, got) + oprec(4, got_nil_ga) + oprec(0x81, b"") + oprec(0x85, b"1"),
        "all_tables.bin": oprec(0, got) + oprec(1, grt) + oprec(2, gpt) + oprec(3, at(b"tok1")) + lists,
        "at_two_entries.bin": (oprec(3, at(b"tok1")) + oprec(7, at(b"tok2", b"\x02", ctx=b"\xfa\xce"))
                               + oprec(0x84, b"") + oprec(0x86, b"tok2")),
        "at_long_kid.bin": oprec(3, at(b"tok1", bytes(range(32)))) + oprec(0x84, b""),
        "at_short_secret.bin": oprec(3, at(b"tok1", ms=b"\x01")) + oprec(0x84, b""),
        "at_same_kid.bin": oprec(3, at(b"tok1")) + oprec(7, at(b"tok2")) + oprec(0x84, b""),
        "got_int_as_href.bin": oprec(0, b"\xa3\x00\x01\x0b\x01\x07\x81\x01") + oprec(0x80, k_write),
        "truncated_cbor.bin": oprec(0, got[:9]) + oprec(1, grt[:5]) + oprec(3, b"\xa6\x00") + lists,
    }


def lsm_event(event):
    """POST /a/lsm body {2: event}."""
    return b"\xa1\x02" + bytes([event])


def corpus_knx_lsm_post():
    """/a/lsm sequences with table and token loads: [op][len_hi][len_lo][data], op % 6:
    0 POST /a/lsm, 1 GET /a/lsm, 2 POST /fp/g, 3 POST /fp/r, 4 POST /auth/at, 5 runtime."""
    start, complete, unload = lsm_event(1), lsm_event(2), lsm_event(4)
    got = (b"\x82"
           b"\xa4\x00\x01\x0b\x64/p/1\x07\x82\x01\x02\x08\x18\x90"
           b"\xa4\x00\x02\x0b\x64/p/2\x07\x81\x03\x08\x18\x48")
    rcp = b"\x81\xa3\x00\x01\x07\x82\x01\x02\x0d\x05"
    load = oprec(0, start) + oprec(2, got) + oprec(3, rcp) + oprec(0, complete)
    return {
        "start_get.bin": oprec(0, start) + oprec(1, b""),
        "load_offline.bin": load + oprec(1, b""),
        "load_runtime.bin": oprec(5, b"") + load + oprec(1, b""),
        "load_runtime_unload.bin": oprec(5, b"") + load + oprec(0, unload) + oprec(1, b""),
        "reload_runtime.bin": oprec(5, b"") + load + oprec(0, start) + oprec(2, got) + oprec(0, complete),
        "complete_from_unloaded.bin": oprec(0, complete) + oprec(1, b""),
        "nop_from_unloaded.bin": oprec(0, lsm_event(0)),
        "event_3.bin": oprec(0, start) + oprec(0, lsm_event(3)),
        "event_out_of_range.bin": oprec(0, b"\xa1\x02\x39\x27\x0f"),
        "empty_map.bin": oprec(0, b"\xa0"),
        "token_unload.bin": oprec(4, auth_at_entry(b"tok1")) + oprec(0, start) + oprec(0, unload),
        # regression: id, ga and cflags twice made four items without href, the href check got NULL
        "got_no_href.bin": (oprec(5, b"") + oprec(0, start)
                            + oprec(2, b"\x81\xa4\x00\x01\x07\x81\x01\x08\x14\x08\x14")),
    }


def swu_package(query, payload):
    """/a/swu record data: [qlen][query][package bytes]."""
    return bytes([len(query)]) + query + payload


def swu_app(state, result=0, received=0, version=(0, 0, 0), name=b""):
    """Application record data: [state][result][bytes:4][major][minor][patch][name]."""
    return bytes([state, result]) + struct.pack(">I", received) + bytes(version) + name


def corpus_swu_handlers():
    """/swu sequences: [op][len_hi][len_lo][data], op % 8: 0 PUT /a/swu, 1 PUT protocol,
    2 PUT method, 3 PUT update, 4 GET all, 5 GET /swu, 6 application state, 7 last update."""
    first = oprec(0, swu_package(b"po=0&ps=4&pkgs=8", b"ABCD"))
    second = oprec(0, swu_package(b"po=4&ps=4", b"EFGH"))
    downloaded = oprec(6, swu_app(2, received=8, version=(1, 2, 3), name=b"pkg.bin"))
    gets = oprec(4, b"")
    return {
        "download.bin": first + second + gets,
        "repeat_block.bin": first + first + second + gets,
        "overlap.bin": first + oprec(0, swu_package(b"po=2&ps=4", b"CDEF")) + gets,
        "gap.bin": first + oprec(0, swu_package(b"po=8&ps=4", b"IJKL")) + gets,
        "restart.bin": first + oprec(0, swu_package(b"po=0&pkgs=4", b"WXYZ")) + gets,
        "not_from_offset0.bin": oprec(0, swu_package(b"po=4&pkgs=8", b"EFGH")) + gets,
        "no_payload.bin": oprec(0, swu_package(b"po=0&pkgs=8", b"")),
        "bad_queries.bin": (oprec(0, swu_package(b"po=-1", b"A")) + oprec(0, swu_package(b"ps=0", b"A"))
                            + oprec(0, swu_package(b"pkgs=x", b"A")) + oprec(0, swu_package(b"po=2147483648", b"A"))),
        "update.bin": first + second + downloaded + gets + oprec(3, b"\x0a") + gets,
        "update_negative_defer.bin": downloaded + oprec(3, b"\x20") + gets,
        "update_not_downloaded.bin": oprec(3, b"\x0a"),
        "protocol_method.bin": (oprec(1, b"\x00") + oprec(1, b"\x01") + oprec(2, b"\x00")
                                + oprec(2, b"\x01") + oprec(1, b"\xa0")),
        "updating_then_upload.bin": oprec(6, swu_app(3)) + first + gets,
        "list.bin": oprec(5, b"") + oprec(5, b"l=total") + oprec(5, b"pn=1&ps=2") + oprec(5, b"ps=0"),
        "last_update.bin": oprec(7, b"2026-01-01T00:00:00Z") + gets + oprec(7, b"osv:true") + gets,
    }


def oscore_plain(code, path, options=b"", payload=b""):
    """OSCORE plaintext (RFC 8613 5.3): inner code, Uri-Path options, more options, payload."""
    segments = [s.encode() for s in path.strip("/").split("/")]
    opts = coap_option(11, segments[0]) + b"".join(coap_option(0, s) for s in segments[1:])
    msg = bytes([code]) + opts + options
    if payload:
        msg += b"\xff" + payload
    return msg


def corpus_oscore_inbound():
    """Decrypted OSCORE requests: [flags] then [sel][len_hi][len_lo][plaintext],
    the flag and sel bits as in fuzz_oscore_inbound.c."""
    FLAGS_NONE, FLAG_RUNTIME, FLAG_NO_ECHO_SYNC = 0x00, 0x01, 0x02
    SEL_NONE, SEL_MULTICAST, SEL_NON, SEL_FETCH = 0x00, 0x01, 0x02, 0x04
    SEL_KID_CTX_8, SEL_KID_CTX_10 = 1 << 3, 2 << 3
    SEL_SAME_SSN, SEL_UNKNOWN_KID, SEL_BAD_TAG = 0x20, 0x40, 0x80
    GET, POST, PUT, DELETE = 1, 2, 3, 4
    URI_PATH, CONTENT_FORMAT, ECHO, CBOR = 11, 12, 252, 60

    def rec(sel, plain):
        return bytes([sel]) + struct.pack(">H", len(plain)) + plain

    def flags(f):
        return bytes([f])

    cf_cbor = coap_option(CONTENT_FORMAT - URI_PATH, bytes([CBOR]))
    def echo(value):
        return coap_option(ECHO - URI_PATH, value)

    get_sn = oscore_plain(GET, "/dev/sn")
    put_pm = oscore_plain(PUT, "/dev/pm", cf_cbor, b"\xa1\x01\xf5")
    lsm_start = oscore_plain(POST, "/a/lsm", cf_cbor, b"\xa1\x02\x01")
    k_write = oscore_plain(POST, "/k", cf_cbor, b"\xa2\x04\x19\x12\x34\x05\xa3\x06\x61w\x07\x01\x01\xf5")
    none = flags(FLAGS_NONE)
    return {
        "get_dev_sn.bin": none + rec(SEL_NONE, get_sn),
        "put_pm_get.bin": none + rec(SEL_NONE, put_pm) + rec(SEL_NONE, oscore_plain(GET, "/dev/pm")),
        "lsm_start.bin": none + rec(SEL_NONE, lsm_start) + rec(SEL_NONE, oscore_plain(GET, "/a/lsm")),
        "get_auth_at.bin": none + rec(SEL_NONE, oscore_plain(GET, "/auth/at")),
        "delete_token_then_get.bin": (none + rec(SEL_NONE, oscore_plain(DELETE, "/auth/at"))
                                      + rec(SEL_NONE, get_sn)),
        "get_core.bin": none + rec(SEL_NONE, oscore_plain(GET, "/.well-known/core")),
        "get_swu_list.bin": none + rec(SEL_NONE, oscore_plain(GET, "/swu")),
        "replay.bin": none + rec(SEL_NONE, get_sn) + rec(SEL_SAME_SSN, get_sn),
        "kid_ctx_8.bin": none + rec(SEL_KID_CTX_8, get_sn) + rec(SEL_KID_CTX_8, put_pm),
        "kid_ctx_10.bin": none + rec(SEL_KID_CTX_10, get_sn),
        "fetch_non.bin": none + rec(SEL_FETCH | SEL_NON, get_sn),
        "k_multicast_runtime.bin": (flags(FLAG_RUNTIME) + rec(SEL_MULTICAST | SEL_NON, k_write)
                                    + rec(SEL_MULTICAST, k_write)),
        "unknown_kid.bin": none + rec(SEL_UNKNOWN_KID, get_sn) + rec(SEL_UNKNOWN_KID | SEL_MULTICAST, get_sn),
        "bad_tag.bin": none + rec(SEL_BAD_TAG, get_sn),
        "empty_plaintext.bin": none + rec(SEL_NONE, b""),
        "code_only.bin": none + rec(SEL_NONE, bytes([GET])),
        "unsynchronised.bin": flags(FLAG_NO_ECHO_SYNC) + rec(SEL_NONE, get_sn) + rec(SEL_MULTICAST, get_sn),
        "stale_echo.bin": flags(FLAG_NO_ECHO_SYNC) + rec(SEL_NONE, oscore_plain(GET, "/dev/sn", echo(bytes(8)))),
        "bad_echo_size.bin": flags(FLAG_NO_ECHO_SYNC) + rec(SEL_NONE, oscore_plain(GET, "/dev/sn", echo(b"\x01\x02"))),
    }

CORPORA = {
    "storage_load": corpus_storage_load,
    "spake_post": corpus_spake_post,
    "coap_inbound": corpus_coap_inbound,
    "knx_k_post": corpus_knx_k_post,
    "fp_table_post": corpus_fp_table_post,
    "auth_handlers": corpus_auth_handlers,
    "dev_put": corpus_dev_put,
    "observe_register": corpus_observe_register,
    "publisher": corpus_publisher,
    "coap_parse": corpus_coap_parse,
    "oscore_options": corpus_oscore_options,
    "oc_rep": corpus_oc_rep,
    "mdns": corpus_mdns,
    "query_string": corpus_query_string,
    "blockwise_reassembly": corpus_blockwise_reassembly,
    "oscore_context_lookup": corpus_oscore_context_lookup,
    "spake2plus_wire": corpus_spake2plus_wire,
    "replay_window": corpus_replay_window,
    "oscore_aad_nonce": corpus_oscore_aad_nonce,
    "oscore_echo_tx": corpus_oscore_echo_tx,
    "core_res_wildcard": corpus_core_res_wildcard,
    "knx_lsm_post": corpus_knx_lsm_post,
    "swu_handlers": corpus_swu_handlers,
    "oscore_inbound": corpus_oscore_inbound,
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
