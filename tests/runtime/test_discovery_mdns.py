"""
Runtime conformance tests -- 5.1.2 Discovery via mDNS/DNS-SD

The plain subtype-presence checks for 5.1.2.1/.2/.3/.3a/.4 are covered by
the EITT template and now live in the conformance tier.  What remains here either
asserts materially more than the template (marked @pytest.mark.eitt_overlap)
or has no template case at all:

  5.1.2.1:  full SRV/AAAA/CoAP resolution chain for the unconfigured device
  5.1.2.2:  full chain for the configured device
  5.1.2.3:  full chain for the individual address
  5.1.2.3b: Discovery using individual address for unconfigured device
  5.1.2.4:  full chain, plus the negative "PM disabled" case
  5.1.2.5a: Unsolicited mDNS responses on Programming mode change
  5.1.2.5b: Unsolicited mDNS responses on Individual Address change

Non-EITT additions (sleep-period TXT, the goodbye/re-announce transition
audit and the state-sync checks) verify that what the DUT advertises stays
consistent with its internal state across PM, SP, restart, factory reset
and LSM unload.

Reference: 08_10_5 KNX IoT Point API Tests v01_01_01_AS

Requires: zeroconf (pip install zeroconf)
"""

import os
import socket
import struct
import time

import cbor2
import pytest

from transport.coap_client import APPLICATION_CBOR, LINK_FORMAT, CoapClient
from fixtures import DEVICE_PASSWORD, ALL_SCOPES, DUT_IA, DUT_IID, auth_prepare, ia_prepare, set_lsm
from transport.knx_oscore import OscoreContext
from transport.knx_spake2plus import Spake2PlusClient

try:
    from zeroconf import (
        IPVersion,
        ServiceBrowser,
        ServiceInfo,
        ServiceListener,
        Zeroconf,
    )

    HAS_ZEROCONF = True
except ImportError:
    HAS_ZEROCONF = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DUT_SERIAL = "00fa10020800"
KNX_SERVICE_TYPE = "_knx._udp.local."

# Timeouts (ms for zeroconf, seconds for CoAP)
MDNS_BROWSE_TIMEOUT_S = 2
# How long to wait after a CoAP state-change before querying mDNS.
# The stack re-announces within ~10 ms of the trigger and repeats that
# announcement one second later (RFC 6762 section 8.3).  1.5 s lets the repeat
# pass before the next step, even under ASan CI load.  The passive-capture
# approach no longer relies on this wait to catch announcements -- it is
# only used in cleanup/restore steps after a state change.
MDNS_ANNOUNCE_WAIT_S = 1.5
COAP_TIMEOUT = 5.0


# ---------------------------------------------------------------------------
# Helper: raw mDNS PTR query (bypasses zeroconf — mirrors EITT approach)
# ---------------------------------------------------------------------------

MDNS_MULTICAST_ADDR = "ff02::fb"
MDNS_PORT = 5353
DNS_TYPE_PTR = 12
DNS_TYPE_TXT = 16
DNS_CLASS_IN = 1


def _encode_dns_name(name: str) -> bytes:
    """Encode a dotted DNS name into wire-format labels."""
    parts = name.rstrip(".").split(".")
    result = b""
    for label in parts:
        encoded = label.encode("ascii")
        result += bytes([len(encoded)]) + encoded
    result += b"\x00"  # root label
    return result


def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS wire-format name, handling compression pointers."""
    labels = []
    seen_offsets = set()
    jumped = False
    return_offset = offset
    while True:
        if offset >= len(data):
            break
        if offset in seen_offsets:
            break  # loop protection
        seen_offsets.add(offset)
        length = data[offset]
        if length == 0:
            if not jumped:
                return_offset = offset + 1
            break
        if (length & 0xC0) == 0xC0:
            # compression pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                return_offset = offset + 2
            jumped = True
            offset = ptr
            continue
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
        if not jumped:
            return_offset = offset
    return ".".join(labels) + ".", return_offset


def _raw_mdns_ptr_query(iface_idx: int, qname: str,
                        timeout: float = 5.0) -> list[str]:
    """Send a raw mDNS PTR query and return PTR RDATA names from responses.

    Also captures unsolicited announcements that contain PTR records for the
    queried name in either the answer or additional sections.

    Returns a list of PTR RDATA domain names (e.g.
    ['00fa10020800._knx._udp.local.']).
    """
    # Build DNS query packet
    txn_id = 0  # mDNS always uses 0
    flags = 0   # standard query
    header = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)
    question = _encode_dns_name(qname) + struct.pack("!HH", DNS_TYPE_PTR, DNS_CLASS_IN)
    packet = header + question

    qname_norm = qname.lower().rstrip(".")

    # Create IPv6 UDP socket
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        # Bind to mDNS port to receive multicast responses
        sock.bind(("::", MDNS_PORT))
        # Join mDNS multicast group on the specific interface
        mreq = socket.inet_pton(socket.AF_INET6, MDNS_MULTICAST_ADDR)
        mreq += struct.pack("I", iface_idx)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        # Set outgoing multicast interface
        sock.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
            struct.pack("I", iface_idx),
        )
        sock.settimeout(timeout)

        # Send query to mDNS multicast group
        sock.sendto(packet, (MDNS_MULTICAST_ADDR, MDNS_PORT, 0, iface_idx))

        # Collect responses
        ptr_results = []
        pkt_count = 0
        deadline = time.monotonic() + timeout
        # Re-send the query periodically.  After heavy multicast traffic the
        # DUT may suppress a PTR in its response (RFC 6762 known-answer /
        # duplicate-response suppression); re-querying past the ~1s window
        # forces a fresh answer that includes the PTR record.
        next_resend = time.monotonic() + 1.2
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if time.monotonic() >= next_resend:
                try:
                    sock.sendto(packet,
                                (MDNS_MULTICAST_ADDR, MDNS_PORT, 0, iface_idx))
                except OSError:
                    pass
                next_resend = time.monotonic() + 1.2
            sock.settimeout(min(remaining, 1.0))
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                continue

            pkt_count += 1

            # Parse DNS packet
            if len(data) < 12:
                continue
            _id, _flags, _qdcount, ancount, _nscount, _arcount = struct.unpack(
                "!HHHHHH", data[:12]
            )
            is_response = bool(_flags & 0x8000)

            # Skip queries (our own echo or from DUT's listener)
            if not is_response:
                continue

            print(f"[mdns] DIAG pkt#{pkt_count} flags=0x{_flags:04x} qd={_qdcount} an={ancount} ns={_nscount} ar={_arcount} len={len(data)}")

            # Skip question section
            offset = 12
            for _ in range(_qdcount):
                _name, offset = _decode_dns_name(data, offset)
                offset += 4  # QTYPE + QCLASS

            # Parse answer + authority + additional for any matching PTR
            total_rr = ancount + _nscount + _arcount
            for _ in range(total_rr):
                if offset >= len(data):
                    break
                rr_name, offset = _decode_dns_name(data, offset)
                if offset + 10 > len(data):
                    break
                rr_type, _rr_class, _rr_ttl, rdlen = struct.unpack(
                    "!HHIH", data[offset : offset + 10]
                )
                offset += 10
                if offset + rdlen > len(data):
                    break
                if rr_type == DNS_TYPE_PTR:
                    rr_name_norm = rr_name.lower().rstrip(".")
                    if rr_name_norm == qname_norm:
                        ptr_rdata, _ = _decode_dns_name(data, offset)
                        if ptr_rdata not in ptr_results:
                            ptr_results.append(ptr_rdata)
                offset += rdlen

            if ptr_results:
                break  # got what we need

        print(f"[mdns] raw query: received {pkt_count} packets, found {len(ptr_results)} PTR matches")
        return ptr_results
    finally:
        sock.close()


def _capture_mdns_announcements(iface_idx: int, target_ptr_name: str,
                                timeout: float = 10.0) -> list[str]:
    """Listen for mDNS announcements and return PTR RDATA for target_ptr_name.

    This passively captures unsolicited mDNS announcements (no query sent).
    Looks for PTR records matching target_ptr_name in any section (answer,
    authority, additional) of any mDNS response packet.

    Returns a list of PTR RDATA domain names found.
    """
    target_norm = target_ptr_name.lower().rstrip(".")

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("::", MDNS_PORT))
        mreq = socket.inet_pton(socket.AF_INET6, MDNS_MULTICAST_ADDR)
        mreq += struct.pack("I", iface_idx)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        sock.settimeout(1.0)

        ptr_results = []
        pkt_count = 0
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                continue

            pkt_count += 1
            if len(data) < 12:
                continue
            _id, _flags, _qdcount, ancount, _nscount, _arcount = struct.unpack(
                "!HHHHHH", data[:12]
            )
            if not (_flags & 0x8000):
                continue  # skip queries

            # Skip questions
            offset = 12
            for _ in range(_qdcount):
                _name, offset = _decode_dns_name(data, offset)
                offset += 4

            # Parse all RRs
            total_rr = ancount + _nscount + _arcount
            for _ in range(total_rr):
                if offset >= len(data):
                    break
                rr_name, offset = _decode_dns_name(data, offset)
                if offset + 10 > len(data):
                    break
                rr_type, _rr_class, _rr_ttl, rdlen = struct.unpack(
                    "!HHIH", data[offset : offset + 10]
                )
                offset += 10
                if offset + rdlen > len(data):
                    break
                if rr_type == DNS_TYPE_PTR:
                    rr_name_norm = rr_name.lower().rstrip(".")
                    if rr_name_norm == target_norm:
                        ptr_rdata, _ = _decode_dns_name(data, offset)
                        if ptr_rdata not in ptr_results:
                            ptr_results.append(ptr_rdata)
                offset += rdlen

            if ptr_results:
                break

        print(f"[mdns] capture: received {pkt_count} packets, found {len(ptr_results)} PTR matches for {target_ptr_name}")
        return ptr_results
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Helper: raw mDNS SP-TXT query (bypasses zeroconf cache)
# ---------------------------------------------------------------------------

def _raw_mdns_txt_query(iface_idx: int, instance_name: str,
                        timeout: float = 5.0) -> "dict[bytes, bytes | None] | None":
    """Send a raw mDNS ANY query for instance_name and return TXT key/value pairs.

    Querying DNS_TYPE_ANY (255) directly for the instance name (e.g.
    <serial>._knx._udp.local.) avoids RFC 6762 PTR duplicate-response
    suppression, which causes the DUT to silently drop PTR responses after
    recent announcements.  The DUT responds with its full record set (SRV +
    AAAA + optional TXT SP=<n>); we collect TXT records from the answer and
    additional sections and return the parsed properties.

    Returns:
        dict  - response received (may be empty if no TXT keys present)
        None  - no response received within timeout
    """
    DNS_TYPE_ANY = 255
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    question = (_encode_dns_name(instance_name)
                + struct.pack("!HH", DNS_TYPE_ANY, DNS_CLASS_IN))
    packet = header + question

    instance_norm = instance_name.lower().rstrip(".")

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("::", MDNS_PORT))
        mreq = socket.inet_pton(socket.AF_INET6, MDNS_MULTICAST_ADDR)
        mreq += struct.pack("I", iface_idx)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        sock.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
            struct.pack("I", iface_idx),
        )
        sock.settimeout(timeout)
        sock.sendto(packet, (MDNS_MULTICAST_ADDR, MDNS_PORT, 0, iface_idx))

        deadline = time.monotonic() + timeout
        next_resend = time.monotonic() + 1.2
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if time.monotonic() >= next_resend:
                try:
                    sock.sendto(packet,
                                (MDNS_MULTICAST_ADDR, MDNS_PORT, 0, iface_idx))
                except OSError:
                    pass
                next_resend = time.monotonic() + 1.2
            sock.settimeout(min(remaining, 1.0))
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                continue

            if len(data) < 12:
                continue
            _id, _flags, _qdcount, ancount, _nscount, _arcount = struct.unpack(
                "!HHHHHH", data[:12]
            )
            if not (_flags & 0x8000):
                continue  # skip non-responses

            # Skip question section
            offset = 12
            for _ in range(_qdcount):
                _name, offset = _decode_dns_name(data, offset)
                offset += 4

            # Parse all RR sections; collect TXT RRs for our instance
            total_rr = ancount + _nscount + _arcount
            txt_props: "dict[bytes, bytes | None]" = {}
            got_response = False

            for _ in range(total_rr):
                if offset >= len(data):
                    break
                rr_name, offset = _decode_dns_name(data, offset)
                if offset + 10 > len(data):
                    break
                rr_type, _rr_class, _rr_ttl, rdlen = struct.unpack(
                    "!HHIH", data[offset: offset + 10]
                )
                offset += 10
                if offset + rdlen > len(data):
                    break
                rdata = data[offset: offset + rdlen]
                offset += rdlen

                # Any RR whose owner name matches our instance = valid response
                if rr_name.lower().rstrip(".") == instance_norm:
                    got_response = True

                # Collect TXT records for our instance
                if (rr_type == DNS_TYPE_TXT
                        and rr_name.lower().rstrip(".") == instance_norm):
                    pos = 0
                    while pos < len(rdata):
                        slen = rdata[pos]
                        pos += 1
                        if pos + slen > len(rdata):
                            break
                        entry = rdata[pos: pos + slen]
                        pos += slen
                        if b"=" in entry:
                            k, v = entry.split(b"=", 1)
                            txt_props[k] = v
                        else:
                            txt_props[entry] = None

            if got_response:
                # We got a response from our DUT — return whatever TXT we found
                # (empty dict means SRV/AAAA were present but no TXT record)
                return txt_props

        return None  # no response received within timeout
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Helper: full mDNS transition capture (goodbye + re-announcement)
# ---------------------------------------------------------------------------

DNS_TYPE_SRV  = 33
DNS_TYPE_AAAA = 28

# Max seconds we wait after triggering a change for both goodbye and
# re-announcement to arrive before declaring the capture complete.
# The stack sends goodbye+announce within ~2 ms; 1 s is ample even under
# ASan CI load.  The passive capture starts before the trigger so there
# is no query round-trip to budget for.
TRANSITION_CAPTURE_TIMEOUT_S = 1.0

# Goodbye re-announcement gap limit (RFC 6762 §8.3: should be < 1 s)
MAX_GOODBYE_HELLO_GAP_S = 1.5


class MdnsPacketInfo:
    """All records extracted from a single raw mDNS multicast packet."""

    def __init__(self, timestamp: float, is_goodbye: bool):
        self.timestamp  = timestamp   # time.monotonic() when received
        self.is_goodbye = is_goodbye  # True when ALL TTLs == 0
        self.ptr:   list[tuple[str, str]]        = []   # (owner, target)
        self.srv:   list[tuple[str, int, str]]   = []   # (owner, port, host)
        self.aaaa:  list[tuple[str, str]]        = []   # (owner, addr_str)
        self.txt:   dict[str, dict[bytes, bytes | None]] = {}  # owner -> props

    def __repr__(self) -> str:
        kind = "GOODBYE" if self.is_goodbye else "ANNOUNCE"
        return (f"MdnsPacketInfo({kind} t={self.timestamp:.3f} "
                f"ptr={self.ptr} srv={self.srv} "
                f"aaaa={self.aaaa} txt={self.txt})")


def _parse_mdns_packets(iface_idx: int,
                        instance_norm: str,
                        timeout: float) -> list[MdnsPacketInfo]:
    """Passively capture mDNS packets that mention *instance_norm* and parse
    every record (PTR, SRV, AAAA, TXT) from them.

    Returns a list of MdnsPacketInfo objects in arrival order.
    Packets from unrelated instances are silently dropped.
    """
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("::", MDNS_PORT))
        mreq = socket.inet_pton(socket.AF_INET6, MDNS_MULTICAST_ADDR)
        mreq += struct.pack("I", iface_idx)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        sock.settimeout(1.0)

        results: list[MdnsPacketInfo] = []
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                continue

            ts = time.monotonic()
            if len(data) < 12:
                continue
            _id, _flags, _qdcount, ancount, _nscount, _arcount = struct.unpack(
                "!HHHHHH", data[:12]
            )
            if not (_flags & 0x8000):
                continue  # skip queries

            # Skip question section
            offset = 12
            for _ in range(_qdcount):
                _, offset = _decode_dns_name(data, offset)
                offset += 4

            total_rr = ancount + _nscount + _arcount
            pkt = MdnsPacketInfo(timestamp=ts, is_goodbye=False)
            relevant = False

            for _ in range(total_rr):
                if offset >= len(data):
                    break
                rr_name, offset = _decode_dns_name(data, offset)
                if offset + 10 > len(data):
                    break
                rr_type, _rr_class, rr_ttl, rdlen = struct.unpack(
                    "!HHIH", data[offset: offset + 10]
                )
                offset += 10
                if offset + rdlen > len(data):
                    break
                rdata = data[offset: offset + rdlen]
                offset += rdlen

                # Goodbye classification:
                # - PTR TTL=0  → full service goodbye
                # - TXT TTL=0  → standalone TXT record goodbye (SP cleared)
                # AAAA records may have TTL>0 even in a goodbye packet.
                # Packets with no PTR/TXT records at all are announcements.
                if rr_ttl == 0 and rr_type in (DNS_TYPE_PTR, DNS_TYPE_TXT):
                    pkt.is_goodbye = True

                rr_norm = rr_name.lower().rstrip(".")

                # A packet belongs to our instance if any RR owner name contains
                # the serial number (covers instance name, hostname, subtype PTRs)
                sn_norm = DUT_SERIAL.lower()
                if sn_norm not in rr_norm:
                    # Still check PTR targets below
                    if rr_type == DNS_TYPE_PTR:
                        try:
                            target, _ = _decode_dns_name(data, offset - rdlen)
                            if sn_norm in target.lower():
                                relevant = True
                                pkt.ptr.append((rr_name, target))
                        except Exception:
                            pass
                    continue

                relevant = True

                if rr_type == DNS_TYPE_PTR:
                    try:
                        target, _ = _decode_dns_name(data, offset - rdlen)
                        pkt.ptr.append((rr_name, target))
                    except Exception:
                        pass

                elif rr_type == DNS_TYPE_SRV:
                    # SRV RDATA: priority(2) weight(2) port(2) target(name)
                    if len(rdata) >= 6:
                        port = struct.unpack("!H", rdata[4:6])[0]
                        try:
                            host, _ = _decode_dns_name(data, offset - rdlen + 6)
                            pkt.srv.append((rr_name, port, host))
                        except Exception:
                            pass

                elif rr_type == DNS_TYPE_AAAA:
                    if len(rdata) == 16:
                        import ipaddress
                        addr = str(ipaddress.IPv6Address(rdata))
                        pkt.aaaa.append((rr_name, addr))

                elif rr_type == DNS_TYPE_TXT:
                    props: dict[bytes, bytes | None] = {}
                    pos = 0
                    while pos < len(rdata):
                        slen = rdata[pos]
                        pos += 1
                        if pos + slen > len(rdata):
                            break
                        entry = rdata[pos: pos + slen]
                        pos += slen
                        if b"=" in entry:
                            k, v = entry.split(b"=", 1)
                            props[k] = v
                        else:
                            props[entry] = None
                    pkt.txt[rr_name] = props

            if relevant:
                results.append(pkt)

        return results
    finally:
        sock.close()


class TransitionResult:
    """Parsed result of a single mDNS state-change transition.

    Packets that arrived before *trigger_time* belong to the previous step
    (for example the RFC 6762 section 8.3 repeat of the setup announcement)
    and are dropped, so goodbyes/announces only hold the reaction to the
    trigger.
    """

    def __init__(self, packets: "list[MdnsPacketInfo]",
                 trigger_time: "float | None" = None):
        if trigger_time is not None:
            packets = [p for p in packets if p.timestamp >= trigger_time]
        self.packets   = packets
        self.goodbyes  = [p for p in packets if p.is_goodbye]
        self.announces = [p for p in packets if not p.is_goodbye]

    @property
    def goodbye_time(self) -> "float | None":
        return self.goodbyes[0].timestamp if self.goodbyes else None

    @property
    def announce_time(self) -> "float | None":
        return self.announces[0].timestamp if self.announces else None

    @property
    def gap_s(self) -> "float | None":
        """Seconds between first goodbye and first re-announcement."""
        if self.goodbye_time is not None and self.announce_time is not None:
            return self.announce_time - self.goodbye_time
        return None

    def all_aaaa(self, is_goodbye: bool) -> list[str]:
        """Collect all IPv6 address strings from goodbye or announce packets."""
        addrs: list[str] = []
        for p in (self.goodbyes if is_goodbye else self.announces):
            for _owner, addr in p.aaaa:
                if addr not in addrs:
                    addrs.append(addr)
        return addrs

    def all_subtypes(self, is_goodbye: bool) -> list[str]:
        """Collect all subtype PTR owner names from goodbye or announce packets."""
        subtypes: list[str] = []
        for p in (self.goodbyes if is_goodbye else self.announces):
            for owner, _target in p.ptr:
                norm = owner.lower()
                if "_sub." in norm and norm not in subtypes:
                    subtypes.append(norm)
        return subtypes

    def txt_sp(self, is_goodbye: bool) -> "str | None":
        """Return the SP TXT value from goodbye or announce packets, or None."""
        for p in (self.goodbyes if is_goodbye else self.announces):
            for _owner, props in p.txt.items():
                for k, v in props.items():
                    if k.upper() == b"SP":
                        return v.decode("ascii") if v else ""
        return None

    def __repr__(self) -> str:
        return (f"TransitionResult(goodbyes={len(self.goodbyes)}, "
                f"announces={len(self.announces)}, gap={self.gap_s})")


def _run_transition(iface_idx: int, trigger_fn,
                    timeout: float = TRANSITION_CAPTURE_TIMEOUT_S,
                    want_goodbye: bool = True) -> TransitionResult:
    """Start packet capture, call trigger_fn(), wait, return TransitionResult.

    Capture runs in a background thread so the trigger is fired while
    the socket is already listening.
    """
    import threading

    captured: list[MdnsPacketInfo] = []

    instance = f"{DUT_SERIAL}.{KNX_SERVICE_TYPE}".lower().rstrip(".")

    def _capture():
        captured.extend(_parse_mdns_packets(iface_idx, instance, timeout))

    t = threading.Thread(target=_capture, daemon=True)
    t.start()
    time.sleep(0.15)  # let socket bind before triggering

    trigger_time = time.monotonic()
    trigger_fn()

    t.join(timeout + 2)
    return TransitionResult(captured, trigger_time)


# ---------------------------------------------------------------------------
# Helper: resolve interface name → index (Linux)
# ---------------------------------------------------------------------------

def _iface_name_to_index(name: str) -> int:
    """Convert interface name (e.g. 'veth-test') to its numeric index."""
    return socket.if_nametoindex(name)


def _get_zeroconf_interfaces():
    """Return the interfaces parameter for Zeroconf based on DEVICE_IFACE.

    In CI (Linux + veth), DEVICE_IFACE is set to the test-side veth interface.
    zeroconf accepts interface indexes for IPv6.  On systems without
    DEVICE_IFACE, returns InterfaceChoice.All.
    """
    iface = os.environ.get("DEVICE_IFACE")
    if iface:
        try:
            idx = _iface_name_to_index(iface)
            return [idx]
        except (OSError, AttributeError):
            pass
    # Fallback: use default (all interfaces)
    from zeroconf import InterfaceChoice
    return InterfaceChoice.All


# ---------------------------------------------------------------------------
# Listener for ServiceBrowser
# ---------------------------------------------------------------------------

class _ServiceCollector:
    """Collects discovered service names from a ServiceBrowser."""

    def __init__(self):
        self.found: list[str] = []

    def add_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
        self.found.append(name)

    def remove_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
        pass

    def update_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
        pass


# ---------------------------------------------------------------------------
# Fixture: session-scoped Zeroconf instance
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mdns(server_process):
    """Create a Zeroconf instance on the correct interface."""
    if not HAS_ZEROCONF:
        pytest.skip("zeroconf library not installed")

    interfaces = _get_zeroconf_interfaces()
    zc = Zeroconf(interfaces=interfaces, ip_version=IPVersion.V6Only)
    yield zc
    zc.close()


# ---------------------------------------------------------------------------
# Helper: browse a DNS-SD type/subtype and return discovered names
# ---------------------------------------------------------------------------

def _browse_service(mdns: "Zeroconf", service_type: str,
                    timeout: float = MDNS_BROWSE_TIMEOUT_S) -> list[str]:
    """Browse for services of the given type, return list of instance names.

    Uses ServiceBrowser (zeroconf) as the primary method.  If that returns
    nothing (e.g. because the DUT rate-limited its response after heavy
    multicast traffic in an earlier test), sends a raw PTR query to "wake"
    the DUT, then re-runs ServiceBrowser to populate the zeroconf cache
    (needed by subsequent _get_service_info calls).
    """
    collector = _ServiceCollector()
    browser = ServiceBrowser(mdns, service_type, collector)
    time.sleep(timeout)
    browser.cancel()
    if collector.found:
        return collector.found

    # Fallback: raw PTR query to break DUT rate-limiting (RFC 6762 §11.3),
    # then re-run ServiceBrowser so the zeroconf cache gets populated.
    iface = os.environ.get("DEVICE_IFACE")
    if not iface:
        return []
    try:
        iface_idx = _iface_name_to_index(iface)
    except (OSError, AttributeError):
        return []
    print(f"[mdns] _browse_service: zeroconf got 0 results for {service_type!r}, sending raw PTR query to wake DUT")
    raw = _raw_mdns_ptr_query(iface_idx, service_type, timeout=timeout)
    if not raw:
        return []
    # Re-run ServiceBrowser now that the DUT has answered; this populates
    # the zeroconf instance cache so that _get_service_info works afterwards.
    collector2 = _ServiceCollector()
    browser2 = ServiceBrowser(mdns, service_type, collector2)
    time.sleep(min(timeout, 3.0))
    browser2.cancel()
    return collector2.found if collector2.found else raw


def _provoke_reannounce(coap, oscore_ctx) -> None:
    """Force the DUT to emit a fresh unsolicited mDNS announcement burst.

    Under full-suite load the DUT applies RFC 6762 response suppression and
    stops answering solicited PTR/SRV/AAAA queries, so a passive browse returns
    nothing.  A state change, however, always triggers a goodbye + re-announce
    burst that the zeroconf listener reliably caches.  This helper performs a
    state-neutral toggle (programming mode on, then off) purely to provoke that
    burst, then waits for the re-announcement to be received.  This mirrors the
    proven pattern used by the passing PM discovery tests (5.1.2.4).
    """
    if oscore_ctx is None:
        return
    for value in (True, False):
        payload = cbor2.dumps({1: value})
        coap.oscore_put(oscore_ctx, "/dev/pm", payload=payload,
                        timeout=COAP_TIMEOUT)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)


def _get_service_info(mdns: "Zeroconf", service_type: str,
                      instance_name: str,
                      timeout_ms: int = 3000) -> "ServiceInfo | None":
    """Query SRV + AAAA + TXT for a specific service instance.

    Retries a few times with a delay when None is returned, to get past the
    DUT's mDNS response-suppression window (RFC 6762) that can appear in a
    full-suite run after heavy multicast traffic.
    """
    for attempt in range(3):
        info = mdns.get_service_info(service_type, instance_name,
                                     timeout=timeout_ms)
        if info is not None:
            return info
        print(f"[mdns] _get_service_info: attempt {attempt + 1} returned None for {instance_name!r}, retrying")
        time.sleep(1.5)
    return None


# ---------------------------------------------------------------------------
# Helper: verify full discovery chain (PTR → SRV → AAAA → CoAP reachability)
# ---------------------------------------------------------------------------

def _verify_discovery_chain(mdns, coap, service_type, expected_instance):
    """
    Full EITT discovery chain:
      1. PTR query → find instance
      2. SRV query → get hostname + port
      3. AAAA query → get IPv6 address
      4. CoAP GET .well-known/core → verify reachability
    """
    # Step 1: Browse for PTR records
    found = _browse_service(mdns, service_type)
    assert len(found) > 0, (
        f"No services found browsing {service_type}")
    assert expected_instance in found, (
        f"Expected '{expected_instance}' in {found}")

    # Step 2+3: SRV + AAAA via get_service_info
    info = _get_service_info(mdns, KNX_SERVICE_TYPE, expected_instance)
    assert info is not None, (
        f"Could not resolve service info for {expected_instance}")
    assert info.server is not None, "SRV record missing hostname"
    assert info.port > 0, f"SRV record has invalid port: {info.port}"

    # Verify hostname format: knx-{serial}.local.
    expected_hostname = f"knx-{DUT_SERIAL}.local."
    assert info.server.lower() == expected_hostname, (
        f"Hostname mismatch: {info.server} != {expected_hostname}")

    # Check AAAA record (IPv6 address)
    ipv6_addrs = info.parsed_addresses(version=IPVersion.V6Only)
    assert len(ipv6_addrs) > 0, "No AAAA (IPv6) records in service info"

    # Step 4: Verify CoAP reachability at discovered address
    resp = coap.get(".well-known/core", accept=LINK_FORMAT,
                    timeout=COAP_TIMEOUT)
    assert resp is not None, "CoAP GET .well-known/core timed out"
    assert resp.is_successful, (
        f"CoAP GET .well-known/core failed: {resp.code}")

    return info


# ===========================================================================
# 5.1.2.1 -- Discovery using serial number for unconfigured device
# ===========================================================================

class TestMdnsDiscoverySerialUnconfigured:
    """5.1.2.1: Discovery using serial number is possible for unconfigured device."""

    @pytest.mark.eitt_overlap("5.1.2.1")
    def test_browse_knx_service_by_serial(self, mdns, coap, oscore_ctx):
        """Step 1-2: PTR query for _knx._udp.local -> find device by SN."""
        _provoke_reannounce(coap, oscore_ctx)
        expected = f"{DUT_SERIAL}.{KNX_SERVICE_TYPE}"
        found = _browse_service(mdns, KNX_SERVICE_TYPE)
        assert len(found) > 0, "No KNX services found via mDNS browse"
        assert expected in found, (
            f"Device '{expected}' not found. Found: {found}")

    @pytest.mark.eitt_overlap("5.1.2.1")
    def test_srv_resolution_of_unconfigured_device(self, mdns, coap, oscore_ctx):
        """Step 5-6: SRV query -> hostname + port."""
        _provoke_reannounce(coap, oscore_ctx)
        instance = f"{DUT_SERIAL}.{KNX_SERVICE_TYPE}"
        info = _get_service_info(mdns, KNX_SERVICE_TYPE, instance)
        assert info is not None, f"Could not resolve SRV for {instance}"

        expected_hostname = f"knx-{DUT_SERIAL}.local."
        assert info.server.lower() == expected_hostname, (
            f"Hostname: {info.server} != {expected_hostname}")
        assert info.port > 0, f"Invalid port: {info.port}"

    @pytest.mark.eitt_overlap("5.1.2.1")
    def test_aaaa_resolution_of_unconfigured_device(self, mdns, coap, oscore_ctx):
        """Step 7-8: AAAA query -> IPv6 address."""
        _provoke_reannounce(coap, oscore_ctx)
        instance = f"{DUT_SERIAL}.{KNX_SERVICE_TYPE}"
        info = _get_service_info(mdns, KNX_SERVICE_TYPE, instance)
        assert info is not None, f"Could not resolve info for {instance}"

        ipv6_addrs = info.parsed_addresses(version=IPVersion.V6Only)
        assert len(ipv6_addrs) > 0, "No IPv6 (AAAA) addresses resolved"

    @pytest.mark.eitt_overlap("5.1.2.1")
    def test_coap_reachability_of_unconfigured_device(self, mdns, coap):
        """Step 9-10: CoAP GET .well-known/core at discovered address → 2.05."""
        # The four preceding tests ran Zeroconf ServiceBrowsers for ~20 s total,
        # flooding the DUT's single-threaded CoAP+mDNS event loop with mDNS queries.
        # Wait for the backlog to drain, drain any stale socket data, then retry a
        # few times in case one attempt still races with a lingering mDNS query.
        time.sleep(2.0)
        coap.drain_socket()
        resp = None
        for _ in range(3):
            resp = coap.get(".well-known/core", accept=LINK_FORMAT,
                            timeout=COAP_TIMEOUT)
            if resp is not None:
                break
            time.sleep(1.0)
        assert resp is not None, "CoAP .well-known/core timed out"
        assert resp.is_successful, f"Expected 2.05, got {resp.code}"


# ===========================================================================
# 5.1.2.2 -- Discovery using serial number for configured device
# ===========================================================================

class TestMdnsDiscoverySerialConfigured:
    """5.1.2.2: Discovery using serial number is possible for configured device."""

    @pytest.mark.eitt_overlap("5.1.2.2")
    def test_full_chain_by_serial_when_configured(self, mdns, coap, oscore_ctx):
        """Full PTR -> SRV -> AAAA -> CoAP chain for configured device."""
        _provoke_reannounce(coap, oscore_ctx)
        subtype = f"_{DUT_SERIAL}._sub.{KNX_SERVICE_TYPE}"
        expected = f"{DUT_SERIAL}.{KNX_SERVICE_TYPE}"
        _verify_discovery_chain(mdns, coap, subtype, expected)


# ===========================================================================
# 5.1.2.3 -- Discovery using individual address for configured device
# ===========================================================================

class TestMdnsDiscoveryIA:
    """5.1.2.3: Discovery using individual address for configured device."""

    @pytest.mark.eitt_overlap("5.1.2.3")
    def test_full_chain_by_individual_address(self, mdns, coap, oscore_ctx):
        """Full discovery chain using IA subtype."""
        _provoke_reannounce(coap, oscore_ctx)
        iid_hex = format(DUT_IID, "x")
        ia_hex = format(DUT_IA, "x")
        subtype = f"_ia{iid_hex}-{ia_hex}._sub.{KNX_SERVICE_TYPE}"
        expected = f"{DUT_SERIAL}.{KNX_SERVICE_TYPE}"
        _verify_discovery_chain(mdns, coap, subtype, expected)


# ===========================================================================
# 5.1.2.3b -- Discovery using IA for unconfigured device
# ===========================================================================

class TestMdnsDiscoveryIAUnconfigured:
    """5.1.2.3b: Discovery using IA for unconfigured device → _ia0-ffff.

    EITT procedure:
      1. Factory reset (code 2)
      2. Browse mDNS for _ia0-ffff._sub._knx._udp.local.
      3. Verify PTR record points to {serial}._knx._udp.local.

    This test factory-resets the device, checks the unconfigured mDNS
    subtype, then re-provisions (SPAKE2+ + AT + IA/IID) to restore
    the session OSCORE context for subsequent tests.
    """

    @pytest.mark.eitt_overlap("5.1.2.3b")
    def test_unconfigured_device_advertises_default_ia_subtype(self, mdns, coap, oscore_ctx):
        """Factory-reset device should advertise _ia0-ffff subtype."""
        subtype = f"_ia0-ffff._sub.{KNX_SERVICE_TYPE}"
        expected_instance = f"{DUT_SERIAL}.{KNX_SERVICE_TYPE}"

        iface = os.environ.get("DEVICE_IFACE")
        if not iface:
            pytest.skip("DEVICE_IFACE not set — cannot capture mDNS")
        iface_idx = _iface_name_to_index(iface)

        # 1. Start capturing mDNS announcements BEFORE the factory reset.
        #    The DUT sends an unsolicited mDNS announcement (with the
        #    _ia0-ffff subtype PTR in additional records) ~200ms after
        #    the factory reset fires.  We need to be listening to catch it.
        import threading
        capture_result: list[str] = []

        def _capture_thread():
            result = _capture_mdns_announcements(
                iface_idx, subtype, timeout=15)
            capture_result.extend(result)

        cap_thread = threading.Thread(target=_capture_thread, daemon=True)
        cap_thread.start()
        time.sleep(0.2)  # let the socket bind before sending reset

        # 2. Factory reset code 2 via OSCORE (like EITT does).
        reset_payload = cbor2.dumps({2: "reset", 1: 2})
        resp = coap.oscore_post(oscore_ctx, "/.well-known/knx",
                                payload=reset_payload, timeout=5)
        assert resp is not None and resp.is_successful, (
            f"Factory reset code 2 failed: {resp}")

        # 3. Wait for the capture thread to finish (it will get the
        #    announcement or time out after 15s).
        cap_thread.join(timeout=20)
        print(f"[5.1.2.3b] Announcement capture for {subtype} -> {capture_result}")

        # 4. If capture missed the announcement, try a raw PTR query
        #    as fallback (the listener thread should respond).
        if not capture_result:
            time.sleep(2)  # extra wait for DUT to settle
            query_result = _raw_mdns_ptr_query(iface_idx, subtype, timeout=8)
            print(f"[5.1.2.3b] Raw PTR query for {subtype} -> {query_result}")
            capture_result.extend(query_result)

        ptr_results = capture_result

        # 5. Re-provision FIRST so subsequent tests work even if
        #    mDNS discovery fails.
        spake = Spake2PlusClient(
            password=DEVICE_PASSWORD, sender_id="MdnsRe")

        req1 = cbor2.dumps(spake.create_parameter_request())
        resp1 = coap.post("/.well-known/knx/spake", payload=req1,
                          content_format=APPLICATION_CBOR, timeout=30)
        assert resp1 is not None and resp1.is_successful, (
            f"SPAKE2+ step 1 failed: {resp1}")
        spake.process_parameter_response(cbor2.loads(resp1.payload))

        req2 = cbor2.dumps(spake.create_key_exchange_request())
        resp2 = coap.post("/.well-known/knx/spake", payload=req2,
                          content_format=APPLICATION_CBOR, timeout=30)
        assert resp2 is not None and resp2.is_successful, (
            f"SPAKE2+ step 2 failed: {resp2}")
        spake.process_key_exchange_response(cbor2.loads(resp2.payload))

        req3 = cbor2.dumps(spake.create_confirmation_request())
        resp3 = coap.post("/.well-known/knx/spake", payload=req3,
                          content_format=APPLICATION_CBOR, timeout=10)
        assert resp3 is not None and resp3.is_successful, (
            f"SPAKE2+ step 3 failed: {resp3}")

        # 6. Provision AT entry via PASE context
        pase_sender_id = spake.sender_id.encode("utf-8")
        pase_ctx = OscoreContext(
            master_secret=spake.shared_key,
            sender_id=pase_sender_id,
            recipient_id=b"",
        )

        new_master_secret = os.urandom(16)
        new_sender_id = b"RtTest"
        at_inner = {
            0: "RuntimeTest",
            9: ALL_SCOPES,
            38: 2,
            8: {4: {0: new_sender_id, 2: new_master_secret}},
        }
        at_cbor = cbor2.dumps({0: at_inner})
        resp_at = coap.oscore_post(pase_ctx, "/auth/at",
                                   payload=at_cbor, timeout=10)
        assert resp_at is not None and resp_at.is_successful, (
            f"AT provisioning failed: {resp_at}")

        # 7. Set IA/IID to restore runtime state
        new_ctx = OscoreContext(
            master_secret=new_master_secret,
            sender_id=new_sender_id,
            recipient_id=b"",
        )
        ia_iid_payload = cbor2.dumps({12: DUT_IA, 26: DUT_IID})
        resp_ia = coap.oscore_post(
            new_ctx, "/.well-known/knx/ia", payload=ia_iid_payload)
        assert resp_ia is not None and resp_ia.is_successful, (
            f"IA/IID restore failed: {resp_ia}")

        # 8. Update session oscore_ctx in-place so subsequent tests work
        oscore_ctx.master_secret = new_ctx.master_secret
        oscore_ctx.sender_id = new_ctx.sender_id
        oscore_ctx.recipient_id = new_ctx.recipient_id
        oscore_ctx.id_context = new_ctx.id_context
        oscore_ctx.ssn = new_ctx.ssn
        oscore_ctx.sender_key = new_ctx.sender_key
        oscore_ctx.recipient_key = new_ctx.recipient_key
        oscore_ctx.common_iv = new_ctx.common_iv

        # 9. Assert on the mDNS result (after re-provisioning)
        assert len(ptr_results) > 0, (
            f"Unconfigured device should respond to PTR query for {subtype}")
        # Check that the PTR RDATA points to the expected instance
        matched = any(
            r.lower().rstrip(".") == expected_instance.lower().rstrip(".")
            for r in ptr_results
        )
        assert matched, (
            f"Expected PTR → '{expected_instance}' in {ptr_results}")


# ===========================================================================
# 5.1.2.4 -- Discovery using programming mode
# ===========================================================================

class TestMdnsDiscoveryPM:
    """5.1.2.4: Discovery using programming mode."""

    @pytest.mark.eitt_overlap("5.1.2.4")
    def test_full_chain_via_programming_mode_subtype(self, mdns, coap, oscore_ctx):
        """Full discovery chain via _pm subtype."""
        # Enable programming mode, then wait for the mDNS re-announcement.
        # This used to be left behind by a sibling test that enabled the
        # _pm subtype, removed as covered by EITT template case 5.1.2.4; the
        # chain test must not depend on a sibling test having run first.
        pm_payload = cbor2.dumps({1: True})
        resp = coap.oscore_put(oscore_ctx, "/dev/pm",
                               payload=pm_payload, timeout=COAP_TIMEOUT)
        assert resp is not None and resp.is_successful, (
            f"PUT /dev/pm=true failed: {resp}")
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

        subtype = f"_pm._sub.{KNX_SERVICE_TYPE}"
        expected = f"{DUT_SERIAL}.{KNX_SERVICE_TYPE}"
        _verify_discovery_chain(mdns, coap, subtype, expected)

    @pytest.mark.eitt_overlap("5.1.2.4")
    def test_programming_mode_subtype_withdrawn_when_disabled(self, mdns, coap, oscore_ctx):
        """Disable PM → _pm subtype should no longer be advertised."""
        # Disable programming mode (CBOR map {1: false})
        pm_payload = cbor2.dumps({1: False})
        resp = coap.oscore_put(oscore_ctx, "/dev/pm",
                               payload=pm_payload, timeout=COAP_TIMEOUT)
        assert resp is not None and resp.is_successful, (
            f"PUT /dev/pm=false failed: {resp}")

        # Wait for mDNS goodbye + re-announcement without _pm
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

        subtype = f"_pm._sub.{KNX_SERVICE_TYPE}"
        found = _browse_service(mdns, subtype, timeout=3)
        # Device should NOT appear in _pm browse results
        expected = f"{DUT_SERIAL}.{KNX_SERVICE_TYPE}"
        assert expected not in found, (
            f"Device still found via _pm subtype after disabling PM")


# ===========================================================================
# 5.1.2.5a -- Unsolicited mDNS responses on Programming mode change
# ===========================================================================

class TestMdnsUnsolicitedPM:
    """5.1.2.5a: Unsolicited mDNS responses on Programming mode change."""

    @pytest.mark.eitt_overlap("5.1.2.5a")
    def test_programming_mode_toggle_announcements(self, mdns, coap, oscore_ctx):
        """Toggle PM on→off→on and verify mDNS announcements appear."""
        expected = f"{DUT_SERIAL}.{KNX_SERVICE_TYPE}"

        # Enable PM
        resp = coap.oscore_put(oscore_ctx, "/dev/pm",
                               payload=cbor2.dumps({1: True}),
                               timeout=COAP_TIMEOUT)
        assert resp is not None and resp.is_successful

        # Browse _pm — should find device
        time.sleep(MDNS_ANNOUNCE_WAIT_S)
        subtype = f"_pm._sub.{KNX_SERVICE_TYPE}"
        found = _browse_service(mdns, subtype)
        assert expected in found, "PM enable: device not found via _pm"

        # Disable PM
        resp = coap.oscore_put(oscore_ctx, "/dev/pm",
                               payload=cbor2.dumps({1: False}),
                               timeout=COAP_TIMEOUT)
        assert resp is not None and resp.is_successful

        # Browse _pm — should NOT find device
        time.sleep(MDNS_ANNOUNCE_WAIT_S)
        found = _browse_service(mdns, subtype, timeout=3)
        assert expected not in found, "PM disable: device still in _pm"

        # Re-enable PM
        resp = coap.oscore_put(oscore_ctx, "/dev/pm",
                               payload=cbor2.dumps({1: True}),
                               timeout=COAP_TIMEOUT)
        assert resp is not None and resp.is_successful

        # Browse _pm — should find device again
        time.sleep(MDNS_ANNOUNCE_WAIT_S)
        found = _browse_service(mdns, subtype)
        assert expected in found, "PM re-enable: device not found via _pm"

        # Cleanup: disable PM
        coap.oscore_put(oscore_ctx, "/dev/pm",
                        payload=cbor2.dumps({1: False}),
                        timeout=COAP_TIMEOUT)


# ===========================================================================
# 5.1.2.5b -- Unsolicited mDNS responses on Individual Address change
# ===========================================================================

class TestMdnsUnsolicitedIA:
    """5.1.2.5b: Unsolicited mDNS responses on Individual Address change."""

    @pytest.mark.eitt_overlap("5.1.2.5b")
    def test_individual_address_change_announcement(self, mdns, coap, oscore_ctx):
        """Change IA and verify new IA subtype appears in mDNS."""
        expected = f"{DUT_SERIAL}.{KNX_SERVICE_TYPE}"

        # Set a new IA (different from EITT default)
        new_ia = 0x4D2   # 1234 decimal
        new_iid = 0x2DFDC1C3D  # 12345678909 decimal
        ia_payload = cbor2.dumps({12: new_ia, 26: new_iid})
        resp = coap.oscore_post(oscore_ctx, "/.well-known/knx/ia",
                                payload=ia_payload, timeout=COAP_TIMEOUT)
        assert resp is not None and resp.is_successful, (
            f"POST IA change failed: {resp}")

        # Wait for mDNS re-announcement
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

        # Browse new IA subtype
        iid_hex = format(new_iid, "x")
        ia_hex = format(new_ia, "x")
        subtype = f"_ia{iid_hex}-{ia_hex}._sub.{KNX_SERVICE_TYPE}"

        found = _browse_service(mdns, subtype)
        assert expected in found, (
            f"Device not found via new IA subtype {subtype} after IA change")

        # Restore original EITT IA
        restore = cbor2.dumps({12: DUT_IA, 26: DUT_IID})
        coap.oscore_post(oscore_ctx, "/.well-known/knx/ia",
                         payload=restore, timeout=COAP_TIMEOUT)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)


# ===========================================================================
# SP (sleep period) TXT record -- non-EITT extension tests
# ===========================================================================

def _set_sleep_period(coap, oscore_ctx, sp: int) -> None:
    """POST /test/sleep-period {1: sp} and wait for the mDNS re-announcement."""
    payload = cbor2.dumps({1: sp})
    resp = coap.oscore_post(oscore_ctx, "/test/sleep-period",
                            payload=payload, timeout=COAP_TIMEOUT)
    assert resp is not None, f"POST /test/sleep-period timed out (sp={sp})"
    assert resp.is_successful, (
        f"POST /test/sleep-period failed: {resp.code} (sp={sp})")
    # Give the stack time to re-announce with the updated TXT record
    time.sleep(MDNS_ANNOUNCE_WAIT_S)


def _get_txt_sp_from_packets(packets: "list[MdnsPacketInfo]") -> "str | None":
    """Extract the SP value from the TXT records of announce packets."""
    for pkt in packets:
        if pkt.is_goodbye:
            continue
        for _owner, props in pkt.txt.items():
            for k, v in props.items():
                if k.upper() == b"SP":
                    return v.decode("ascii") if v is not None else ""
    return None


def _set_sp_and_get_txt(coap, oscore_ctx, iface_idx: int,
                        sp: int) -> "str | None":
    """POST /test/sleep-period and capture the DUT's proactive re-announcement.

    Starts the passive mDNS capture BEFORE posting the change so that the
    re-announcement burst is not missed.  The DUT always sends a full
    PTR+SRV+AAAA+(TXT) re-announcement after a sleep-period change; reading
    that proactive packet avoids RFC 6762 duplicate-response suppression that
    would silence a query-based approach.

    Returns the SP TXT value string, or None if the TXT record was absent.
    """
    instance = f"{DUT_SERIAL}.{KNX_SERVICE_TYPE}".lower().rstrip(".")
    capture_timeout = COAP_TIMEOUT + MDNS_ANNOUNCE_WAIT_S + 2.0

    import threading
    packets: "list[MdnsPacketInfo]" = []
    ready = threading.Event()

    def _capture():
        # Signal the main thread that the socket is bound and listening
        # before it fires the POST.
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM,
                             socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(("::", MDNS_PORT))
            mreq = socket.inet_pton(socket.AF_INET6, MDNS_MULTICAST_ADDR)
            mreq += struct.pack("I", iface_idx)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
            sock.settimeout(0.5)
            ready.set()
            deadline = time.monotonic() + capture_timeout
            while time.monotonic() < deadline:
                try:
                    data, _addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                if len(data) < 12:
                    continue
                _id, _flags, _qdcount, ancount, _nscount, _arcount = (
                    struct.unpack("!HHHHHH", data[:12]))
                if not (_flags & 0x8000):
                    continue
                offset = 12
                for _ in range(_qdcount):
                    _, offset = _decode_dns_name(data, offset)
                    offset += 4
                total_rr = ancount + _nscount + _arcount
                pkt = MdnsPacketInfo(timestamp=time.monotonic(), is_goodbye=False)
                relevant = False
                for _ in range(total_rr):
                    if offset >= len(data):
                        break
                    rr_name, offset = _decode_dns_name(data, offset)
                    if offset + 10 > len(data):
                        break
                    rr_type, _rr_class, rr_ttl, rdlen = struct.unpack(
                        "!HHIH", data[offset: offset + 10])
                    offset += 10
                    if offset + rdlen > len(data):
                        break
                    rdata = data[offset: offset + rdlen]
                    offset += rdlen
                    # Goodbye classification:
                    # - PTR TTL=0  → full service goodbye
                    # - TXT TTL=0  → standalone TXT record goodbye (SP cleared)
                    if rr_ttl == 0 and rr_type in (DNS_TYPE_PTR, DNS_TYPE_TXT):
                        pkt.is_goodbye = True
                    rr_norm = rr_name.lower().rstrip(".")
                    sn_norm = DUT_SERIAL.lower()
                    if sn_norm not in rr_norm:
                        if rr_type == DNS_TYPE_PTR:
                            try:
                                target, _ = _decode_dns_name(data, offset - rdlen)
                                if sn_norm in target.lower():
                                    relevant = True
                            except Exception:
                                pass
                        continue
                    relevant = True
                    if rr_type == DNS_TYPE_TXT:
                        props: "dict[bytes, bytes | None]" = {}
                        pos = 0
                        while pos < len(rdata):
                            slen = rdata[pos]; pos += 1
                            if pos + slen > len(rdata):
                                break
                            entry = rdata[pos: pos + slen]; pos += slen
                            if b"=" in entry:
                                k, v = entry.split(b"=", 1)
                                props[k] = v
                            else:
                                props[entry] = None
                        pkt.txt[rr_name] = props
                if relevant:
                    packets.append(pkt)
        finally:
            sock.close()

    t = threading.Thread(target=_capture, daemon=True)
    t.start()
    ready.wait(timeout=2.0)

    _set_sleep_period(coap, oscore_ctx, sp)

    t.join(timeout=capture_timeout + 1.0)
    announces = [p for p in packets if not p.is_goodbye]
    return _get_txt_sp_from_packets(announces)


class TestMdnsSleepPeriod:
    """SP TXT record in the mDNS announcement.

    The KNX spec allows an optional TXT record SP=<seconds> on the service.
    The C function knx_dns_sd_set_sleep_period(sp) controls it:
      sp == 0  -> TXT record absent (device is wakeful)
      sp >  0  -> TXT record SP=<sp> present
    Reachable at runtime via POST /test/sleep-period {1: <int>}.

    SP buffer is char sp[6] (max 5 digits + NUL), so values up to 65535 (uint16_t).
    """

    @pytest.fixture(autouse=True)
    def _require_iface(self):
        iface = os.environ.get("DEVICE_IFACE")
        if not iface:
            pytest.skip("DEVICE_IFACE not set — passive mDNS capture not possible")
        self._iface_idx = _iface_name_to_index(iface)

    def test_sleep_period_not_present_by_default(self, coap, oscore_ctx):
        """SP TXT record is absent when sleep period is 0 (default)."""
        sp_val = _set_sp_and_get_txt(coap, oscore_ctx, self._iface_idx, 0)
        assert sp_val is None, (
            f"Expected no SP TXT record when sp=0, got SP={sp_val!r}")

    def test_sleep_period_200_appears_in_txt(self, coap, oscore_ctx):
        """SP=200 appears in the TXT record after setting sp=200."""
        sp_val = _set_sp_and_get_txt(coap, oscore_ctx, self._iface_idx, 200)
        assert sp_val == "200", (
            f"Expected SP=200 in TXT, got SP={sp_val!r}")

    def test_sleep_period_20000_appears_in_txt(self, coap, oscore_ctx):
        """SP=20000 appears in the TXT record after setting sp=20000."""
        sp_val = _set_sp_and_get_txt(coap, oscore_ctx, self._iface_idx, 20000)
        assert sp_val == "20000", (
            f"Expected SP=20000 in TXT, got SP={sp_val!r}")

    def test_sleep_period_cleared_removes_txt(self, coap, oscore_ctx):
        """Setting sp=0 after a non-zero value removes the TXT record."""
        # First set a value so the TXT record is present
        sp_before = _set_sp_and_get_txt(coap, oscore_ctx, self._iface_idx, 30)
        assert sp_before == "30", (
            f"Precondition failed: expected SP=30, got {sp_before!r}")

        # Now clear it
        sp_after = _set_sp_and_get_txt(coap, oscore_ctx, self._iface_idx, 0)
        assert sp_after is None, (
            f"Expected SP TXT record to be absent after sp=0, got {sp_after!r}")


# ===========================================================================
# Transition audit tests
#
# Each test captures the raw mDNS multicast stream around a single state
# change and verifies:
#
#   1. A goodbye (TTL=0) packet was sent for the OLD advertisement.
#   2. A re-announcement was sent with the NEW advertisement.
#   3. Both packets carry the SAME serial number (SN unchanged).
#   4. Both packets include at least one IPv6 (AAAA) address.
#   5. The gap between the goodbye and the re-announcement is ≤ 1.5 s.
#   6. The relevant field (IA subtype / PM subtype / SP TXT) changed between
#      goodbye and announcement as expected.
#
# These tests require DEVICE_IFACE (set by the docker runner) and are
# automatically skipped on hosts that do not define it.
# ===========================================================================

class TestMdnsTransitionAudit:
    """Audit the full goodbye → re-announcement cycle for every mDNS trigger."""

    @pytest.fixture(autouse=True)
    def _require_iface(self):
        iface = os.environ.get("DEVICE_IFACE")
        if not iface:
            pytest.skip("DEVICE_IFACE not set — raw mDNS capture not possible")
        self._iface_idx = _iface_name_to_index(iface)

    # ------------------------------------------------------------------
    # Shared assertion helpers
    # ------------------------------------------------------------------

    def _assert_transition_basics(self, tr: TransitionResult,
                                   label: str) -> None:
        """Check goodbye present, announce present, SN unchanged, AAAA present,
        gap within limit."""
        assert tr.goodbyes, f"[{label}] No goodbye (TTL=0) packet captured"
        assert tr.announces, f"[{label}] No re-announcement packet captured"

        # SN must appear in both goodbye and announce PTR records (unchanged)
        sn_norm = DUT_SERIAL.lower()
        for p in tr.goodbyes + tr.announces:
            for _owner, target in p.ptr:
                assert sn_norm in target.lower(), (
                    f"[{label}] SN '{sn_norm}' missing from PTR target "
                    f"'{target}' in {'goodbye' if p.is_goodbye else 'announce'}")

        # AAAA must be present in the re-announcement
        aaaa_new = tr.all_aaaa(is_goodbye=False)
        assert aaaa_new, f"[{label}] No AAAA record in re-announcement"

        # Goodbye→announce gap
        gap = tr.gap_s
        assert gap is not None, f"[{label}] Could not compute goodbye→announce gap"
        assert gap <= MAX_GOODBYE_HELLO_GAP_S, (
            f"[{label}] Gap {gap:.3f}s > limit {MAX_GOODBYE_HELLO_GAP_S}s")

    # ------------------------------------------------------------------
    # Timeline printer
    # ------------------------------------------------------------------

    @staticmethod
    def _print_transition_timeline(tr: TransitionResult, label: str) -> None:
        """Print a compact OLD-vs-NEW timeline to stdout (captured by pytest -s).

        Layout (one row per captured packet, earliest first):
          +0.000s  GOODBYE  SUBTYPES=<...>  AAAA=<...>  PORT=<n>  SP=<val>
          +0.042s  ANNOUNCE SUBTYPES=<...>  AAAA=<...>  PORT=<n>  SP=<val>
        T=0 is the timestamp of the very first packet captured.
        """
        pkts = sorted(tr.packets, key=lambda p: p.timestamp)
        if not pkts:
            print(f"[{label}] timeline: (no packets captured)")
            return

        t0 = pkts[0].timestamp
        lines = [f"[{label}] mDNS transition timeline (T0={t0:.3f}):"]
        lines.append(f"  {'dt(s)':>8}  {'TYPE':^8}  {'SUBTYPES':<42}  {'AAAA':<39}  {'PORT':>6}  SP")
        lines.append("  " + "-" * 118)

        for pkt in pkts:
            kind = "GOODBYE " if pkt.is_goodbye else "ANNOUNCE"
            dt   = pkt.timestamp - t0

            subtypes = [
                owner.split("._sub.")[0].lstrip("_")
                for owner, _target in pkt.ptr
                if "._sub." in owner.lower()
            ]
            subtypes_str = ",".join(subtypes) if subtypes else "-"

            addrs = [addr for _owner, addr in pkt.aaaa]
            aaaa_str = ",".join(addrs) if addrs else "-"

            ports = list({port for _owner, port, _host in pkt.srv})
            port_str = str(ports[0]) if ports else "-"

            sp_vals = []
            for _owner, props in pkt.txt.items():
                for k, v in props.items():
                    if k.upper() == b"SP":
                        sp_vals.append(v.decode("ascii") if v else "")
            sp_str = sp_vals[0] if sp_vals else "-"

            lines.append(f"  +{dt:>7.3f}s  {kind}  {subtypes_str:<42}  {aaaa_str:<39}  {port_str:>6}  {sp_str}")

        if tr.gap_s is not None:
            lines.append(f"  goodbye->announce gap: {tr.gap_s:.3f}s (limit {MAX_GOODBYE_HELLO_GAP_S}s)")
        print("\n".join(lines))

    # ------------------------------------------------------------------
    # IA / IID change
    # ------------------------------------------------------------------

    def test_transition_ia_change(self, coap, oscore_ctx):
        """IA/IID change: old _ia subtype in goodbye, new _ia subtype in
        re-announcement; SN, AAAA, and gap all verified."""
        old_iid_hex = format(DUT_IID, "x")
        old_ia_hex  = format(DUT_IA, "x")
        old_subtype = f"_ia{old_iid_hex}-{old_ia_hex}._sub.{KNX_SERVICE_TYPE}".lower().rstrip(".")

        new_ia  = 0x4D2          # 1234 decimal — distinct from EITT default
        new_iid = 0x2DFDC1C3D    # 12345678909 decimal
        new_iid_hex = format(new_iid, "x")
        new_ia_hex  = format(new_ia, "x")
        new_subtype = f"_ia{new_iid_hex}-{new_ia_hex}._sub.{KNX_SERVICE_TYPE}".lower().rstrip(".")

        def _trigger():
            payload = cbor2.dumps({12: new_ia, 26: new_iid})
            resp = coap.oscore_post(oscore_ctx, "/.well-known/knx/ia",
                                    payload=payload, timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST IA change failed: {resp}")

        tr = _run_transition(self._iface_idx, _trigger)
        self._assert_transition_basics(tr, "ia_change")

        # Old subtype must appear in the goodbye packet(s)
        goodbye_subtypes = tr.all_subtypes(is_goodbye=True)
        assert any(old_subtype in s for s in goodbye_subtypes), (
            f"Old IA subtype '{old_subtype}' not in goodbye subtypes: "
            f"{goodbye_subtypes}")

        # New subtype must appear in the re-announcement
        announce_subtypes = tr.all_subtypes(is_goodbye=False)
        assert any(new_subtype in s for s in announce_subtypes), (
            f"New IA subtype '{new_subtype}' not in announce subtypes: "
            f"{announce_subtypes}")

        self._print_transition_timeline(tr, "ia_change")

        # Restore EITT IA
        coap.oscore_post(oscore_ctx, "/.well-known/knx/ia",
                         payload=cbor2.dumps({12: DUT_IA, 26: DUT_IID}),
                         timeout=COAP_TIMEOUT)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

    # ------------------------------------------------------------------
    # PM enable
    # ------------------------------------------------------------------

    def test_transition_pm_enable(self, coap, oscore_ctx):
        """PM enabled: _pm subtype appears in re-announcement but not goodbye;
        SN, AAAA, and gap all verified."""
        # Ensure PM starts disabled
        coap.oscore_put(oscore_ctx, "/dev/pm",
                        payload=cbor2.dumps({1: False}), timeout=COAP_TIMEOUT)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

        pm_subtype = f"_pm._sub.{KNX_SERVICE_TYPE}".lower().rstrip(".")

        def _trigger():
            resp = coap.oscore_put(oscore_ctx, "/dev/pm",
                                   payload=cbor2.dumps({1: True}),
                                   timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"PUT /dev/pm=true failed: {resp}")

        tr = _run_transition(self._iface_idx, _trigger)
        self._assert_transition_basics(tr, "pm_enable")

        # _pm must NOT appear in goodbye (wasn't set before)
        goodbye_subtypes = tr.all_subtypes(is_goodbye=True)
        assert not any(pm_subtype in s for s in goodbye_subtypes), (
            f"_pm subtype unexpectedly in goodbye: {goodbye_subtypes}")

        # _pm MUST appear in re-announcement
        announce_subtypes = tr.all_subtypes(is_goodbye=False)
        assert any(pm_subtype in s for s in announce_subtypes), (
            f"_pm subtype missing from re-announcement: {announce_subtypes}")

        self._print_transition_timeline(tr, "pm_enable")

        # Cleanup
        coap.oscore_put(oscore_ctx, "/dev/pm",
                        payload=cbor2.dumps({1: False}), timeout=COAP_TIMEOUT)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

    # ------------------------------------------------------------------
    # PM disable
    # ------------------------------------------------------------------

    def test_transition_pm_disable(self, coap, oscore_ctx):
        """PM disabled: _pm subtype present in goodbye, absent in
        re-announcement; SN, AAAA, and gap all verified."""
        # Ensure PM starts enabled
        coap.oscore_put(oscore_ctx, "/dev/pm",
                        payload=cbor2.dumps({1: True}), timeout=COAP_TIMEOUT)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

        pm_subtype = f"_pm._sub.{KNX_SERVICE_TYPE}".lower().rstrip(".")

        def _trigger():
            resp = coap.oscore_put(oscore_ctx, "/dev/pm",
                                   payload=cbor2.dumps({1: False}),
                                   timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"PUT /dev/pm=false failed: {resp}")

        tr = _run_transition(self._iface_idx, _trigger)
        self._assert_transition_basics(tr, "pm_disable")

        # _pm MUST appear in goodbye (was set before)
        goodbye_subtypes = tr.all_subtypes(is_goodbye=True)
        assert any(pm_subtype in s for s in goodbye_subtypes), (
            f"_pm subtype missing from goodbye: {goodbye_subtypes}")

        # _pm must NOT appear in re-announcement
        announce_subtypes = tr.all_subtypes(is_goodbye=False)
        assert not any(pm_subtype in s for s in announce_subtypes), (
            f"_pm subtype unexpectedly in re-announcement: {announce_subtypes}")

        self._print_transition_timeline(tr, "pm_disable")

    # ------------------------------------------------------------------
    # SP set (0 → 500)
    # ------------------------------------------------------------------

    def test_transition_sleep_period_set(self, coap, oscore_ctx):
        """SP set from 0 to 500: no goodbye expected (nothing to retract);
        SP=500 appears in re-announcement TXT; SN, AAAA, and gap verified."""
        # Ensure SP starts at 0
        _set_sleep_period(coap, oscore_ctx, 0)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

        def _trigger():
            # POST only — don't wait inside trigger so capture catches the announce
            payload = cbor2.dumps({1: 500})
            resp = coap.oscore_post(oscore_ctx, "/test/sleep-period",
                                    payload=payload, timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST /test/sleep-period sp=500 failed: {resp}")

        tr = _run_transition(self._iface_idx, _trigger)

        # sp=0 → 500: no old TXT to retract, so no goodbye is expected
        assert tr.announces, "[sp_set] No re-announcement packet captured"

        aaaa_new = tr.all_aaaa(is_goodbye=False)
        assert aaaa_new, "[sp_set] No AAAA record in re-announcement"

        # SN unchanged in all announce PTRs
        sn_norm = DUT_SERIAL.lower()
        for p in tr.announces:
            for _owner, target in p.ptr:
                assert sn_norm in target.lower(), (
                    f"[sp_set] SN missing from PTR target '{target}'")

        # SP=500 must appear in the re-announcement TXT
        assert tr.txt_sp(is_goodbye=False) == "500", (
            f"Expected SP=500 in re-announcement, "
            f"got {tr.txt_sp(is_goodbye=False)!r}")

        self._print_transition_timeline(tr, "sp_set")

        # Cleanup
        _set_sleep_period(coap, oscore_ctx, 0)

    # ------------------------------------------------------------------
    # SP clear (500 → 0): standalone TXT goodbye + re-announcement
    # ------------------------------------------------------------------

    def test_transition_sleep_period_clear(self, coap, oscore_ctx):
        """SP cleared from 500 to 0: re-announcement without SP TXT;
        SN and AAAA verified."""
        # Ensure SP starts at 500
        _set_sleep_period(coap, oscore_ctx, 500)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

        def _trigger():
            payload = cbor2.dumps({1: 0})
            resp = coap.oscore_post(oscore_ctx, "/test/sleep-period",
                                    payload=payload, timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST /test/sleep-period sp=0 failed: {resp}")

        tr = _run_transition(self._iface_idx, _trigger,
                             want_goodbye=False)

        assert tr.announces, "[sp_clear] No re-announcement captured"

        announce_aaaa = tr.all_aaaa(is_goodbye=False)
        assert announce_aaaa, "[sp_clear] No AAAA in re-announcement"

        sn_norm = DUT_SERIAL.lower()
        for p in tr.announces:
            for _owner, target in p.ptr:
                assert sn_norm in target.lower(), (
                    f"[sp_clear] SN missing from PTR target '{target}'")

        assert tr.txt_sp(is_goodbye=False) is None, (
            f"[sp_clear] SP should be absent in re-announcement, "
            f"got {tr.txt_sp(is_goodbye=False)!r}")

        self._print_transition_timeline(tr, "sp_clear")


# ===========================================================================
# State-sync tests: client queries mDNS, device acts on its own, client
# re-queries and verifies the advertisement matches the action.
#
# Mental model:
#   client --[mDNS PTR query]-----> DUT responds (read-only observation)
#                  ... DUT internally changes state ...
#                  (test harness CoAP endpoints are thin wrappers that call
#                   the same C functions a real device event would call:
#                   oc_knx_device_restart, knx_dns_sd_set_sleep_period, etc.)
#   client --[mDNS PTR query]-----> DUT responds with new state
#   assert: new response matches expected state after action
# ===========================================================================

class _MdnsSnapshot:
    """Parsed observation of the DUT's current mDNS advertisement.

    Built by _query_snapshot(): fires a raw PTR query to provoke the DUT,
    captures the DUT's multicast response, and extracts all relevant fields.
    """

    def __init__(self):
        self.subtypes: list  = []   # short names, e.g. ["pm", "ia1199887766-1101"]
        self.sp = None               # str value of SP= TXT key, or None
        self.sn_present: bool = False
        self.aaaa: list = []         # IPv6 address strings
        self.port: int = 0           # CoAP port from SRV record, 0 if not seen

    # ------------------------------------------------------------------
    # Derived helpers -- parsed lazily from the ia<IID>-<IA> subtype label
    # ------------------------------------------------------------------

    def _ia_subtype(self):
        """Return the raw 'ia<IID>-<IA>' subtype string, or None."""
        for s in self.subtypes:
            if s.startswith("ia"):
                return s
        return None

    @property
    def ia(self):
        """Individual Address (hex string), e.g. '1101', or None if not present."""
        sub = self._ia_subtype()
        if sub:
            parts = sub[2:].split("-")   # strip 'ia', split on '-'
            return parts[1] if len(parts) == 2 else None
        return None

    @property
    def iid(self):
        """Installation ID (hex string), e.g. '1199887766', or None."""
        sub = self._ia_subtype()
        if sub:
            parts = sub[2:].split("-")
            return parts[0] if len(parts) == 2 else None
        return None

    @property
    def pm(self):
        """True if _pm subtype is advertised (device is in programming mode)."""
        return "pm" in self.subtypes

    def __repr__(self):
        return (f"MdnsSnapshot(subtypes={self.subtypes}, sp={self.sp!r}, "
                f"sn_present={self.sn_present}, aaaa={self.aaaa}, port={self.port})")


def _query_snapshot(iface_idx: int,
                    timeout: float = 2.0) -> "_MdnsSnapshot":
    """Fire a raw PTR query and capture the DUT's full mDNS response.

    Starts a background capture thread (using _parse_mdns_packets) then
    sends a PTR query so the DUT responds.  The response packets are parsed
    into an _MdnsSnapshot with subtypes, SP TXT, SN presence, and AAAA.

    Returns an _MdnsSnapshot (may have empty fields if DUT did not respond).
    """
    import threading

    instance = f"{DUT_SERIAL}.{KNX_SERVICE_TYPE}".lower().rstrip(".")
    captured: list = []

    def _capture():
        captured.extend(_parse_mdns_packets(iface_idx, instance, timeout))

    t = threading.Thread(target=_capture, daemon=True)
    t.start()
    time.sleep(0.15)  # let socket bind before sending query

    # Send a raw PTR query to provoke the DUT to respond
    _raw_mdns_ptr_query(iface_idx, KNX_SERVICE_TYPE, timeout=min(1.0, timeout))

    t.join(timeout + 2)

    snap = _MdnsSnapshot()
    sn_norm = DUT_SERIAL.lower()

    for pkt in captured:
        if not pkt.is_goodbye:
            # Subtype PTR owner names contain "_sub."
            for owner, target in pkt.ptr:
                owner_l = owner.lower()
                if "_sub." in owner_l:
                    # Extract the short label before "._sub."
                    short = owner_l.split("._sub.")[0].lstrip("_")
                    if short not in snap.subtypes:
                        snap.subtypes.append(short)
                if sn_norm in target.lower():
                    snap.sn_present = True

            # AAAA records
            for _owner, addr in pkt.aaaa:
                if addr not in snap.aaaa:
                    snap.aaaa.append(addr)

            # SRV records - capture the CoAP port
            for _owner, port, _host in pkt.srv:
                if snap.port == 0 and port > 0:
                    snap.port = port

            # TXT records - look for SP=
            for _owner, props in pkt.txt.items():
                for k, v in props.items():
                    if k.upper() == b"SP":
                        snap.sp = v.decode("ascii") if v else ""

    return snap


class TestMdnsStateSync:
    """State-sync conformance tests for mDNS advertisements.

    Each test interleaves read-only mDNS queries (client asks the DUT what
    it currently advertises) with device-internal state changes (simulated
    by test harness CoAP endpoints that call the same C functions a real
    device event would call).  Every assertion checks that what the DUT
    advertises on mDNS is consistent with its internal state.
    """

    @pytest.fixture(autouse=True)
    def _require_iface(self):
        iface = os.environ.get("DEVICE_IFACE")
        if not iface:
            pytest.skip("DEVICE_IFACE not set -- raw mDNS capture not possible")
        self._iface_idx = _iface_name_to_index(iface)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _snap(self, label: str, timeout: float = 6.0) -> "_MdnsSnapshot":
        """Query the DUT's current mDNS state and print a summary."""
        snap = _query_snapshot(self._iface_idx, timeout=timeout)
        print(f"[state_sync/{label}] snapshot: subtypes={snap.subtypes}"
              f" sp={snap.sp!r} sn={snap.sn_present} aaaa={snap.aaaa} port={snap.port}")
        return snap

    @staticmethod
    def _print_client_view(label: str, snap: "_MdnsSnapshot") -> None:
        """Print a structured single-line client view: what an mDNS client sees."""
        addr = snap.aaaa[0] if snap.aaaa else "(none)"
        port = snap.port if snap.port else "(none)"
        ia   = snap.ia  or "(none)"
        iid  = snap.iid or "(none)"
        pm   = "ON" if snap.pm else "off"
        sp   = snap.sp if snap.sp is not None else "(none)"
        print(f"[client-view/{label}]  addr=[{addr}]  port={port}  IA=0x{ia}  IID=0x{iid}  PM={pm}  SP={sp}")

    def _transition(self, label: str, trigger_fn,
                    timeout: float = TRANSITION_CAPTURE_TIMEOUT_S,
                    want_goodbye: bool = True) -> TransitionResult:
        """Fire a device-internal state change and capture the mDNS transition."""
        tr = _run_transition(self._iface_idx, trigger_fn,
                             timeout=timeout, want_goodbye=want_goodbye)
        print(f"[state_sync/{label}] transition: goodbyes={len(tr.goodbyes)} announces={len(tr.announces)} gap={tr.gap_s}")
        return tr

    # ------------------------------------------------------------------
    # PM on/off sequence
    # ------------------------------------------------------------------

    def test_state_sync_pm_sequence(self, coap, oscore_ctx):
        """PM state is reflected correctly in mDNS across on/off cycle.

        Sequence:
          1. Query  -> _pm subtype absent  (baseline: PM off)
          2. Action -> device enters programming mode  (PUT /dev/pm true)
          3. Query  -> _pm subtype present
          4. Action -> device leaves programming mode  (PUT /dev/pm false)
          5. Query  -> _pm subtype absent
        """
        pm_subtype = f"_pm._sub.{KNX_SERVICE_TYPE}".lower().rstrip(".")
        pm_short = "pm"

        # Ensure PM starts disabled
        coap.oscore_put(oscore_ctx, "/dev/pm",
                        payload=cbor2.dumps({1: False}), timeout=COAP_TIMEOUT)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

        # --- Step 1: query baseline ---
        snap = self._snap("pm/before")
        assert pm_short not in snap.subtypes, (
            f"[pm_seq] Expected _pm absent before enable, "
            f"got subtypes={snap.subtypes}")

        # --- Step 2: device enters programming mode ---
        def _enable_pm():
            resp = coap.oscore_put(oscore_ctx, "/dev/pm",
                                   payload=cbor2.dumps({1: True}),
                                   timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"PUT /dev/pm=true failed: {resp}")

        tr_on = self._transition("pm/enable", _enable_pm)
        assert tr_on.announces, "[pm_seq] No re-announcement after PM enable"

        # --- Step 3: query after PM on ---
        snap = self._snap("pm/after_enable")
        assert pm_short in snap.subtypes, (
            f"[pm_seq] Expected _pm present after enable, "
            f"got subtypes={snap.subtypes}")

        # --- Step 4: device leaves programming mode ---
        def _disable_pm():
            resp = coap.oscore_put(oscore_ctx, "/dev/pm",
                                   payload=cbor2.dumps({1: False}),
                                   timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"PUT /dev/pm=false failed: {resp}")

        tr_off = self._transition("pm/disable", _disable_pm)
        assert tr_off.announces, "[pm_seq] No re-announcement after PM disable"

        # --- Step 5: query after PM off ---
        snap = self._snap("pm/after_disable")
        assert pm_short not in snap.subtypes, (
            f"[pm_seq] Expected _pm absent after disable, "
            f"got subtypes={snap.subtypes}")

        # Confirm goodbye carried the _pm subtype
        goodbye_subtypes = tr_off.all_subtypes(is_goodbye=True)
        assert any(pm_subtype in s for s in goodbye_subtypes), (
            f"[pm_seq] _pm subtype missing from goodbye: {goodbye_subtypes}")

    # ------------------------------------------------------------------
    # SP set / clear sequence
    # ------------------------------------------------------------------

    def test_state_sync_sleep_period_sequence(self, coap, oscore_ctx):
        """Sleep-period TXT record stays in sync across set / clear cycle.

        Sequence:
          1. Query  -> SP absent  (baseline: SP=0)
          2. Action -> device sets sleep period  (POST /test/sleep-period 300)
          3. Query  -> SP=300 in TXT
          4. Action -> device clears sleep period  (POST /test/sleep-period 0)
          5. Query  -> SP absent
        """
        # Ensure SP starts at 0
        _set_sleep_period(coap, oscore_ctx, 0)

        # --- Step 1: query baseline ---
        snap = self._snap("sp/before")
        assert snap.sp is None, (
            f"[sp_seq] Expected SP absent before set, got sp={snap.sp!r}")

        # --- Step 2: device sets sleep period ---
        def _set_sp():
            resp = coap.oscore_post(oscore_ctx, "/test/sleep-period",
                                    payload=cbor2.dumps({1: 300}),
                                    timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST /test/sleep-period sp=300 failed: {resp}")

        tr_set = self._transition("sp/set", _set_sp, want_goodbye=False)
        assert tr_set.announces, "[sp_seq] No re-announcement after SP set"

        # --- Step 3: query after SP set ---
        snap = self._snap("sp/after_set")
        assert snap.sp == "300", (
            f"[sp_seq] Expected SP=300 after set, got sp={snap.sp!r}")

        # --- Step 4: device clears sleep period ---
        def _clear_sp():
            resp = coap.oscore_post(oscore_ctx, "/test/sleep-period",
                                    payload=cbor2.dumps({1: 0}),
                                    timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST /test/sleep-period sp=0 failed: {resp}")

        tr_clear = self._transition("sp/clear", _clear_sp,
                                    timeout=3.0, want_goodbye=False)
        assert tr_clear.announces, "[sp_seq] No re-announcement after SP clear"

        # --- Step 5: query after SP clear ---
        snap = self._snap("sp/after_clear")
        assert snap.sp is None, (
            f"[sp_seq] Expected SP absent after clear, got sp={snap.sp!r}")

        # Cleanup
        _set_sleep_period(coap, oscore_ctx, 0)

    # ------------------------------------------------------------------
    # Restart: IA preserved (stored), PM cleared (spec mandate)
    # ------------------------------------------------------------------

    def test_state_sync_restart_preserves_state(self, coap, oscore_ctx):
        """IA survives a restart; PM is always cleared by restart (spec).

        POST /.well-known/knx/ia writes IA+IID to persistent storage
        immediately (oc_core_set_and_store_device_ia/iid).  On restart
        oc_knx_device_restart() keeps the in-memory IA/IID as-is (it does
        NOT call oc_knx_load_device) and forces device->pm = false before
        re-registering DNS-SD.

        Sequence:
          1. Action -> device commissioned with new IA/IID  (written to storage)
          2. Action -> device enters programming mode
          3. Query  -> new IA subtype AND _pm both visible before restart
          4. Action -> device restarts  (POST /test/restart)
             wait + refresh OSCORE (SSN resets after restart)
          5. Query  -> new IA subtype still present  (IA in RAM, same as stored)
          6. Query  -> _pm ABSENT  (spec: restart always forces pm=false)
        """
        new_ia  = 0x4D3          # distinct from EITT default
        new_iid = 0x2DFDC1C3E
        new_iid_hex = format(new_iid, "x")
        new_ia_hex  = format(new_ia, "x")
        new_ia_short = f"ia{new_iid_hex}-{new_ia_hex}"

        # --- Step 1: device gets commissioned with new IA/IID ---
        def _set_ia():
            resp = coap.oscore_post(oscore_ctx, "/.well-known/knx/ia",
                                    payload=cbor2.dumps({12: new_ia,
                                                         26: new_iid}),
                                    timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST IA change failed: {resp}")

        self._transition("restart/ia_set", _set_ia)

        # --- Step 2: device enters programming mode ---
        def _enable_pm():
            resp = coap.oscore_put(oscore_ctx, "/dev/pm",
                                   payload=cbor2.dumps({1: True}),
                                   timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"PUT /dev/pm=true failed: {resp}")

        self._transition("restart/pm_enable", _enable_pm)

        # --- Step 3: query -- both IA and PM must be visible ---
        snap = self._snap("restart/before_restart")
        assert new_ia_short in snap.subtypes, (
            f"[restart] Expected new IA subtype '{new_ia_short}' before "
            f"restart, got subtypes={snap.subtypes}")
        assert "pm" in snap.subtypes, (
            f"[restart] Expected _pm before restart, "
            f"got subtypes={snap.subtypes}")

        # --- Step 4: device restarts ---
        def _restart():
            resp = coap.oscore_post(oscore_ctx, "/test/restart",
                                    timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST /test/restart failed: {resp}")

        self._transition("restart/restart", _restart, timeout=20.0)
        time.sleep(2)
        coap.drain_socket(timeout=0.5)
        # After restart the device resets its OSCORE replay table to empty and
        # reloads the SSN from storage (with an osn-delay padding offset).
        # The AT table and keys survive restart.
        #
        # The shared oscore_ctx.ssn may be AHEAD of where the device left off,
        # which is fine — any SSN above the device's replay window is fresh.
        # What we MUST NOT do is reset ssn=0 here, because that can race with
        # CoAP CON retransmits: the device sends an async Echo-challenge for the
        # low SSN, but the client's retransmit arrives first as REPLAY → hard
        # 4.01 with no echo, and the session shared ssn ends up in a bad state
        # for the next test.
        #
        # Instead, send a one-shot probe GET to allow the Echo-challenge cycle
        # to complete cleanly and advance oscore_ctx.ssn past any ECHO zone.
        # The probe result is intentionally not checked — we only care that the
        # replay-table entry is established with a known rx_ssn.
        coap.oscore_get(oscore_ctx, "/dev", timeout=COAP_TIMEOUT)
        coap.drain_socket(timeout=0.5)

        # --- Step 5: query -- new IA must survive restart ---
        snap = self._snap("restart/after_restart_ia")
        assert new_ia_short in snap.subtypes, (
            f"[restart] IA subtype '{new_ia_short}' lost after restart, "
            f"got subtypes={snap.subtypes}")

        # --- Step 6: query -- PM must be CLEARED by restart (spec) ---
        snap = self._snap("restart/after_restart_pm")
        assert "pm" not in snap.subtypes, (
            f"[restart] _pm still present after restart (spec requires PM "
            f"cleared on restart), got subtypes={snap.subtypes}")

        # Cleanup: restore default IA (PM is already false after restart)
        coap.oscore_post(oscore_ctx, "/.well-known/knx/ia",
                         payload=cbor2.dumps({12: DUT_IA, 26: DUT_IID}),
                         timeout=COAP_TIMEOUT)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

    # ------------------------------------------------------------------
    # Factory reset (erase_code=2): IA->0xFFFF, IID->0, PM cleared,
    # SP cleared; SN survives (hardware-fixed)
    # ------------------------------------------------------------------

    def test_state_sync_factory_reset_clears_state(self, coap, oscore_ctx):
        """Factory reset (erase_code=2) resets IA/IID to defaults, clears PM and SP.

        oc_knx_device_storage_reset(2) sets ia=0xFFFF, iid=0, pm=false and
        writes them to storage.  SP is a runtime-only DNS-SD value and is
        not stored, so it is also lost.  SN is hardware-fixed in the binary
        and never changes.

        Sequence:
          1. Action -> device commissioned with non-default IA/IID
          2. Action -> device enters programming mode  (PUT /dev/pm true)
          3. Action -> device sets sleep period  (POST /test/sleep-period 500)
          4. Query  -> new IA subtype, _pm, AND SP=500 all present
          5. Action -> device factory-resets  (POST /test/factory-reset)
             wait + re-provision (AT table wiped by reset)
          6. Query  -> IA subtype reflects reset defaults (ia=0xFFFF, iid=0)
          7. Query  -> _pm absent
          8. Query  -> SP absent
          9. Query  -> DUT_SERIAL still in PTR target  (SN is hardware-fixed)
        """
        # erase_code=2 resets ia->0xFFFF, iid->0
        reset_ia_short  = f"ia{format(0, 'x')}-{format(0xFFFF, 'x')}"

        # --- Step 1: device commissioned with a non-default IA/IID ---
        new_ia  = 0x4D4
        new_iid = 0x2DFDC1C3F
        new_ia_short = f"ia{format(new_iid, 'x')}-{format(new_ia, 'x')}"

        def _set_ia():
            resp = coap.oscore_post(oscore_ctx, "/.well-known/knx/ia",
                                    payload=cbor2.dumps({12: new_ia,
                                                         26: new_iid}),
                                    timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST IA change failed: {resp}")

        self._transition("freset/ia_set", _set_ia)

        # --- Step 2: device enters programming mode ---
        def _enable_pm():
            resp = coap.oscore_put(oscore_ctx, "/dev/pm",
                                   payload=cbor2.dumps({1: True}),
                                   timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"PUT /dev/pm=true failed: {resp}")

        tr = self._transition("freset/pm_enable", _enable_pm)
        assert tr.announces, "[freset] No re-announce after PM enable"

        # --- Step 3: device sets sleep period ---
        def _set_sp():
            resp = coap.oscore_post(oscore_ctx, "/test/sleep-period",
                                    payload=cbor2.dumps({1: 500}),
                                    timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST /test/sleep-period sp=500 failed: {resp}")

        tr = self._transition("freset/sp_set", _set_sp, want_goodbye=False)
        assert tr.announces, "[freset] No re-announce after SP set"

        # --- Step 4: query -- new IA, PM, and SP=500 all visible ---
        snap = self._snap("freset/before_reset")
        assert new_ia_short in snap.subtypes, (
            f"[freset] Expected new IA subtype '{new_ia_short}' before reset, "
            f"got subtypes={snap.subtypes}")
        assert "pm" in snap.subtypes, (
            f"[freset] Expected _pm before reset, got subtypes={snap.subtypes}")
        assert snap.sp == "500", (
            f"[freset] Expected SP=500 before reset, got sp={snap.sp!r}")

        # --- Step 5: device factory-resets ---
        def _factory_reset():
            resp = coap.post("/test/factory-reset", timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST /test/factory-reset failed: {resp}")

        self._transition("freset/reset", _factory_reset, timeout=20.0)
        time.sleep(2)
        coap.drain_socket(timeout=0.5)
        # AT table wiped -- full re-provisioning needed
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)
        # SP is a RAM-only DNS-SD value; knx_dns_sd_clear_advertisement()
        # zeroes it during reset, but stale packets may still be in flight.
        # Explicitly clear SP to force a clean re-announce, then drain and
        # wait so _query_snapshot only captures the fresh post-reset state.
        _set_sleep_period(coap, oscore_ctx, 0)
        coap.drain_socket(timeout=0.5)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

        # --- Step 6: query -- IA subtype must reflect erase_code=2 defaults ---
        # erase_code=2 sets ia=0xFFFF, iid=0 and writes to storage.
        # ia_prepare() above re-sets IA to DUT_IA/DUT_IID for the session,
        # so the subtype seen here reflects the re-commissioned values.
        snap = self._snap("freset/after_reset_ia")
        assert new_ia_short not in snap.subtypes, (
            f"[freset] Old IA subtype '{new_ia_short}' still present after "
            f"factory reset, got subtypes={snap.subtypes}")

        # --- Step 7: query -- _pm must be gone ---
        snap = self._snap("freset/after_reset_pm")
        assert "pm" not in snap.subtypes, (
            f"[freset] _pm still present after factory reset, "
            f"got subtypes={snap.subtypes}")

        # --- Step 8: query -- SP must be gone ---
        snap = self._snap("freset/after_reset_sp")
        assert snap.sp is None, (
            f"[freset] SP still present after factory reset, "
            f"got sp={snap.sp!r}")

        # --- Step 9: query -- SN is hardware-fixed, must survive ---
        snap = self._snap("freset/after_reset_sn")
        assert snap.sn_present, (
            f"[freset] DUT serial number lost after factory reset")

    # ------------------------------------------------------------------
    # Restart address stability: mDNS-discovered endpoint is always
    # reachable after a restart, regardless of whether IPv6/port changed.
    # ------------------------------------------------------------------

    def test_state_sync_restart_address_stability(self, coap, oscore_ctx):
        """mDNS endpoint announced after restart is reachable by a fresh client.

        Key invariant: an mDNS-aware client that re-queries after a device
        restart will NEVER lose connection -- the post-restart announcement
        always points to a valid, reachable CoAP endpoint.

        IPv6 address and port stability are NOT asserted (they may legitimately
        change after a network stack reinit).  What IS asserted is that:

          1. The pre-restart mDNS announcement yields a reachable endpoint
             (plain GET /a/lsm -> 4.03, the spec-correct response to an
             unprotected request on an OSCORE-required resource).
          2. The DUT sends a proper goodbye -> re-announce transition.
          3. The post-restart mDNS announcement yields a reachable endpoint.

        To make the before/after output more informative, a non-default IA is
        provisioned before the restart so the mDNS IA subtype is visible.

        Sequence:
          0. Stage  -> set non-default IA so subtype shows IID/IA before restart
          1. Query  -> capture full client view before restart
          2. Probe  -> plain GET /a/lsm  -> 4.03 (liveness OK)
          3. Action -> device restarts  (POST /test/restart)
          4. Resync -> OSCORE probe-GET
          5. Query  -> capture full client view after restart
          6. Table  -> print before/after side by side
          7. Probe  -> plain GET /a/lsm at new mDNS endpoint  -> 4.03
        """
        # --- Step 0: stage a non-default IA so the mDNS output is informative ---
        staged_ia  = 0xA1B
        staged_iid = 0x11223344AA

        def _set_staged_ia():
            resp = coap.oscore_post(oscore_ctx, "/.well-known/knx/ia",
                                    payload=cbor2.dumps({12: staged_ia,
                                                         26: staged_iid}),
                                    timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST staged IA failed: {resp}")

        self._transition("addr_stab/stage_ia", _set_staged_ia)

        # --- Step 1: capture pre-restart client view ---
        snap_before = self._snap("addr_stab/before")
        assert snap_before.aaaa, (
            "[addr_stab] DUT not advertising any AAAA record before restart")
        assert snap_before.port > 0, (
            "[addr_stab] DUT not advertising any SRV port before restart")

        addr_before = snap_before.aaaa[0]
        port_before = snap_before.port
        self._print_client_view("BEFORE restart", snap_before)

        # --- Step 2: probe reachability before restart ---
        client_before = CoapClient(addr_before, port_before,
                                   timeout=COAP_TIMEOUT)
        try:
            resp_before = client_before.get("/a/lsm", timeout=COAP_TIMEOUT)
            assert resp_before is not None, (
                f"[addr_stab] GET /a/lsm timed out at pre-restart "
                f"[{addr_before}]:{port_before}")
            assert resp_before.code_class == 4 and resp_before.code_detail in (0, 1, 3), (
                f"[addr_stab] Expected 4.xx from /a/lsm before restart, "
                f"got {resp_before.code_class}.{resp_before.code_detail:02d}")
        finally:
            client_before.close()

        print(f"[addr_stab] pre-restart GET /a/lsm -> {resp_before.code_class}.{resp_before.code_detail:02d} (liveness OK)")

        # --- Step 3: trigger restart and capture mDNS transition ---
        def _restart():
            resp = coap.oscore_post(oscore_ctx, "/test/restart",
                                    timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST /test/restart failed: {resp}")

        tr = self._transition("addr_stab/restart", _restart, timeout=20.0)
        assert tr.goodbyes, (
            "[addr_stab] No mDNS goodbye sent before restart")
        assert tr.announces, (
            "[addr_stab] No mDNS re-announcement after restart")

        time.sleep(2)
        coap.drain_socket(timeout=0.5)

        # --- Step 4: resync OSCORE session ---
        coap.oscore_get(oscore_ctx, "/dev", timeout=COAP_TIMEOUT)
        coap.drain_socket(timeout=0.5)

        # --- Step 5: capture post-restart client view ---
        snap_after = self._snap("addr_stab/after")
        assert snap_after.aaaa, (
            "[addr_stab] DUT not advertising any AAAA record after restart")
        assert snap_after.port > 0, (
            "[addr_stab] DUT not advertising any SRV port after restart")

        addr_after = snap_after.aaaa[0]
        port_after = snap_after.port

        # --- Step 6: print before/after table ---
        addr_changed = (addr_after != addr_before)
        port_changed = (port_after != port_before)
        print(f"[addr_stab] {'':=<62}")
        print(f"[addr_stab]  {'Field':<14}  {'BEFORE restart':<28}  {'AFTER restart':<28}")
        print(f"[addr_stab]  {'-'*14}  {'-'*28}  {'-'*28}")
        print(f"[addr_stab]  {'IPv6 addr':<14}  {addr_before:<28}  {addr_after:<28}"
              f"  {'<-- CHANGED' if addr_changed else ''}")
        print(f"[addr_stab]  {'CoAP port':<14}  {port_before:<28}  {port_after:<28}"
              f"  {'<-- CHANGED' if port_changed else ''}")
        print(f"[addr_stab]  {'IID (hex)':<14}  {snap_before.iid or '?':<28}  {snap_after.iid or '?':<28}")
        print(f"[addr_stab]  {'IA  (hex)':<14}  {snap_before.ia  or '?':<28}  {snap_after.ia  or '?':<28}")
        print(f"[addr_stab]  {'PM':<14}  {'ON' if snap_before.pm else 'off':<28}  {'ON' if snap_after.pm else 'off':<28}")
        print(f"[addr_stab]  {'SP':<14}  {snap_before.sp or '(none)':<28}  {snap_after.sp or '(none)':<28}")
        print(f"[addr_stab] {'':=<62}")
        if addr_changed or port_changed:
            print(f"[addr_stab] NOTE: endpoint changed -- client MUST re-read mDNS")
        else:
            print(f"[addr_stab] endpoint unchanged (addr/port stable across restart)")

        # --- Step 7: probe reachability after restart using fresh client ---
        client_after = CoapClient(addr_after, port_after,
                                  timeout=COAP_TIMEOUT)
        try:
            resp_after = client_after.get("/a/lsm", timeout=COAP_TIMEOUT)
            assert resp_after is not None, (
                f"[addr_stab] GET /a/lsm timed out at post-restart "
                f"[{addr_after}]:{port_after} -- mDNS announcement is stale")
            assert resp_after.code_class == 4 and resp_after.code_detail in (0, 1, 3), (
                f"[addr_stab] Expected 4.xx from /a/lsm after restart at "
                f"[{addr_after}]:{port_after}, "
                f"got {resp_after.code_class}.{resp_after.code_detail:02d} "
                f"-- post-restart mDNS endpoint is not reachable or incorrect")
        finally:
            client_after.close()

        print(f"[addr_stab] post-restart GET /a/lsm -> {resp_after.code_class}.{resp_after.code_detail:02d}"
              f" (liveness OK) -- mDNS endpoint is reachable across restart")

    # ------------------------------------------------------------------
    # Factory-reset address stability: mDNS-discovered endpoint is always
    # reachable after a factory reset (erase_code=2), regardless of whether
    # IPv6/port changed.
    # ------------------------------------------------------------------

    def test_state_sync_factory_reset_address_stability(self, coap, oscore_ctx):
        """mDNS endpoint announced after factory reset (erase_code=2) is reachable.

        Identical invariant to test_state_sync_restart_address_stability, but
        the device lifecycle event is a factory reset rather than a plain
        restart.  A factory reset wipes the AT table, so full re-provisioning
        (auth_prepare + ia_prepare) is required before any OSCORE request can
        be sent post-reset.

        To make the before/after output maximally informative, a non-default
        IA, PM=ON, and SP are staged before the reset so all fields are
        populated in the BEFORE column and cleared in the AFTER column.

        Sequence:
          0. Stage  -> non-default IA + PM=ON + SP=750
          1. Query  -> capture full client view before reset
          2. Probe  -> plain GET /a/lsm  -> 4.03 (liveness OK)
          3. Action -> factory reset  (POST /test/factory-reset, erase_code=2)
          4a.Query  -> snapshot immediately post-reset (ia=ffff, iid=0, pm=off, sp=gone)
          4b.Reprov -> auth_prepare + ia_prepare + SP clear (needed for OSCORE probe)
          5. Table  -> print before/after side by side
          6. Probe  -> plain GET /a/lsm at mDNS-announced endpoint  -> 4.03
        """
        # --- Step 0: stage non-default IA, PM=ON, SP=750 ---
        staged_ia  = 0xB2C
        staged_iid = 0xAABBCCDD11

        def _set_staged_ia():
            resp = coap.oscore_post(oscore_ctx, "/.well-known/knx/ia",
                                    payload=cbor2.dumps({12: staged_ia,
                                                         26: staged_iid}),
                                    timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST staged IA failed: {resp}")

        self._transition("addr_stab_freset/stage_ia", _set_staged_ia)

        def _enable_pm():
            resp = coap.oscore_put(oscore_ctx, "/dev/pm",
                                   payload=cbor2.dumps({1: True}),
                                   timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"PUT /dev/pm=true failed: {resp}")

        self._transition("addr_stab_freset/stage_pm", _enable_pm)

        def _set_sp():
            resp = coap.oscore_post(oscore_ctx, "/test/sleep-period",
                                    payload=cbor2.dumps({1: 750}),
                                    timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST /test/sleep-period sp=750 failed: {resp}")

        self._transition("addr_stab_freset/stage_sp", _set_sp, want_goodbye=False)

        # --- Step 1: capture pre-reset client view ---
        snap_before = self._snap("addr_stab_freset/before")
        assert snap_before.aaaa, (
            "[addr_stab_freset] DUT not advertising any AAAA record before reset")
        assert snap_before.port > 0, (
            "[addr_stab_freset] DUT not advertising any SRV port before reset")

        addr_before = snap_before.aaaa[0]
        port_before = snap_before.port
        self._print_client_view("BEFORE factory-reset", snap_before)

        # --- Step 2: probe reachability before reset ---
        client_before = CoapClient(addr_before, port_before,
                                   timeout=COAP_TIMEOUT)
        try:
            resp_before = client_before.get("/a/lsm", timeout=COAP_TIMEOUT)
            assert resp_before is not None, (
                f"[addr_stab_freset] GET /a/lsm timed out at pre-reset "
                f"[{addr_before}]:{port_before}")
            assert resp_before.code_class == 4 and resp_before.code_detail in (0, 1, 3), (
                f"[addr_stab_freset] Expected 4.xx from /a/lsm before reset, "
                f"got {resp_before.code_class}.{resp_before.code_detail:02d}")
        finally:
            client_before.close()

        print(f"[addr_stab_freset] pre-reset GET /a/lsm ->"
              f" {resp_before.code_class}.{resp_before.code_detail:02d} (liveness OK)")

        # --- Step 3: trigger factory reset and capture mDNS transition ---
        def _factory_reset():
            resp = coap.post("/test/factory-reset", timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"POST /test/factory-reset failed: {resp}")

        tr = self._transition("addr_stab_freset/reset", _factory_reset, timeout=20.0)
        assert tr.goodbyes, (
            "[addr_stab_freset] No mDNS goodbye sent before factory reset")
        assert tr.announces, (
            "[addr_stab_freset] No mDNS re-announcement after factory reset")

        time.sleep(2)
        coap.drain_socket(timeout=0.5)

        # --- Step 4a: snapshot BEFORE re-provisioning ---
        # Capture what mDNS announces immediately after the reset, while the
        # device is still in its factory-default state (ia=0xFFFF, iid=0,
        # pm=off, sp=gone).  This is what a real client sees post-reset.
        snap_after = self._snap("addr_stab_freset/after")
        assert snap_after.aaaa, (
            "[addr_stab_freset] DUT not advertising any AAAA record after reset")
        assert snap_after.port > 0, (
            "[addr_stab_freset] DUT not advertising any SRV port after reset")

        addr_after = snap_after.aaaa[0]
        port_after = snap_after.port

        # --- Step 4b: full re-provisioning (needed so OSCORE probe works) ---
        # auth_prepare re-runs SPAKE2+ (AT table was wiped by the reset).
        # ia_prepare re-sets IA/IID so subsequent tests in the class are clean.
        # _set_sleep_period(0) ensures SP does not bleed into later queries.
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)
        _set_sleep_period(coap, oscore_ctx, 0)
        coap.drain_socket(timeout=0.5)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

        # --- Step 5: print before/after table (factory-reset) ---
        addr_changed = (addr_after != addr_before)
        port_changed = (port_after != port_before)
        print(f"[addr_stab_freset] {'':=<62}")
        print(f"[addr_stab_freset]  {'Field':<14}  {'BEFORE factory-reset':<28}  {'AFTER factory-reset':<28}")
        print(f"[addr_stab_freset]  {'-'*14}  {'-'*28}  {'-'*28}")
        print(f"[addr_stab_freset]  {'IPv6 addr':<14}  {addr_before:<28}  {addr_after:<28}"
              f"  {'<-- CHANGED' if addr_changed else ''}")
        print(f"[addr_stab_freset]  {'CoAP port':<14}  {port_before:<28}  {port_after:<28}"
              f"  {'<-- CHANGED' if port_changed else ''}")
        print(f"[addr_stab_freset]  {'IID (hex)':<14}  {snap_before.iid or '?':<28}  {snap_after.iid or '(reset=0)':<28}")
        print(f"[addr_stab_freset]  {'IA  (hex)':<14}  {snap_before.ia  or '?':<28}  {snap_after.ia  or '(reset=ffff)':<28}")
        print(f"[addr_stab_freset]  {'PM':<14}  {'ON' if snap_before.pm else 'off':<28}"
              f"  {'ON' if snap_after.pm else 'off':<28}")
        print(f"[addr_stab_freset]  {'SP':<14}  {snap_before.sp or '(none)':<28}  {snap_after.sp or '(none)':<28}")
        print(f"[addr_stab_freset] {'':=<62}")
        if addr_changed or port_changed:
            print(f"[addr_stab_freset] NOTE: endpoint changed -- client MUST re-read mDNS")
        else:
            print(f"[addr_stab_freset] endpoint unchanged (addr/port stable across factory reset)")

        # --- Step 7: probe reachability after reset using fresh client ---
        client_after = CoapClient(addr_after, port_after,
                                  timeout=COAP_TIMEOUT)
        try:
            resp_after = client_after.get("/a/lsm", timeout=COAP_TIMEOUT)
            assert resp_after is not None, (
                f"[addr_stab_freset] GET /a/lsm timed out at post-reset "
                f"[{addr_after}]:{port_after} -- mDNS announcement is stale")
            assert resp_after.code_class == 4 and resp_after.code_detail in (0, 1, 3), (
                f"[addr_stab_freset] Expected 4.xx from /a/lsm after reset at "
                f"[{addr_after}]:{port_after}, "
                f"got {resp_after.code_class}.{resp_after.code_detail:02d} "
                f"-- post-reset mDNS endpoint is not reachable or incorrect")
        finally:
            client_after.close()

        print(f"[addr_stab_freset] post-reset GET /a/lsm -> {resp_after.code_class}.{resp_after.code_detail:02d}"
              f" (liveness OK) -- mDNS endpoint is reachable across factory reset")

    # ------------------------------------------------------------------
    # LSM unload: mDNS advertisement MUST survive
    # ------------------------------------------------------------------

    def test_state_sync_mdns_alive_in_unloaded(self, coap, oscore_ctx):
        """mDNS keeps advertising when the LSM enters UNLOADED.

        Entering UNLOADED drops the group multicast memberships and deletes
        the group object / group address tables, but it does NOT invalidate
        the device identity: serial number, IA and IID are all unchanged.
        The device must therefore stay discoverable so an ETS-like client can
        re-commission it. Accordingly oc_knx.c does not call knx_dns_sd_stop()
        on this transition.

        Sequence:
          1. Action -> LSM to loaded             (baseline: known-good state)
          2. Query  -> serial and IA subtypes present, AAAA + SRV port present
          3. Action -> LSM unload (POST /a/lsm cmd=4)
          4. Query  -> the very same advertisement is still there
          5. Probe  -> CoAP GET /a/lsm on the advertised endpoint answers
          6. Cleanup -> restore loaded state
        """
        ia_short = f"ia{format(DUT_IID, 'x')}-{format(DUT_IA, 'x')}"

        # --- Step 1: baseline, make sure we start from loaded ---
        # event_to_state[] rejects LOAD_COMPLETE straight from UNLOADED, so the
        # transition to LOADED always needs START_LOADING (1) first.
        set_lsm(coap, oscore_ctx, 1)
        set_lsm(coap, oscore_ctx, 2)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)

        snap_before = self._snap("unloaded/before")
        self._print_client_view("BEFORE unload", snap_before)
        assert DUT_SERIAL in snap_before.subtypes, (
            f"[unloaded] Expected serial subtype '{DUT_SERIAL}' while loaded, "
            f"got subtypes={snap_before.subtypes}")
        assert ia_short in snap_before.subtypes, (
            f"[unloaded] Expected IA subtype '{ia_short}' while loaded, "
            f"got subtypes={snap_before.subtypes}")
        assert snap_before.aaaa, (
            "[unloaded] DUT not advertising any AAAA record while loaded")
        assert snap_before.port > 0, (
            "[unloaded] DUT not advertising any SRV port while loaded")

        # --- Step 3: unload ---
        # want_goodbye=False: no goodbye is expected here. The advertisement is
        # meant to stay untouched, so the capture must not fail if nothing at
        # all is sent on the wire.
        tr = self._transition(
            "unloaded/unload",
            lambda: set_lsm(coap, oscore_ctx, 4),
            timeout=20.0, want_goodbye=False)
        assert not tr.goodbyes, (
            "[unloaded] DUT sent an mDNS goodbye when entering UNLOADED -- the "
            "device identity (sn/ia/iid) is unchanged, so the service must stay "
            f"advertised. Captured {len(tr.goodbyes)} goodbye packet(s).")

        time.sleep(MDNS_ANNOUNCE_WAIT_S)
        coap.drain_socket(timeout=0.5)

        # --- Step 4: the advertisement must be unchanged ---
        snap_after = self._snap("unloaded/after")
        self._print_client_view("AFTER unload", snap_after)
        assert DUT_SERIAL in snap_after.subtypes, (
            f"[unloaded] Serial subtype '{DUT_SERIAL}' disappeared after "
            f"unload, got subtypes={snap_after.subtypes}")
        assert ia_short in snap_after.subtypes, (
            f"[unloaded] IA subtype '{ia_short}' disappeared after unload -- "
            f"IA/IID are not cleared by an unload, got "
            f"subtypes={snap_after.subtypes}")
        assert snap_after.aaaa, (
            "[unloaded] DUT stopped advertising AAAA records in UNLOADED -- "
            "mDNS must keep running")
        assert snap_after.port == snap_before.port, (
            f"[unloaded] Advertised SRV port changed across unload: "
            f"{snap_before.port} -> {snap_after.port}")
        assert snap_after.aaaa[0] == snap_before.aaaa[0], (
            f"[unloaded] Advertised address changed across unload: "
            f"{snap_before.aaaa[0]} -> {snap_after.aaaa[0]}")

        # --- Step 5: the advertised endpoint must actually answer ---
        client = CoapClient(snap_after.aaaa[0], snap_after.port,
                            timeout=COAP_TIMEOUT)
        try:
            resp = client.get("/a/lsm", timeout=COAP_TIMEOUT)
            assert resp is not None, (
                f"[unloaded] GET /a/lsm timed out at the advertised endpoint "
                f"[{snap_after.aaaa[0]}]:{snap_after.port} -- the mDNS record "
                f"is stale while UNLOADED")
        finally:
            client.close()

        print(f"[unloaded] post-unload GET /a/lsm -> "
              f"{resp.code_class}.{resp.code_detail:02d} (liveness OK) -- "
              f"mDNS endpoint is reachable in UNLOADED")

        # --- Step 6: cleanup, back to loaded for the following tests ---
        set_lsm(coap, oscore_ctx, 1)
        set_lsm(coap, oscore_ctx, 2)
        time.sleep(MDNS_ANNOUNCE_WAIT_S)
