"""Decrypt TLS sessions in a capture with a browser or app Key Log File.

Browsers and many apps write TLS session secrets to the file named by
SSLKEYLOGFILE (the NSS key log format). tshark uses those secrets to decrypt the
matching TLS records. This module drives tshark for that and turns each
decrypted conversation into ordinary payloads, so the existing decoders read
the plaintext HTTP, FTP, IMAP and so on.

Decryption needs the key log entries for each session and the handshake in the
same capture, so a connection that was already open before the capture window
cannot be decrypted. The capture is decrypted after the window closes, using
every key line written up to that point.
"""

import os
import re
import shutil
import subprocess

_NODE_LINE = re.compile(r"^Node ([01]): (.+)$")
_DATA_LINE = re.compile(r"^(\t?)([0-9a-fA-F]+)$")
_TIMEOUT = 120


def _endpoint(text: str) -> "tuple | None":
    host, _, port = text.rpartition(":")
    try:
        return host.strip("[]"), int(port)
    except ValueError:
        return None


def parse_follow_raw(text: str) -> tuple:
    """Split one ``follow,tls,raw`` dump into (endpoints, blocks).

    ``endpoints`` maps node 0/1 to (ip, port) from the "Node N:" lines. Each
    block is (node, hex) for one run of decrypted application data. tshark marks
    data from node 1 with a leading tab and leaves node 0 unmarked.
    """
    endpoints: dict = {}
    blocks: list = []
    for line in text.splitlines():
        node = _NODE_LINE.match(line)
        if node:
            ep = _endpoint(node.group(2))
            if ep:
                endpoints[int(node.group(1))] = ep
            continue
        data = _DATA_LINE.match(line)
        if data:
            blocks.append((1 if data.group(1) else 0, data.group(2).lower()))
    return endpoints, blocks


def _run(cmd: list, runner=None):
    run = runner or (lambda c, kwargs: subprocess.run(c, **kwargs))
    return run(cmd, {"capture_output": True, "text": True,
                     "timeout": _TIMEOUT, "check": False})


def _tshark(pcap: str, keylog: str, *extra: str) -> list:
    return ["tshark", "-r", pcap, "-o", "tls.keylog_file:" + keylog, *extra]


def decrypt_pcap(pcap: str, keylog: str, runner=None) -> dict:
    """Decrypt the TLS sessions in ``pcap`` with ``keylog``.

    Returns {"streams", "payloads", "note"}. Each payload is shaped like the
    capture payloads: hex text plus src/dst IP and port, marked
    ``via: tls-keylog``. ``runner`` is injectable so tests never run tshark.
    """
    result = {"tool": "tshark", "streams": 0, "payloads": [], "note": ""}
    if not shutil.which("tshark") and runner is None:
        result["note"] = "tshark not found: install wireshark-cli to decrypt TLS"
        return result
    if not os.path.isfile(keylog) or os.path.getsize(keylog) == 0:
        result["note"] = (f"key log file {keylog} is missing or empty: the browser "
                          "or app must write SSLKEYLOGFILE before the traffic")
        return result

    try:
        listed = _run(_tshark(pcap, keylog, "-Y", "tls", "-T", "fields",
                              "-e", "tls.stream"), runner)
    except (OSError, subprocess.SubprocessError) as exc:
        result["note"] = f"could not run tshark: {exc}"
        return result
    streams = sorted({int(s) for s in (listed.stdout or "").split() if s.isdigit()})
    result["streams"] = len(streams)

    for stream in streams:
        try:
            followed = _run(_tshark(pcap, keylog, "-q", "-z",
                                    f"follow,tls,raw,{stream}"), runner)
        except (OSError, subprocess.SubprocessError):
            continue
        endpoints, blocks = parse_follow_raw(followed.stdout or "")
        for node, data in blocks:
            src, dst = endpoints.get(node), endpoints.get(1 - node)
            if not src or not dst:
                continue
            result["payloads"].append({
                "payload": data, "via": "tls-keylog",
                "src": src[0], "sport": src[1], "dst": dst[0], "dport": dst[1],
            })

    if not streams:
        result["note"] = "no TLS sessions in the capture"
    elif not result["payloads"]:
        result["note"] = ("TLS sessions were found but none decrypted: the key log "
                          "does not cover them, or their handshake was not captured")
    return result
