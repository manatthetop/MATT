"""matt.ui -- the ASCII banner and the interactive menu.

Standard library only, and it opens nothing: it reads /sys/class/net for the
interface list (no socket) and shells out to nothing. Importing it costs the
same as importing ``re``. ``matt.cli`` imports it lazily, only when a terminal
session actually asks for the menu, so a scripted ``--analyze-only`` run never
pays for it.

It opens nothing and it degrades cleanly: on a real terminal it prints the
colour banner and uses red/green accents; piped or captured (a test's StringIO)
every escape code is stripped, so the output is clean plain text.
"""

from __future__ import annotations

import os
import re
import sys

__all__ = ["banner", "render_header", "run_menu", "paint", "color_key",
           "red", "green", "cyan", "yellow", "bold", "dim"]

_HERE = os.path.dirname(os.path.abspath(__file__))
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

# A plain fallback used only if banner.txt is missing for some reason.
_FALLBACK = ("#     #    #    ####### #######\n"
             "##   ##   # #      #       #\n"
             "# # # #  #   #     #       #\n"
             "#  #  # #     #    #       #\n"
             "#     # #######    #       #\n"
             "#     # #     #    #       #\n"
             "#     # #     #    #       #")


def _load_art() -> str:
    """The colour banner (ANSI + block glyphs), read from matt/banner.txt.

    Uses importlib.resources first so it also works when MATT runs from a
    zipapp (.pyz) where the file lives inside the archive; falls back to a plain
    filesystem read, then to a plain-ASCII banner.
    """
    try:
        import importlib.resources as _res
        return (_res.files(__package__).joinpath("banner.txt")
                .read_text(encoding="utf-8").rstrip("\n"))
    except Exception:
        pass
    try:
        with open(os.path.join(_HERE, "banner.txt"), "r", encoding="utf-8") as fh:
            return fh.read().rstrip("\n")
    except OSError:
        return _FALLBACK


_ART = _load_art()
_TAGLINE = "M A N   A T   T H E   T O P"
_SUBTITLE = "authorized MITM credential capture + decode"


# --------------------------------------------------------------------------
# colour -- red/green/cyan/yellow + bold/dim, only on a real terminal
# --------------------------------------------------------------------------

_CODES = {"red": "31", "green": "32", "yellow": "33", "blue": "34",
          "magenta": "35", "cyan": "36", "bold": "1", "dim": "2"}


def _use_style(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def paint(text: str, *styles, stream=None) -> str:
    """Wrap ``text`` in the named styles (e.g. paint(x, "green", "bold")), but
    only when ``stream`` is a real terminal; otherwise return it untouched."""
    stream = stream if stream is not None else sys.stdout
    if not styles or not _use_style(stream):
        return text
    seq = ";".join(_CODES[s] for s in styles if s in _CODES)
    return f"\033[{seq}m{text}\033[0m" if seq else text


def red(text, stream=None):
    return paint(text, "red", stream=stream)


def green(text, stream=None):
    return paint(text, "green", stream=stream)


def cyan(text, stream=None):
    return paint(text, "cyan", stream=stream)


def yellow(text, stream=None):
    return paint(text, "yellow", stream=stream)


def bold(text, stream=None):
    return paint(text, "bold", stream=stream)


def dim(text, stream=None):
    return paint(text, "dim", stream=stream)


# internal aliases kept for the menu code below
def _bold(text, stream):
    return paint(text, "bold", stream=stream)


def _dim(text, stream):
    return paint(text, "dim", stream=stream)


def color_key(stream=None) -> str:
    """A one-line legend for the colours the tool uses."""
    stream = stream or sys.stdout
    return ("  " + paint("key:", "dim", stream=stream) + "  "
            + paint("credential found", "green", "bold", stream=stream) + "   "
            + paint("cracked / network / danger", "red", "bold", stream=stream)
            + "   " + paint("nothing", "dim", stream=stream))


def banner(color: bool = True) -> str:
    """The ASCII banner. ``color=True`` keeps the ANSI colour codes (for a real
    terminal); ``color=False`` strips them to plain glyphs (for a pipe/test)."""
    return _ART if color else _ANSI_RE.sub("", _ART)


def render_header(stream=None) -> str:
    """The colour banner plus tagline and a rule, ready to print.

    On a terminal the banner keeps its colours; piped or captured, every escape
    code is stripped so the output stays clean plain text.
    """
    stream = stream or sys.stdout
    colored = _use_style(stream)
    width = _term_width(stream)
    rule = "-" * min(width, 52)
    art = _ART if colored else _ANSI_RE.sub("", _ART)
    lines = [art, ""]
    lines.append(paint(_TAGLINE, "green", "bold", stream=stream))
    lines.append(paint(_SUBTITLE, "dim", stream=stream))
    lines.append(paint(rule, "dim", stream=stream))
    return "\n".join(lines)


def _term_width(stream) -> int:
    try:
        return max(40, os.get_terminal_size(stream.fileno()).columns)
    except Exception:
        return 60


# --------------------------------------------------------------------------
# the menu
# --------------------------------------------------------------------------

_MENU = [
    ("1", "Analyze a capture file", "offline, no root, zero network, zero tokens"),
    ("2", "Live passive capture", "sniff an interface only -- needs root"),
    ("3", "Live MITM capture", "ARP-poison + sniff -- needs root + authorization"),
    ("4", "Crack a capture with hashcat", "recover plaintext from the findings -- needs hashcat"),
    ("5", "Wi-Fi handshake capture", "scan, auto-tune, deauth + capture -> hashcat 22000 -- needs root"),
    ("6", "About / how it works", ""),
    ("q", "Quit", ""),
]


def run_menu(parser, dispatch, reader=None, writer=None, clear=None) -> int:
    """Drive the interactive menu until the operator quits.

    ``dispatch(argv_list)`` parses an argv list and runs it -- the same entry
    the flags use, so the menu can never drift from the command line. ``reader``
    and ``writer`` are injectable (default: ``input`` / ``print``) so the whole
    loop is testable without a real terminal, and ``clear`` likewise.

    Returns the exit code of the last action, or 0 on a clean quit.
    """
    reader = reader or (lambda prompt="": input(prompt))
    writer = writer or (lambda *a: print(*a))
    out = sys.stdout
    if clear is None:
        clear = lambda: _clear(out)

    accent = {"1": "green", "2": "cyan", "3": "red", "4": "red", "5": "red",
              "6": "cyan", "q": "dim"}
    last_code = 0
    while True:
        clear()
        writer(render_header(out))
        writer("")
        for key, title, hint in _MENU:
            acc = accent.get(key, "cyan")
            keytag = paint(f"[{key}]", acc, "bold", stream=out)
            label = f"  {keytag}  {paint(title, 'bold', stream=out)}"
            writer(label if not hint
                   else f"{label}\n        {paint(hint, 'dim', stream=out)}")
        writer("")
        writer(color_key(out))
        writer("")
        try:
            choice = reader(paint("matt> ", "green", "bold", stream=out)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            writer("")
            return last_code

        if choice in ("q", "quit", "exit", "0"):
            writer(paint("bye.", "dim", stream=out))
            return last_code

        def enter():  # redraw banner so it sits on top of the running action
            clear()
            writer(render_header(out))
            writer("")

        if choice == "1":
            enter()
            last_code = _do_analyze(parser, dispatch, reader, writer, out)
        elif choice == "2":
            enter()
            last_code = _do_live(parser, dispatch, reader, writer, out, poison=False)
        elif choice == "3":
            enter()
            last_code = _do_live(parser, dispatch, reader, writer, out, poison=True)
        elif choice == "4":
            enter()
            last_code = _do_analyze(parser, dispatch, reader, writer, out, crack=True)
        elif choice == "5":
            enter()
            last_code = _do_wpa(parser, dispatch, reader, writer, out)
        elif choice == "6":
            enter()
            _about(writer, out)
        else:
            writer(paint(f"  not a choice: {choice!r}", "red", stream=out))
        _pause(reader, writer)


# --------------------------------------------------------------------------
# menu actions -- each one builds an argv list and hands it to dispatch()
# --------------------------------------------------------------------------

def _do_analyze(parser, dispatch, reader, writer, out, crack: bool = False) -> int:
    reports = _find_reports()
    if reports:
        writer(_dim("  capture reports found near here:", out))
        for i, path in enumerate(reports[:9], 1):
            writer(f"    ({i}) {path}")
    default = reports[0] if reports else "capture_report.json"
    answer = reader(f"  report to analyze [{default}]: ").strip()
    if answer.isdigit() and reports and 1 <= int(answer) <= min(9, len(reports)):
        path = reports[int(answer) - 1]
    else:
        path = answer or default
    argv = ["--analyze-only", path, "--pretty", "--no-banner"]

    do_crack = crack
    if not do_crack:
        do_crack = _yes(reader(paint(
            "  crack the findings with hashcat afterwards? [y/N]: ",
            "red", stream=out)))
    if do_crack:
        argv.append("--crack")
        default_wl = "/usr/share/wordlists/rockyou.txt"
        wl = reader(f"  wordlist [{default_wl}]: ").strip()
        if wl:
            argv += ["--wordlist", wl]
    writer("")
    return dispatch(argv)


def _do_live(parser, dispatch, reader, writer, out, poison: bool) -> int:
    ifaces = _interfaces()
    if ifaces:
        writer(_dim("  interfaces: " + ", ".join(ifaces), out))
    iface = reader("  interface to capture on [wlan0]: ").strip() or "wlan0"
    duration = reader("  seconds to capture [30]: ").strip() or "30"

    argv = ["--iface", iface, "--duration", duration, "--no-banner"]
    if not poison:
        argv.append("--no-poison")
        writer(_dim("  passive capture: nothing is poisoned, sniff only.", out))
    else:
        gateway = reader("  gateway to poison [auto-detect]: ").strip()
        if gateway:
            argv += ["--gateway", gateway]
        writer("")
        writer(paint("  ARP poisoning rewrites other people's traffic.",
                     "red", "bold", stream=out))
        ok = reader(paint("  type YES if you hold written authorization: ",
                          "red", stream=out)).strip()
        if ok != "YES":
            writer(paint("  not confirmed -- nothing was run.", "red", stream=out))
            return 2
    # the gate flag is still required by the engine; the prompt above IS the
    # operator confirming it, so pass it through for both passive and MITM runs.
    argv.append("--i-have-written-authorization")
    if _yes(reader("  dry run first (show what would run)? [y/N]: ")):
        writer("")
        dispatch(argv + ["--dry-run"])
        if not _yes(reader("  proceed for real? [y/N]: ")):
            writer("  stopped.")
            return 0
    writer("")
    return dispatch(argv)


def _do_wpa(parser, dispatch, reader, writer, out) -> int:
    """Menu-driven WPA/WPA2 handshake capture: pick the monitor adapter, scan for
    networks, pick one, and MATT auto-detects its channel, sets monitor mode, and
    runs the deauth + capture -> hashcat 22000. The operator never touches iw."""
    from matt import wifi
    gone = wifi.missing_tools()
    if gone:
        writer(paint("  missing tools: " + ", ".join(gone), "red", stream=out))
        writer(_dim("  install with: sudo apt install aircrack-ng hcxtools iw", out))
        return 2

    ifaces = _interfaces()
    if ifaces:
        writer(_dim("  interfaces: " + ", ".join(ifaces), out))
    # default to a second interface if there is one (the dedicated monitor
    # adapter), else the only one.
    default_if = ifaces[-1] if len(ifaces) > 1 else (ifaces[0] if ifaces else "wlan1")
    iface = reader(f"  monitor-capable adapter [{default_if}]: ").strip() or default_if

    writer(_dim(f"  scanning on {iface} for nearby Wi-Fi networks ...", out))
    try:
        aps = [a for a in wifi.list_aps(iface) if a.get("ssid")]
    except Exception as exc:
        writer(paint(f"  scan failed: {exc}", "red", stream=out))
        return 2
    if not aps:
        writer(paint("  no networks found -- is the adapter in range / powered?",
                     "red", stream=out))
        return 2

    writer("")
    writer(_bold("  #   SSID                       CH    SIGNAL   BSSID", out))
    for i, a in enumerate(aps[:20], 1):
        writer("  %-3d %-26s %-5s %+4s dBm  %s" % (
            i, (a["ssid"] or "<hidden>")[:26], a.get("channel") or "?",
            int(a["signal"]) if a.get("signal") is not None else "?", a["bssid"]))
    writer("")
    pick = reader("  target: pick a number, or type an SSID/BSSID: ").strip()
    target = None
    if pick.isdigit() and 1 <= int(pick) <= len(aps):
        target = aps[int(pick) - 1]
    else:
        for a in aps:
            if pick and (pick.lower() == a["bssid"] or pick == a["ssid"]):
                target = a
                break
    if not target or not target.get("channel"):
        writer(paint("  no usable target selected.", "red", stream=out))
        return 2

    writer(_dim("  target: %s  (BSSID %s, channel %s)"
                % (target["ssid"], target["bssid"], target["channel"]), out))
    client = reader("  client MAC to deauth [broadcast]: ").strip()

    writer("")
    writer(paint("  A deauth briefly knocks a client off this network to force a "
                 "reconnect.", "red", "bold", stream=out))
    ok = reader(paint("  type YES if you own / are authorized to test this network: ",
                      "red", stream=out)).strip()
    if ok != "YES":
        writer(paint("  not confirmed -- nothing was run.", "red", stream=out))
        return 2

    argv = ["--wpa", "--iface", iface, "--bssid", target["bssid"],
            "--channel", str(target["channel"]), "--no-banner",
            "--i-have-written-authorization"]
    if client:
        argv += ["--client", client]
    writer("")
    code = dispatch(argv)
    # offer to crack a captured handshake straight away
    if _yes(reader("  crack the captured handshake now with hashcat? [y/N]: ")):
        writer("")
        dispatch(["--analyze-only", "matt-wpa.22000", "--crack", "--no-banner"])
    return code


def _about(writer, out) -> None:
    writer("")
    for line in (
        paint("MATT -- Man At The Top", "green", "bold", stream=out),
        "",
        "Two stages, and the split is the point:",
        "  stage 1  capture   pull raw bytes off the wire into capture_report.json",
        "  stage 2  analyze   decode those bytes into hashcat-ready candidates +",
        "                     plain-English prose a human can act on",
        "",
        "A default run costs ZERO usage tokens: it is standard-library only and",
        "opens no socket. The optional --use-model stage 2 writer is the one and",
        "only thing that can reach the network, and only when you ask for it.",
        "",
        "It never claims to have cracked a password. It says 'candidate recovered,",
        "hand it to hashcat', because that is what actually happened.",
        "",
        _dim("Only run this against a network you are authorized to test.", out),
    ):
        writer("  " + line if line else "")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def _interfaces() -> list:
    try:
        from matt import capture
        return capture.live_interface_names()
    except Exception:
        return []


def _find_reports() -> list:
    try:
        from matt import capture
        found = capture.find_reports(".")
        # newest first is friendlier in a menu
        return list(reversed(found))
    except Exception:
        return []


def _yes(answer: str) -> bool:
    return answer.strip().lower() in ("y", "yes")


def _clear(stream) -> None:
    if _use_style(stream):
        try:
            stream.write("\033[H\033[2J")
            stream.flush()
        except Exception:
            pass


def _pause(reader, writer) -> None:
    writer("")
    try:
        reader(_dim_plain("  press Enter to return to the menu ... "))
    except (EOFError, KeyboardInterrupt):
        pass


def _dim_plain(text: str) -> str:
    return _dim(text, sys.stdout)
