"""matt.crack -- the optional "crack this now" step.

Takes the credential-bearing findings MATT already decoded and runs ``hashcat``
over them against a wordlist, then maps any recovered plaintext back to the
finding it belongs to (host, user, destination). This is the one place MATT
turns a candidate into an actual password, and it only runs when the operator
asks for it (``--crack`` / the menu).

Standard library only, and it opens no socket. ``hashcat`` is invoked as a
subprocess; nothing is imported from it. Importing this module spawns nothing,
so ``matt.cli`` can import it lazily the moment a crack is requested.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

__all__ = ["have_hashcat", "crackable", "group_by_mode", "parse_outfile", "crack"]

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"


def have_hashcat(which=shutil.which) -> bool:
    """True if a hashcat binary is on PATH."""
    return bool(which("hashcat"))


def crackable(findings) -> list:
    """The findings worth handing to hashcat: those with a real hashcat mode and
    a candidate string. http-basic (mode None) and unknown blobs are skipped --
    there is nothing for hashcat to do with them."""
    out = []
    for f in findings or []:
        if f.get("hashcat_mode") and str(f.get("candidate") or "").strip():
            out.append(f)
    return out


def group_by_mode(findings) -> dict:
    """Map hashcat mode -> list of findings, so one hashcat run covers each mode.
    De-duplicates identical candidates within a mode."""
    groups: dict = {}
    for f in crackable(findings):
        mode = str(f["hashcat_mode"])
        groups.setdefault(mode, [])
        if f["candidate"] not in [g["candidate"] for g in groups[mode]]:
            groups[mode].append(f)
    return groups


def parse_outfile(text: str) -> dict:
    """Parse a hashcat outfile (``hash:plaintext`` per line) into a map keyed by
    the lower-cased hash. hashcat may echo the hash with a different case (it
    upper-cases the NTLM account name), so the key is lower-cased for matching;
    the plaintext is the last ':'-separated field and is kept verbatim."""
    recovered: dict = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        hash_part, plain = line.rsplit(":", 1)
        recovered[hash_part.strip().lower()] = plain
    return recovered


def _default_runner(cmd, timeout):
    """Run hashcat. Returns the CompletedProcess; the outfile it wrote (``-o``)
    is read by crack(). Never raises for a non-zero exit (an exhausted wordlist
    is exit 1, which is normal)."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          check=False)


def crack(findings, wordlist=DEFAULT_WORDLIST, hashcat="hashcat", runner=None,
          timeout=300, tmpdir=None, extra_args=(), optimized=True) -> list:
    """Run hashcat over every crackable finding and return a result per finding.

    Each result is a dict: host, username, target, kind, mode, candidate, and
    ``plaintext`` (the recovered password, or None if the wordlist was
    exhausted or the run timed out). ``runner(cmd, timeout)`` is injectable so
    tests never need a real hashcat; the default runs it for real.

    One hashcat invocation per mode (not per hash), writing to a per-mode
    outfile, so a report with ten NTLMv2 hashes is one run, not ten.
    """
    runner = runner or _default_runner
    items = crackable(findings)
    owns_tmp = tmpdir is None
    tmp = tmpdir or tempfile.mkdtemp(prefix="matt-crack-")
    recovered: dict = {}
    notes: dict = {}

    if optimized and "-O" not in extra_args:
        extra_args = tuple(extra_args) + ("-O",)
    try:
        _crack_into(items, tmp, hashcat, wordlist, runner, timeout, extra_args,
                    recovered, notes)
    finally:
        # Only remove a directory we made ourselves: a caller-supplied tmpdir
        # (tests inject one to inspect the hash/outfiles afterward) is theirs
        # to clean up, not ours. Without this, a long session running --crack
        # repeatedly (the menu's "crack a capture" option, or --watch --crack
        # on a directory of incoming reports) leaves one abandoned
        # "matt-crack-*" directory under /tmp per run, forever.
        if owns_tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    results = []
    for f in items:
        cand = f["candidate"]
        results.append({
            "host": f.get("host"),
            "username": f.get("username"),
            "target": f.get("target"),
            "kind": f.get("kind"),
            "mode": str(f.get("hashcat_mode")),
            "candidate": cand,
            "plaintext": recovered.get(cand.lower()),
            "note": notes.get(cand.lower()),
        })
    return results


def _crack_into(items, tmp, hashcat, wordlist, runner, timeout, extra_args,
                recovered, notes) -> None:
    """The actual hashcat-running loop, factored out of crack() so the
    tmpdir-cleanup in its caller is a single try/finally around one call,
    not duplicated around every early return this loop used to have."""
    for mode, group in group_by_mode(items).items():
        hashfile = os.path.join(tmp, "hashes_%s.txt" % mode)
        outfile = os.path.join(tmp, "cracked_%s.txt" % mode)
        try:
            os.path.exists(outfile) and os.remove(outfile)
        except OSError:
            pass
        with open(hashfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(g["candidate"] for g in group) + "\n")

        base = [hashcat, "-m", mode, "-a", "0", "--potfile-disable", "--quiet",
                "-o", outfile, hashfile, wordlist, *extra_args]

        def _run(cmd):
            try:
                return runner(cmd, timeout), None
            except subprocess.TimeoutExpired:
                return None, "timed out"
            except OSError as exc:
                return None, "hashcat error: %s" % exc

        proc, err = _run(base)
        if err:
            for g in group:
                notes[g["candidate"].lower()] = err
            if err.startswith("hashcat error"):
                continue

        # A weak / low-RAM box (e.g. a 4 GB laptop with only a CPU backend) can
        # fail to allocate the default backend's memory and exit 0 having cracked
        # NOTHING -- which looks exactly like an exhausted wordlist. Detect that
        # from hashcat's own message and retry once pinned to the CPU backend
        # with a small allocation, so cracking actually works on modest hardware.
        out_text = ""
        if proc is not None:
            out_text = (getattr(proc, "stdout", "") or "") + \
                       (getattr(proc, "stderr", "") or "")
        def _is_oom(text):
            return any(s in text for s in (
                "Not enough allocatable device memory",
                "No devices found/left", "Not enough allocatable"))

        # Retry once pinned to the CPU backend, which allocates more modestly.
        if _is_oom(out_text) and "-D" not in base and not _outfile_has_data(outfile):
            proc, err = _run(base + ["-D", "1"])
            if proc is not None:
                out_text = (getattr(proc, "stdout", "") or "") + \
                           (getattr(proc, "stderr", "") or "")

        rc = getattr(proc, "returncode", None)
        if not _outfile_has_data(outfile):
            if _is_oom(out_text):
                # Do NOT let this look like an exhausted wordlist: it is a
                # resource failure, and the honest fix is a bigger box.
                for g in group:
                    notes[g["candidate"].lower()] = (
                        "hashcat ran out of memory on this machine -- crack on a "
                        "host with more RAM or a GPU")
            elif rc not in (None, 0, 1):
                for g in group:
                    notes.setdefault(g["candidate"].lower(),
                                     "hashcat exited %s" % rc)
        try:
            with open(outfile, "r", encoding="utf-8", errors="replace") as fh:
                recovered.update(parse_outfile(fh.read()))
        except OSError:
            pass


def _outfile_has_data(path) -> bool:
    try:
        return os.path.getsize(path) > 0
    except OSError:
        return False
