"""matt.core -- stage 1 decode, stage 2 prose, and the report builders.

STDlib ONLY. Nothing here may import a third-party or HTTP client module, and
nothing here may open a socket. tests/test_core.py asserts both properties, so
a future edit that reaches for ``requests`` or ``urllib.request`` breaks the
build instead of quietly costing the operator tokens on a live engagement.

The decode/crack split is honest, and it matters:

  * A hash is not a password. Stage 1 turns wire bytes into text deterministically
    (NTLM string fields are UTF-16LE, NUL-padded, with a hex fallback for bytes
    that are not text at all). Stage 2 turns a decoded candidate into prose.
  * Neither stage ever claims to have recovered a plaintext. It says
    "candidate recovered, hashcat mode 5600, awaiting offline crack", which is
    what actually happened.

``analyze(report, model=None)`` uses the built-in ``stage2_prose`` writer. It
never calls a model implicitly: pass a callable to get a different writer, pass
nothing to get a free one.
"""

from __future__ import annotations

import base64
import datetime as _datetime
import hashlib
import json
import os
import re

__all__ = [
    "SCHEMA_VERSION",
    "HASHCAT_MODES",
    "SIGNAL_144",
    "HEX_RE",
    "type_hash",
    "identify_hash",
    "reverse_hash",
    "tls_sni",
    "tls_alpn",
    "tls_cert_names",
    "quic_info",
    "HASH_CATALOG",
    "decode_utf16le",
    "decode_field",
    "to_hex",
    "_coerce_bytes",
    "build_ntlmv2",
    "parse_ntlmv2",
    "ntlmv2_username",
    "ntlmv2_target",
    "kerberos_identity",
    "cleartext_credentials",
    "snmpv3_user",
    "candidates_from_payload",
    "extract_candidates",
    "stage2_prose",
    "analyze",
    "write_report",
    "read_report",
    "utc_now",
]

# Bumped when the on-disk capture_report.json shape changes.
SCHEMA_VERSION = "matt-capture/1"

# On this class of box, a python-wrapped tshark dies with 144 (SIGSTKFLT)
# instead of exiting clean. A crashed capture must never be logged as
# "0 credentials found", so both modules share this one constant.
SIGNAL_144 = 144

# name -> hashcat mode. Single source of truth for type_hash().
HASHCAT_MODES = {
    "ntlmv2": "5600",
    "netntlmv1": "5500",
    "wpa-pmkid": "16800",
    "wpa-eh2912": "22000",
    "krb5asrep": "18200",
    "krb5tgs": "13100",
    "krb5pa": "7500",
    "md5": "0",
    "sha1": "100",
    "sha256": "1400",
}

# one hex run, nothing else. Shared with capture.py, which uses it to pick the
# hex body out of a tcpdump/tshark hexdump row.
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HEX_RE = HEX_RE  # internal alias


# --------------------------------------------------------------------------
# time
# --------------------------------------------------------------------------

def utc_now() -> str:
    """ISO-8601 UTC timestamp, second resolution, 'Z' suffix. Stdlib only."""
    return _datetime.datetime.now(_datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# stage 1: deterministic byte decoding
# --------------------------------------------------------------------------

def decode_utf16le(data: bytes) -> "str | None":
    """Decode UTF-16LE to text, or None if ``data`` is not valid UTF-16LE.

    Handles the two things the wire actually does to NTLM string fields:

      * NUL padding -- trailing 0x00 0x00 units are padding, not content, and
        are stripped. A single trailing NUL byte (odd length, UTF-8-ish
        padding) is stripped too.
      * non-text bytes -- surrogate pairs decode via the ``surrogatepass``
        error handler and are dropped, because a lone surrogate is a corrupt
        length field, not a character the operator wants to read.

    Empty input is valid and yields "".
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"decode_utf16le expects bytes, got {type(data).__name__}")
    data = bytes(data)
    if not data:
        return ""
    bom = data[:2] in (b"\xff\xfe", b"\xfe\xff")
    if bom:
        data = data[2:]
    if len(data) % 2:
        if data[-1] != 0:
            return None
        data = data[:-1]
    try:
        text = data.decode("utf-16le", errors="surrogatepass")
    except UnicodeDecodeError:
        return None
    if any("\ud800" <= ch <= "\udfff" for ch in text):
        text = "".join(ch for ch in text if not ("\ud800" <= ch <= "\udfff"))
    text = text.rstrip("\x00")
    # A stray BOM in the middle means the field is not a plain little-endian
    # string: 0x00,0x01 (a length, or an AVP header) decodes as U+FEFF and would
    # otherwise be reported as a username that starts with an invisible
    # character. A leading BOM is different -- that one was real, and is gone.
    if not bom and text.startswith("﻿"):
        return None
    return text


def to_hex(data: bytes) -> str:
    """Lowercase hex of ``data``, prefixed 'hex:' so a reader cannot mistake it
    for decoded text. This is the binary fallback in decode_field."""
    return "hex:" + bytes(data).hex()


def _printable(text: str) -> bool:
    """True if every character is something a human should read off a report.

    Control bytes (below 0x20 and 0x7f-0x9f) are what a length field or an AVP
    header looks like when a binary blob happens to be valid text encoding. If
    a field is mostly those, it is not a username, it is bytes, and it goes to
    hex where the operator can actually use it.
    """
    if not text.strip():
        return False
    return all(
        ch.isprintable() or ch in "\t\n\r "
        for ch in text
        if ord(ch) < 0xa0 or ord(ch) > 0xac  # keep NBSP and soft hyphen readable
    )


def decode_field(data: bytes) -> "tuple[str, str]":
    """Decode one captured field to printable text.

    Returns ``(method, text)`` where method is one of:

      "utf-16le"  valid UTF-16LE text
      "utf-8"     valid UTF-8 / ASCII text
      "empty"     nothing in the field but padding
      "hex"       not text at all -- binary, returned as ``hex:<...>``

    UTF-16LE is tried first because that is what NTLMSSP uses for the fields
    that carry usernames and SPNs, but a candidate is only accepted as text if
    it is actually printable. An 0xFF byte is illegal UTF-16LE and illegal
    UTF-8, so it lands in hex, which is where a hash or an AVP blob belongs.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"decode_field expects bytes, got {type(data).__name__}")
    data = bytes(data)
    if not data or not data.strip(b"\x00"):
        return "empty", ""

    utf16 = None
    if len(data) % 2 == 0:
        text = decode_utf16le(data)
        if text and _printable(text):
            utf16 = ("utf-16le", text)

    utf8 = None
    try:
        text = data.decode("utf-8").rstrip("\x00")
    except UnicodeDecodeError:
        text = None
    if text is not None and _printable(text):
        utf8 = ("utf-8", text)

    if utf8 and utf16:
        # Both codecs read this field as the same ASCII text, which is genuinely
        # ambiguous. What breaks the tie is the NUL interleaving, not the
        # printable characters: "a\x00l\x00" is UTF-16LE, "alice\r\n" is UTF-8,
        # and a CRLF from an HTTP header is only an odd-length accident. So the
        # test is whether every other byte of an even-length prefix is NUL.
        prefix = data[:2 * len(utf16[1])]
        if len(data) % 2 == 0 and not prefix[1::2].strip(b"\x00"):
            return utf16
        return utf8
    return utf16 or utf8 or ("hex", to_hex(data))


# --------------------------------------------------------------------------
# hash typing
# --------------------------------------------------------------------------

def _looks_like_hex(data: bytes) -> bool:
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return False
    return bool(text) and len(text) % 2 == 0 and bool(_HEX_RE.match(text))


def _hex_payload_len(data: bytes) -> int:
    """Byte length a hex payload represents (half its char length)."""
    return len(data.strip()) // 2


def _ntlmv2_shape(payload: bytes) -> bool:
    """hashcat 5600 shape: USER::DOMAIN:SRVCHALLENGE:NTPROOF:BLOB.

    This is the exact field order ``hashcat -m 5600`` reads: an 8-byte server
    challenge, then the 16-byte NTProofStr, then the blob. The '::' anchors the
    split so a UPN that itself contains ':' stays in the username.
    """
    head, sep, tail = payload.partition(b"::")
    if not sep:
        return False
    after = tail.split(b":")
    if len(after) != 4:
        return False
    _realm, challenge, responsor, blob = after
    return (
        _looks_like_hex(challenge)
        and _looks_like_hex(responsor)
        and _looks_like_hex(blob)
        and _hex_payload_len(challenge) == 8
        and _hex_payload_len(responsor) == 16
        and _hex_payload_len(blob) >= 1
    )


def type_hash(payload) -> "tuple[str, str | None]":
    """Classify a captured credential payload.

    Returns ``(name, hashcat_mode)``:

        ntlmv2       5600
        netntlmv1    5500
        wpa-pmkid    16800
        wpa-eh2912   22000
        md5          0
        sha1         100
        sha256       1400
        unknown      None

    Never raises and never guesses a mode: an unrecognised blob comes back
    ``("unknown", None)`` so the caller cannot hand hashcat a mode that does
    not exist. Specific formats are tested before bare digest lengths, so a
    real NetNTLM v1 candidate is never mislabelled just because some slice of
    it happens to look like 32 hex digits.
    """
    if isinstance(payload, (bytes, bytearray)):
        raw = bytes(payload)
    elif isinstance(payload, str):
        raw = payload.encode("utf-8", "surrogateescape")
    elif payload is None:
        return ("unknown", None)
    else:
        raise TypeError(f"type_hash expects str or bytes, got {type(payload).__name__}")

    raw = raw.strip()
    if not raw:
        return ("unknown", None)

    # -- 802.11 WPA PMKID, hashcat 16800 ------------------------------------------
    #   <SSID><anonce-part>*<bssid>*<mac_ap>*<mac_cli>*<message>
    # '*' delimited, exactly like 22000, which is why these two are tested as a
    # pair: the 5th field is the discriminator. A PMKID sweep yields a
    # truncated 64-byte message; a real message-A carries a >= 68-byte EAPOL
    # frame. Calling a 64-byte blob a full handshake would tell the operator he
    # has four-way handshake material he does not have.
    if raw.count(b"*") == 4:
        parts = raw.split(b"*")
        if (
            _looks_like_hex(parts[1])
            and _looks_like_hex(parts[2])
            and _looks_like_hex(parts[3])
            and _looks_like_hex(parts[4])
            and _hex_payload_len(parts[1]) == 6
            and _hex_payload_len(parts[2]) == 6
            and _hex_payload_len(parts[3]) == 6
            and _looks_like_hex(parts[0][-32:])
        ):
            return ("wpa-pmkid", HASHCAT_MODES["wpa-pmkid"])

    # -- 802.11 WPA PMKID, hashcat 16800, canonical hcxtools form ----------------
    #   PMKID*MAC_AP*MAC_STA*ESSID      (exactly 3 '*' separators)
    # This is the line hcxpcapngtool emits and hashcat -m 16800 reads. The
    # 5-field variant checked above is MATT's own harvester shape; this one is
    # what an operator actually pastes in from a PMKID sweep, so a real capture
    # is classified instead of falling through to "unknown".
    if raw.count(b"*") == 3:
        parts = raw.split(b"*")
        if (
            _looks_like_hex(parts[0]) and _hex_payload_len(parts[0]) == 16
            and _looks_like_hex(parts[1]) and _hex_payload_len(parts[1]) == 6
            and _looks_like_hex(parts[2]) and _hex_payload_len(parts[2]) == 6
            and _looks_like_hex(parts[3]) and _hex_payload_len(parts[3]) >= 1
        ):
            return ("wpa-pmkid", HASHCAT_MODES["wpa-pmkid"])

    # -- 802.11 WPA2/3 handshake, hashcat 22000 (WPA-PBKDF2-PMKID+EAPOL) ----------
    #   <SSID><AP-nonce-part>*<bssid>*<mac_ap>*<mac_cli>*<S-nonce-part>*<EAPOL>
    if raw.count(b"*") == 5:
        parts = raw.split(b"*")
        if (
            _looks_like_hex(parts[1])
            and _looks_like_hex(parts[2])
            and _hex_payload_len(parts[1]) == 6
            and _hex_payload_len(parts[2]) == 6
            and _looks_like_hex(parts[5])
            and _hex_payload_len(parts[5]) >= 68
        ):
            return ("wpa-eh2912", HASHCAT_MODES["wpa-eh2912"])

    # -- NetNTLM v2, hashcat 5600 -------------------------------------------------
    if _ntlmv2_shape(raw):
        return ("ntlmv2", HASHCAT_MODES["ntlmv2"])

    # -- NetNTLM v1, hashcat 5500 -------------------------------------------------
    #   USER::DOMAIN:LM:NT:SERVERCHALLENGE. v1 emits a fixed 16-byte (32 hex)
    #   response with no appended blob, which is what separates it from 5600.
    if raw.count(b":") == 5:
        parts = raw.split(b":")
        lm, nt, server = parts[3], parts[4], parts[5]
        if (
            _looks_like_hex(lm)
            and _looks_like_hex(nt)
            and _looks_like_hex(server)
            and _hex_payload_len(lm) in (8, 16, 21)
            and _hex_payload_len(nt) == 16
            and _hex_payload_len(server) == 8
        ):
            return ("netntlmv1", HASHCAT_MODES["netntlmv1"])

    # -- Kerberos roasting: AS-REP (hashcat 18200) and TGS-REP (13100) ------------
    #   $krb5asrep$23$user@REALM:checksum$edata      (pre-auth disabled)
    #   $krb5tgs$23$*user$realm$spn*$checksum$edata   (kerberoast)
    # Both are '$'-tagged containers with a trailing hex digest; the tag is the
    # discriminator, so a real roast is classified instead of falling through.
    if raw.startswith(b"$krb5asrep$"):
        return ("krb5asrep", HASHCAT_MODES["krb5asrep"])
    if raw.startswith(b"$krb5tgs$"):
        return ("krb5tgs", HASHCAT_MODES["krb5tgs"])
    if raw.startswith(b"$krb5pa$"):
        return ("krb5pa", HASHCAT_MODES["krb5pa"])

    # -- salted containers ($krb5tgs$, $krb5asrep$) carry their digest in $[1] ----
    body = raw.split(b"$")[1] if raw.startswith(b"$") else raw

    # -- bare digests -------------------------------------------------------------
    if _looks_like_hex(body):
        n = _hex_payload_len(body)
        if n == 16:
            return ("md5", HASHCAT_MODES["md5"])
        if n == 20:
            return ("sha1", HASHCAT_MODES["sha1"])
        if n == 32:
            return ("sha256", HASHCAT_MODES["sha256"])

    return ("unknown", None)


# --------------------------------------------------------------------------
# hash identification ("what is this hash") and common-hash reversal
# --------------------------------------------------------------------------

# Prefix-tagged formats, checked first. (prefixes, name, hashcat mode). Covers
# the password-hashing / modular-crypt / tool formats across the catalog.
_IDENT_PREFIXES = [
    (("$argon2id$",), "Argon2id", "34000"),
    (("$argon2i$",), "Argon2i", None),
    (("$argon2d$",), "Argon2d", None),
    (("$2a$", "$2b$", "$2y$", "$2x$"), "bcrypt (Blowfish)", "3200"),
    (("$2$",), "bcrypt (old)", "3200"),
    (("$scrypt$", "scrypt:", "SCRYPT:"), "scrypt", "8900"),
    (("$7$",), "scrypt (unix)", "8900"),
    (("$y$", "$gy$"), "yescrypt", None),
    (("$1$",), "md5crypt (Unix MD5)", "500"),
    (("$apr1$",), "Apache apr1-md5", "1600"),
    (("$5$",), "sha256crypt (Unix)", "7400"),
    (("$6$",), "sha512crypt (Unix)", "1800"),
    (("$sha1$",), "sha1crypt", "15100"),
    (("$md5$",), "Cisco-IOS / Sun md5crypt", "500"),
    (("$P$", "$H$"), "phpass (WordPress / phpBB)", "400"),
    (("$S$",), "Drupal 7 (SHA-512/phpass)", "7900"),
    (("pbkdf2_sha256$",), "Django PBKDF2-SHA256", "10000"),
    (("pbkdf2_sha1$",), "Django PBKDF2-SHA1", "12001"),
    (("pbkdf2-sha256$",), "PBKDF2-HMAC-SHA256", "10900"),
    (("pbkdf2-sha512$",), "PBKDF2-HMAC-SHA512", "12100"),
    (("pbkdf2-sha1$", "$pbkdf2$"), "PBKDF2-HMAC-SHA1", "12000"),
    (("sha256:", "PBKDF2$"), "PBKDF2 (generic)", None),
    (("$ml$",), "macOS 10.8+ PBKDF2-SHA512", "7100"),
    (("$cram_md5$",), "CRAM-MD5", "16500"),
    (("{SSHA}",), "LDAP {SSHA} (salted SHA-1)", "111"),
    (("{SHA}",), "LDAP {SHA}", "101"),
    (("{SSHA256}",), "LDAP {SSHA256}", "1411"),
    (("{SSHA512}",), "LDAP {SSHA512}", "1711"),
    (("{SMD5}",), "LDAP {SMD5}", "6300"),
    (("{MD5}",), "LDAP {MD5}", "90"),
    (("{CRYPT}",), "LDAP {CRYPT}", None),
    (("{x-issha,",), "AIX ssha", "6700"),
    (("$krb5asrep$",), "Kerberos 5 AS-REP", "18200"),
    (("$krb5tgs$",), "Kerberos 5 TGS-REP (kerberoast)", "13100"),
    (("$krb5pa$",), "Kerberos 5 AS-REQ pre-auth", "7500"),
    (("$DCC2$", "$DCC2$10240#"), "Domain Cached Credentials 2 (mscash2)", "2100"),
    (("M$",), "Domain Cached Credentials (mscash)", "1100"),
    (("$NT$",), "NTLM", "1000"),
    (("$sip$",), "SIP digest auth (MD5)", "11400"),
    (("$netntlmv2$",), "NetNTLMv2", "5600"),
    (("$racf$",), "RACF", "8500"),
    (("$office$",), "MS Office 2007-2016", "9400"),
    (("$oldoffice$",), "MS Office <= 2003", "9700"),
    (("$pdf$",), "PDF", "10500"),
    (("$zip2$",), "WinZip", "13600"),
    (("$rar5$",), "RAR5", "13000"),
    (("$7z$",), "7-Zip", "11600"),
    (("$bitcoin$",), "Bitcoin/Litecoin wallet.dat", "11300"),
    (("$ethereum$",), "Ethereum wallet", "15700"),
    (("$keepass$",), "KeePass", "13400"),
    (("$1password$",), "1Password", "6600"),
    (("$electrum$",), "Electrum wallet", "16600"),
    (("$dpapimk$",), "DPAPI masterkey", "15300"),
    (("$mysqlna$",), "MySQL CRAM (SHA1)", "11200"),
    (("$postgres$",), "PostgreSQL CRAM (MD5)", "11100"),
    (("$cisco$", "$8$"), "Cisco IOS PBKDF2-SHA256 (type 8)", "9200"),
    (("$9$",), "Cisco IOS scrypt (type 9)", "9300"),
    (("$SNMPv3$",), "SNMPv3 HMAC", "25100"),
    (("$WPA$", "WPA*"), "WPA/WPA2 (hcx 22000)", "22000"),
    (("sha1$",), "Django SHA-1", "124"),
]

# Bare-hex formats by hex length. Many algorithms share a length, so this lists
# all plausible ones (crackable/cryptographic first, then non-crypto) -- the
# honest answer for a bare digest. Modes are hashcat modes where one exists.
_IDENT_BY_HEXLEN = {
    8: [("CRC-32", None), ("CRC-32C", None), ("Adler-32", None),
        ("FNV-1/FNV-1a (32)", None), ("MurmurHash3 (32)", None),
        ("xxHash32", None), ("Jenkins/lookup3", None), ("djb2 / sdbm", None)],
    16: [("MySQL323", "200"), ("CRC-64", None), ("xxHash64", None),
         ("FNV-1a (64)", None), ("SipHash-2-4", None), ("MurmurHash (64)", None),
         ("DES (half LM)", "3000")],
    24: [("CRC-96", None)],
    32: [("MD5", "0"), ("NTLM", "1000"), ("MD4", "900"), ("LM", "3000"),
         ("MD2", None), ("MD6-128", None), ("RIPEMD-128", None),
         ("HAVAL-128", None), ("Snefru-128", None), ("Tiger-128", None),
         ("MurmurHash3 x64 (128)", None), ("Double MD5", "2600"),
         ("RAdmin v2", "9900"), ("Domain Cached Credentials", "1100"),
         ("Skein-256(128)", None), ("Lotus Notes/Domino 5", "8600")],
    40: [("SHA-1", "100"), ("SHA-0", None), ("RIPEMD-160", "6000"),
         ("HAS-160", None), ("Tiger-160", None), ("HAVAL-160", None),
         ("MySQL4.1/5+ (SHA1(SHA1))", "300"), ("BLAKE-160", None)],
    48: [("Tiger-192", None), ("HAVAL-192", None), ("SHA-192", None)],
    56: [("SHA-224", "sha224"), ("SHA3-224", "17300"), ("SHA-512/224", None),
         ("Keccak-224", None), ("HAVAL-224", None), ("BLAKE-224", None)],
    64: [("SHA-256", "1400"), ("SHA3-256", "17400"), ("SHA-512/256", None),
         ("Keccak-256", "17800"), ("RIPEMD-256", None), ("BLAKE2s-256", None),
         ("GOST R 34.11-94", "6900"), ("Streebog-256", "11700"),
         ("SM3", None), ("Snefru-256", None), ("HAVAL-256", None),
         ("Skein-256", None), ("Grostl-256", None), ("Ascon-Hash", None)],
    80: [("RIPEMD-320", None)],
    96: [("SHA-384", "10800"), ("SHA3-384", "17500"), ("Keccak-384", None),
         ("SHA-512/384", None)],
    128: [("SHA-512", "1700"), ("SHA3-512", "17600"), ("Whirlpool", "6100"),
          ("BLAKE2b-512", "600"), ("Streebog-512", "11800"),
          ("Keccak-512", None), ("Skein-512", None), ("Grostl-512", None),
          ("JH-512", None), ("RIPEMD/BLAKE-512", None)],
}

# Non-cryptographic / checksum / perceptual families MATT recognizes by name,
# so `--identify` can say what a value *is* even when it is not a crackable
# password hash. (These are not length-identifiable on their own.)
HASH_CATALOG = {
    "cryptographic": ["SHA-0", "SHA-1", "SHA-224", "SHA-256", "SHA-384",
        "SHA-512", "SHA-512/224", "SHA-512/256", "SHA3-224/256/384/512",
        "SHAKE128/256", "Keccak", "KangarooTwelve", "MD2", "MD4", "MD5", "MD6",
        "BLAKE/BLAKE2b/BLAKE2s/BLAKE3", "RIPEMD-128/160/256/320", "Whirlpool",
        "Tiger/Tiger2", "HAVAL", "Snefru", "GOST", "Streebog", "SM3", "LSH",
        "HAS-160", "Skein", "Grostl", "JH", "Ascon-Hash", "Xoodyak"],
    "password_kdf": ["Argon2d/i/id", "bcrypt", "scrypt", "PBKDF2", "yescrypt",
        "Balloon", "Catena", "Lyra2", "Makwa", "DES-crypt", "MD5-crypt",
        "SHA-256-crypt", "SHA-512-crypt", "apr1", "phpass", "Django PBKDF2",
        "Drupal SHA-512", "NTLM", "LM"],
    "mac": ["HMAC", "KMAC", "CMAC/OMAC", "GMAC", "PMAC", "Poly1305", "UMAC",
        "VMAC", "SipHash", "BLAKE2/BLAKE3 keyed"],
    "non_crypto": ["MurmurHash1/2/3", "xxHash (XXH32/64/XXH3/XXH128)",
        "CityHash", "FarmHash", "MetroHash", "SpookyHash", "HighwayHash",
        "wyhash", "rapidhash", "t1ha", "komihash", "MeowHash", "SeaHash",
        "FNV-0/1/1a", "djb2", "sdbm", "Jenkins (OAAT/lookup2/lookup3)",
        "SuperFastHash", "Pearson", "PJW/ELF", "Rabin-Karp", "BuzHash"],
    "checksum": ["CRC-8/16/32/32C/64", "Adler-32", "Fletcher-16/32/64",
        "Internet checksum", "BSD/SysV sum", "Luhn", "Verhoeff", "Damm",
        "ISBN", "IBAN mod-97"],
    "perceptual_fuzzy": ["pHash/dHash/aHash/wHash", "PhotoDNA", "NeuralHash",
        "Chromaprint", "MinHash", "SimHash", "LSH", "ssdeep (CTPH)", "TLSH",
        "sdhash", "nilsimsa"],
    "structural": ["Geohash", "Zobrist", "Merkle trees / hash chains",
        "Bloom / Count-Min", "Cuckoo/hopscotch/Robin Hood", "Perfect (CHD/BDZ/FKS)",
        "Consistent / Rendezvous (HRW)", "Jump / Maglev", "Multihash"],
}


def identify_hash(value) -> list:
    """Best-effort "what kind of hash is this?" -- a hashid-style identifier that
    returns a list of (name, hashcat_mode) candidates by prefix and length.

    This is deliberately broad (a bare 32-hex string really could be MD5, NTLM,
    MD4, LM, ...), so it is for recon and `--identify`. The strict classifier
    used on captured candidates is type_hash(); this is "knows all the hash
    functions", that is "knows which one to crack".
    """
    if isinstance(value, (bytes, bytearray)):
        s = bytes(value).decode("latin-1", "replace")
    else:
        s = str(value or "")
    s = s.strip()
    if not s:
        return []
    # MySQL 4.1+ prints PASSWORD() as '*' + 40 hex (SHA1(SHA1(pw))). hashcat -m
    # 300 wants the hash without the star, but people paste the stored form, so
    # recognize it here (the bare 40-hex form is covered by the length table).
    if re.fullmatch(r"\*[0-9A-Fa-f]{40}", s):
        return [("MySQL4.1/5+ (SHA1(SHA1))", "300")]
    # Modular-crypt tags are case-sensitive ($P$ phpass vs $p$), so match the
    # original string, not a lower-cased copy.
    for prefixes, name, mode in _IDENT_PREFIXES:
        if any(s.startswith(p) for p in prefixes):
            return [(name, mode)]
    # '*'/'$'-delimited composite formats keep their own classifier
    kind, mode = type_hash(s)
    if kind not in ("unknown", "md5", "sha1", "sha256"):
        return [(kind, mode)]
    if _HEX_RE.match(s) and len(s) % 2 == 0:
        return list(_IDENT_BY_HEXLEN.get(len(s), []))
    return []


# The most common passwords, hashed four ways, as a tiny built-in rainbow table.
# This reverses a weak unsalted hash instantly, offline, with no brute force --
# the right first move before spinning up hashcat.
_COMMON_PASSWORDS = (
    "123456 123456789 qwerty password 12345678 111111 1234567 12345 123123 "
    "1234567890 admin abc123 qwerty123 1q2w3e password1 123321 welcome 666666 "
    "letmein monkey dragon master superman football iloveyou sunshine princess "
    "root toor changeme secret pass passw0rd P@ssw0rd Password1 Welcome1 "
    "qazwsx trustno1 whatever starwars hello access shadow 000000 zaq12wsx "
    "google 1q2w3e4r 1qaz2wsx admin123 test test123 guest oracle "
    "Summer2026! Winter2026! Autumn2026! Spring2026 Flawless#2026"
).split()


def _md4(data: bytes) -> bytes:
    """MD4 digest. Uses OpenSSL when it offers md4, else a pure-Python fallback
    (RFC 1320) -- OpenSSL 3 disables md4 by default, and NTLM = MD4(UTF-16LE),
    so MATT must not depend on the platform having the legacy provider."""
    try:
        return hashlib.new("md4", data).digest()
    except (ValueError, TypeError):
        pass
    import struct
    mask = 0xFFFFFFFF

    def lrot(x, n):
        return ((x << n) | (x >> (32 - n))) & mask

    msg = bytearray(data)
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d
        for k in range(0, 16, 4):          # round 1 (F), shifts 3,7,11,19
            a = lrot((a + ((b & c) | (~b & d)) + x[k]) & mask, 3)
            d = lrot((d + ((a & b) | (~a & c)) + x[k + 1]) & mask, 7)
            c = lrot((c + ((d & a) | (~d & b)) + x[k + 2]) & mask, 11)
            b = lrot((b + ((c & d) | (~c & a)) + x[k + 3]) & mask, 19)
        for k in range(4):                 # round 2 (G), +5a827999, shifts 3,5,9,13
            a = lrot((a + ((b & c) | (b & d) | (c & d)) + x[k] + 0x5A827999) & mask, 3)
            d = lrot((d + ((a & b) | (a & c) | (b & c)) + x[k + 4] + 0x5A827999) & mask, 5)
            c = lrot((c + ((d & a) | (d & b) | (a & b)) + x[k + 8] + 0x5A827999) & mask, 9)
            b = lrot((b + ((c & d) | (c & a) | (d & a)) + x[k + 12] + 0x5A827999) & mask, 13)
        order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for k in range(0, 16, 4):          # round 3 (H), +6ed9eba1, shifts 3,9,11,15
            a = lrot((a + (b ^ c ^ d) + x[order[k]] + 0x6ED9EBA1) & mask, 3)
            d = lrot((d + (a ^ b ^ c) + x[order[k + 1]] + 0x6ED9EBA1) & mask, 9)
            c = lrot((c + (d ^ a ^ b) + x[order[k + 2]] + 0x6ED9EBA1) & mask, 11)
            b = lrot((b + (c ^ d ^ a) + x[order[k + 3]] + 0x6ED9EBA1) & mask, 15)
        a = (a + aa) & mask
        b = (b + bb) & mask
        c = (c + cc) & mask
        d = (d + dd) & mask
    return struct.pack("<4I", a, b, c, d)


def _common_hash_table() -> dict:
    table = {}
    for pw in _COMMON_PASSWORDS:
        b = pw.encode("utf-8")
        for algo in ("md5", "sha1", "sha256"):
            table[hashlib.new(algo, b).hexdigest()] = pw
        table[_md4(pw.encode("utf-16le")).hex()] = pw  # NTLM = MD4(UTF-16LE)
    return table


_COMMON_HASHES = None


def reverse_hash(value) -> "str | None":
    """Reverse a bare unsalted hash (MD5, SHA-1, SHA-256, or NTLM) when it is the
    hash of one of the most common passwords -- a tiny built-in rainbow table,
    instant, offline, no brute force. Returns the plaintext, or None.

    Hashes are one-way, so this is a lookup, not true inversion: it only works
    for weak/common passwords. That is exactly where it saves the most time.
    """
    global _COMMON_HASHES
    if _COMMON_HASHES is None:
        _COMMON_HASHES = _common_hash_table()
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("latin-1", "replace")
    if not isinstance(value, str):
        return None
    return _COMMON_HASHES.get(value.strip().lower())


# --------------------------------------------------------------------------
# NTLMv2 build / parse  (hashcat 5600 form)
# --------------------------------------------------------------------------

def build_ntlmv2(username: str, realm: str, authenticator: bytes, response: bytes,
                 challenge: bytes) -> str:
    """Assemble a hashcat 5600 candidate string.

        USERNAME::REALM:CHALLENGE:RESPONSOR:AUTHENTICATOR

    This is the exact field order ``hashcat -m 5600`` expects: the 8-byte server
    ``challenge`` first, then the 16-byte NTProofStr ``response``, then the
    ``authenticator`` blob (client challenge + timestamp + avpairs). Everything
    after the realm is lowercase hex. (Earlier versions emitted response before
    challenge, which hashcat rejected with a token-length error -- so the hash
    MATT wrote could not actually be cracked. This order fixes that.)
    """
    for name, value in (
        ("authenticator", authenticator),
        ("response", response),
        ("challenge", challenge),
    ):
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
    if len(challenge) != 8:
        raise ValueError(f"server challenge must be 8 bytes, got {len(challenge)}")
    if len(response) != 16:
        raise ValueError(f"NTProofStr must be 16 bytes, got {len(response)}")
    return "{u}::{r}:{chal}:{resp}:{auth}".format(
        u=username,
        r=realm,
        chal=bytes(challenge).hex(),
        resp=bytes(response).hex(),
        auth=bytes(authenticator).hex(),
    )


def parse_ntlmv2(candidate: str) -> dict:
    """Inverse of build_ntlmv2. Raises ValueError on anything malformed.

    The three hex fields are fixed-width, so they are taken off the END. That
    is not cosmetic: a UPN legally contains '@' and can contain ':', and
    splitting left-to-right would call "alice:corp::DOM:11..:22..:33.." a
    six-field candidate and reject the one credential type this tool exists to
    catch. The '::' separator is what anchors the split.
    """
    if not isinstance(candidate, str):
        raise TypeError(f"parse_ntlmv2 expects str, got {type(candidate).__name__}")
    head, sep, tail = candidate.partition("::")
    if not sep:
        raise ValueError("a 5600 candidate needs a 'USERNAME::REALM' prefix")
    after = tail.split(":")
    if len(after) != 4:
        raise ValueError(
            "after '::' a 5600 candidate is REALM:CHALLENGE:RESPONSOR:"
            f"AUTENTICATOR, i.e. 3 colons, got {len(after) - 1}")
    realm, challenge, responsor, authenticator = after
    username = head
    out = {
        "username": username,
        "user": username,
        "realm": realm,
        "domain": realm,
        "responsor": bytes.fromhex(responsor),
        "challenge": bytes.fromhex(challenge),
        "authenticator": bytes.fromhex(authenticator),
    }
    if len(out["responsor"]) != 16:
        raise ValueError(f"NTProofStr must be 16 bytes, got {len(out['responsor'])}")
    if len(out["challenge"]) != 8:
        raise ValueError(f"server challenge must be 8 bytes, got {len(out['challenge'])}")
    if not out["authenticator"]:
        raise ValueError("authenticator blob is empty")
    return out


def ntlmv2_username(candidate: str) -> str:
    """The account name from a 5600 candidate, safe on UPNs that contain ':'.

    A NetNTLMv2 hash is bytes to crack, not a password. This only lifts the
    identity that was already sent in the clear.
    """
    return candidate.partition("::")[0]


# AV_PAIR ids that name the server the NTLMv2 auth was going to.
_AV_EOL = 0x0000
_AV_NB_COMPUTER = 0x0001   # server NetBIOS name, e.g. FILESERVER01
_AV_NB_DOMAIN = 0x0002
_AV_DNS_COMPUTER = 0x0003  # server FQDN, e.g. fileserver01.corp.local


def _ntlmv2_avpairs(blob: bytes) -> dict:
    """Walk the AV_PAIR list inside an NTLMv2 client-challenge blob.

    The blob (hashcat 5600's last field) starts with a fixed 28-byte header --
    1+1 response types, 2 + 4 reserved, 8 timestamp, 8 client challenge, 4
    reserved -- then a list of AV pairs: id (u16le), length (u16le), value. The
    list ends at id 0x0000. Values are UTF-16LE. Returns {av_id: text}; a value
    that is not valid UTF-16LE is kept as hex rather than guessed at.
    """
    pairs: dict = {}
    i, n = 28, len(blob)
    while i + 4 <= n:
        av_id = blob[i] | (blob[i + 1] << 8)
        av_len = blob[i + 2] | (blob[i + 3] << 8)
        i += 4
        if av_id == _AV_EOL:
            break
        if i + av_len > n:
            break
        value = blob[i:i + av_len]
        i += av_len
        if av_id not in pairs:
            try:
                pairs[av_id] = value.decode("utf-16le").rstrip("\x00")
            except UnicodeDecodeError:
                pairs[av_id] = to_hex(value)
    return pairs


def ntlmv2_target(candidate: str) -> "str | None":
    """The server an NTLMv2 authentication was going to, read from the AV_PAIRs
    in the blob: the NetBIOS computer name if present, else the DNS one. None if
    the candidate is malformed or carries no server name.

    Like the username, the target is sent in the clear inside the hash -- reading
    it is not cracking, it is just parsing what was already on the wire.
    """
    try:
        parsed = parse_ntlmv2(candidate)
    except (ValueError, TypeError):
        return None
    pairs = _ntlmv2_avpairs(parsed["authenticator"])
    return pairs.get(_AV_NB_COMPUTER) or pairs.get(_AV_DNS_COMPUTER) or None


# Kerberos roast lines carry the account (and, for TGS, the service) in the clear.
_KRB_ASREP_RE = re.compile(r"^\$krb5asrep\$(?:\d+\$)?([^@:$]+)@([^:$]+)")
_KRB_TGS_RE = re.compile(r"^\$krb5tgs\$(?:\d+\$)?\*?([^*$]+)\$([^*$]+)\$([^*]+)\*")
_KRB_PA_RE = re.compile(r"^\$krb5pa\$(?:\d+\$)?([^$]+)\$([^$]+)")


def kerberos_identity(candidate: str) -> dict:
    """The account, realm and (for TGS) the service/SPN out of a krb5 roast line.

    AS-REP (hashcat 18200) names the user whose pre-auth is disabled; TGS-REP
    (13100, kerberoast) names the service account and the SPN the ticket is for.
    These identities are in the clear inside the hash -- reading them is parsing,
    not cracking. Returns {} for anything that is not a krb5 line.
    """
    m = _KRB_ASREP_RE.match(candidate or "")
    if m:
        return {"username": m.group(1), "realm": m.group(2), "target": m.group(2)}
    m = _KRB_TGS_RE.match(candidate or "")
    if m:
        return {"username": m.group(1), "realm": m.group(2),
                "spn": m.group(3), "target": m.group(3)}
    m = _KRB_PA_RE.match(candidate or "")
    if m:
        return {"username": m.group(1), "realm": m.group(2), "target": m.group(2)}
    return {}


# --------------------------------------------------------------------------
# cleartext logins: FTP/POP3, IMAP, SMTP, LDAP
# --------------------------------------------------------------------------

# Well-known service port -> protocol label. When a capture records which port
# a cleartext credential was going to (or coming from), it removes the one real
# ambiguity in the cleartext decoders: FTP and POP3 both speak USER/PASS, so the
# verbs alone cannot tell them apart. The port can. Both the TLS/implicit-SSL
# variants are listed so a credential seen on 995/993/465/636 still labels right.
_PORT_PROTOCOL = {
    21: "ftp", 23: "telnet", 25: "smtp", 110: "pop3", 143: "imap",
    161: "snmp", 389: "ldap", 465: "smtp", 587: "smtp", 636: "ldap",
    993: "imap", 995: "pop3",
}


def service_protocol(*ports) -> "str | None":
    """The protocol for the first of ``ports`` that is a known service port, or
    None. Lets a decoder resolve a flow from whichever side carried the well-known
    port (a client's dport on a request, a server's sport on a response)."""
    for p in ports:
        if p in _PORT_PROTOCOL:
            return _PORT_PROTOCOL[p]
    return None


def _pick_service_port(dport, sport):
    """The one of dport/sport that is a recognized service port (either side of
    the flow may carry it), or dport if neither is, or None."""
    for p in (dport, sport):
        if p in _PORT_PROTOCOL:
            return p
    return dport if dport is not None else sport


# These stop the capture at CR/LF rather than anchoring on $, because a wire
# line ends in CRLF and the $ (even multiline) sits before the \n, leaving the
# \r to break a trailing-whitespace match.
_USERPASS_USER_RE = re.compile(rb"(?im)^USER[ \t]+([^\r\n]+)")
_USERPASS_PASS_RE = re.compile(rb"(?im)^PASS[ \t]+([^\r\n]+)")
_IMAP_LOGIN_RE = re.compile(
    rb'(?im)^(?:[A-Za-z0-9.]+[ \t]+)?LOGIN[ \t]+"?([^"\r\n ]+)"?[ \t]+([^\r\n]+)')
_SMTP_PLAIN_RE = re.compile(rb"(?im)^AUTH[ \t]+PLAIN[ \t]+([A-Za-z0-9+/]{4,}={0,2})")
# LDAP simple bind: BindRequest is APPLICATION 0 (tag 0x60); inside it a version
# INTEGER, the bind DN as an OCTET STRING, then the simple password as a
# context-0 primitive ([0], tag 0x80).
_LDAP_BIND_RE = re.compile(rb"\x60.{1,4}?\x02\x01[\x01-\x07]\x04", re.DOTALL)
# SNMP v1/v2c: SEQUENCE { version INTEGER (0 or 1), community OCTET STRING, PDU }.
# The community string is the clear-text secret; it is followed by a PDU tag
# (0xa0-0xa8), which is what tells this apart from a stray 02 01 00 04 run.
_SNMP_RE = re.compile(rb"\x02\x01[\x00\x01]\x04", re.DOTALL)
# Line-mode telnet (and many console logins): "login: <user>" / "Password: <pw>".
_TELNET_LOGIN_RE = re.compile(rb"(?i)login:[ \t]*([^\r\n]+)")
_TELNET_PASS_RE = re.compile(rb"(?i)password:[ \t]*([^\r\n]+)")


def _snmp_community(raw: bytes):
    """The SNMP v1/v2c community string, or None. It is the clear-text secret an
    agent trusts; reading it is parsing, not cracking."""
    for m in _SNMP_RE.finditer(raw):
        i = m.end()
        if i >= len(raw):
            continue
        ln = raw[i]
        if not 1 <= ln <= 64 or i + 1 + ln >= len(raw):
            continue
        comm = raw[i + 1:i + 1 + ln]
        nxt = raw[i + 1 + ln]
        if not (0xA0 <= nxt <= 0xA8):      # must be followed by an SNMP PDU tag
            continue
        try:
            text = comm.decode("ascii")
        except UnicodeDecodeError:
            continue
        if text.isprintable():
            return text
    return None


def _telnet_clean(value: bytes) -> str:
    """Strip telnet IAC/control bytes from a captured value, keep printable text."""
    return "".join(chr(b) for b in value if 0x20 <= b < 0x7F).strip()


_HOSTNAME_RE = re.compile(
    rb"^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$")


def tls_sni(raw: bytes):
    """The SNI (server name) from a TLS ClientHello, or None.

    This is how MATT "gets" encrypted traffic: the SNI is sent in the CLEAR even
    for HTTPS, so without breaking any crypto MATT can report which server an
    encrypted session is going to -- metadata, not plaintext. Scans for the
    server_name extension (type 0x0000) and validates the host looks like a
    domain, so a stray 00 00 in binary data is not mistaken for one.
    """
    i, n = 0, len(raw)
    if b"\x16\x03" not in raw and b"\x01\x00" not in raw:  # cheap TLS/ClientHello gate
        return None
    while i < n:
        j = raw.find(b"\x00\x00", i)            # server_name extension type
        if j < 0 or j + 9 > n:
            return None
        name_type = raw[j + 6]
        name_len = (raw[j + 7] << 8) | raw[j + 8]
        if name_type == 0x00 and 4 <= name_len <= 253 and j + 9 + name_len <= n:
            name = raw[j + 9:j + 9 + name_len]
            if _HOSTNAME_RE.match(name):
                return name.decode("ascii")
        i = j + 1   # step by one: overlapping 00-runs must not skip the real tag
    return None


_ALPN_RE = re.compile(rb"(h2|http/1\.1|h3(?:-\d+)?|spdy/[0-9.]+|h2c|dot|dns)\Z")


def tls_alpn(raw: bytes) -> list:
    """The ALPN protocols offered in a TLS ClientHello (e.g. ['h2','http/1.1']),
    or []. ALPN is sent in the clear, so this tells you a session is HTTP/2 (h2)
    or HTTP/3 (h3) without decrypting anything."""
    protos = []
    i, n = 0, len(raw)
    while i < n:
        j = raw.find(b"\x00\x10", i)            # ALPN extension type
        if j < 0 or j + 6 > n:
            break
        ext_len = (raw[j + 2] << 8) | raw[j + 3]
        list_len = (raw[j + 4] << 8) | raw[j + 5]
        if 2 <= ext_len <= 255 and list_len == ext_len - 2 and j + 6 + list_len <= n:
            p, end = j + 6, j + 6 + list_len
            ok = True
            found = []
            while p < end:
                plen = raw[p]
                if plen == 0 or p + 1 + plen > end:
                    ok = False
                    break
                token = raw[p + 1:p + 1 + plen]
                if _ALPN_RE.match(token):
                    found.append(token.decode("ascii"))
                p += 1 + plen
            if ok and found:
                return found
        i = j + 1
    return protos


_CN_OID = b"\x06\x03\x55\x04\x03"        # 2.5.4.3  commonName
_SAN_OID = b"\x06\x03\x55\x1d\x11"       # 2.5.29.17 subjectAltName
_X509_STR_TAGS = (0x13, 0x0c, 0x16, 0x14, 0x1e, 0x0a)  # Printable/UTF8/IA5/...


def tls_cert_names(raw: bytes):
    """Subject CN, issuer CN, and SAN DNS names out of an X.509 certificate seen
    in a TLS ServerHello/Certificate message (TLS 1.2 and earlier send it in the
    clear). Returns a dict or None. This names the server (and who signed its
    cert) from the handshake -- metadata, no decryption. TLS 1.3 encrypts the
    certificate, so this only applies to <= 1.2 handshakes.
    """
    cns = []
    i = 0
    while True:
        j = raw.find(_CN_OID, i)
        if j < 0:
            break
        k = j + len(_CN_OID)
        if k + 1 < len(raw) and raw[k] in _X509_STR_TAGS:
            ln = raw[k + 1]
            if ln < 0x80 and k + 2 + ln <= len(raw):
                try:
                    text = raw[k + 2:k + 2 + ln].decode("utf-8")
                    if text.strip() and text.isprintable():
                        cns.append(text)
                except UnicodeDecodeError:
                    pass
        i = j + 1

    sans = []
    s = raw.find(_SAN_OID)
    if s >= 0:
        region = raw[s:s + 4000]
        p = 0
        while p + 2 < len(region):
            if region[p] == 0x82:                 # dNSName [2]
                ln = region[p + 1]
                if 0 < ln < 0x80 and p + 2 + ln <= len(region):
                    name = region[p + 2:p + 2 + ln]
                    if _HOSTNAME_RE.match(name) or name[:2] == b"*.":
                        try:
                            sans.append(name.decode("ascii"))
                        except UnicodeDecodeError:
                            pass
                        p += 2 + ln
                        continue
            p += 1

    out = {}
    if cns:
        out["subject_cn"] = cns[-1]               # DER order: issuer DN then subject
        if len(cns) >= 2:
            out["issuer_cn"] = cns[0]
    if sans:
        out["sans"] = sorted(set(sans))
    return out or None


_QUIC_VERSIONS = {
    0x00000001: "QUIC v1 (RFC 9000)", 0xFF00001D: "QUIC draft-29",
    0x6B3343CF: "QUIC v2", 0x51303530: "gQUIC Q050",
}


def quic_info(raw: bytes):
    """Detect a QUIC long-header Initial packet and return its version string,
    or None. HTTP/3 rides on QUIC; the SNI there is inside an AEAD-encrypted
    CRYPTO frame, so MATT reports the connection but not the hostname (decrypting
    it needs AES, which the standard library does not provide)."""
    i, n = 0, len(raw)
    while i + 5 <= n:
        b0 = raw[i]
        if b0 & 0xC0 == 0xC0:                   # long header, fixed bit set
            ver = (raw[i + 1] << 24) | (raw[i + 2] << 16) | (raw[i + 3] << 8) | raw[i + 4]
            if ver in _QUIC_VERSIONS:
                return _QUIC_VERSIONS[ver]
        i += 1
    return None


def arp_info(raw: bytes):
    """Decode an Ethernet ARP packet (IPv4-over-Ethernet shape only), or None.

    ARP has no IP header for strip_wire_headers to find, so these packets
    arrive at candidates_from_payload exactly as captured -- 28 bytes of
    hardware/protocol type, lengths, opcode, then sender/target MAC+IP, plus
    whatever Ethernet padding tcpdump included. There is no secret in an ARP
    frame (it is who-has/is-at gossip, not auth), so this is purely so ARP
    traffic reads as "ARP: who has 10.0.0.1? tell 10.0.0.5" instead of falling
    into the generic "does not match any hashcat format" catch-all, which
    reads as suspicious for something this mundane.
    """
    if len(raw) < 28 or raw[:4] != b"\x00\x01\x08\x00" or raw[4] != 6 or raw[5] != 4:
        return None
    op = (raw[6] << 8) | raw[7]
    if op not in (1, 2):
        return None
    smac = ":".join("%02x" % b for b in raw[8:14])
    sip = ".".join(str(b) for b in raw[14:18])
    tmac = ":".join("%02x" % b for b in raw[18:24])
    tip = ".".join(str(b) for b in raw[24:28])
    return {"op": "request" if op == 1 else "reply",
            "sender_mac": smac, "sender_ip": sip,
            "target_mac": tmac, "target_ip": tip}


_DISCOVERY_LABELS = {
    "dropbox-lansync": "Dropbox LAN-sync discovery broadcast",
    "bsdp": "Apple BSDP (NetBoot) discovery request",
    "spotify-connect": "Spotify Connect discovery broadcast",
    "hasp-lm": "Sentinel HASP / FlexLM license-manager discovery broadcast",
}


def known_discovery_protocol(raw: bytes, port=None) -> "str | None":
    """A kind slug for a handful of common, no-secret LAN discovery/broadcast
    protocols, recognized by their own signature (and, for HASP, its port --
    its payload is an opaque session token with no signature of its own), or
    None.

    None of these carry a credential: there is nothing here for hashcat, or
    any other method, to crack -- the right outcome is naming the protocol,
    not forcing it through a cracker that has nothing to crack. Without this,
    all four fell into the generic "does not match any hashcat format, kept
    verbatim for manual review" catch-all, which reads as suspicious for
    traffic this mundane.
    """
    if raw.startswith(b'{"version"') and b'"namespaces"' in raw[:260]:
        return "dropbox-lansync"
    if raw.startswith(b"SEARCH BSDP/"):
        return "bsdp"
    if raw.startswith(b"SpotUdp"):
        return "spotify-connect"
    if port == 1947:
        return "hasp-lm"
    return None


def _usm_username(seq: bytes):
    """The msgUserName (4th field) out of an SNMPv3 USM SEQUENCE: OCTET engineID,
    INTEGER boots, INTEGER time, OCTET userName, ..."""
    try:
        if seq[0] != 0x30:
            return None
        ln, i = _ber_len(seq, 1)
        body = seq[i:i + ln]
        p, fields = 0, []
        while p < len(body) and len(fields) < 4:
            length, q = _ber_len(body, p + 1)
            fields.append((body[p], body[q:q + length]))
            p = q + length
        if len(fields) >= 4 and fields[3][0] == 0x04 and fields[3][1]:
            name = fields[3][1].decode("utf-8", "replace")
            if name.isprintable():
                return name
    except (IndexError, ValueError):
        return None
    return None


def snmpv3_user(raw: bytes):
    """The SNMPv3 msgUserName, or None. SNMPv3 does not put the password on the
    wire, but the username is clear and the auth params are crackable offline
    (hashcat -m 25100/25200), so surfacing the user is useful reconnaissance."""
    if b"\x02\x01\x03" not in raw:          # msgVersion INTEGER = 3
        return None
    i, n = 0, len(raw)
    while i < n:
        j = raw.find(b"\x04", i)            # msgSecurityParameters is an OCTET STRING
        if j < 0:
            return None
        try:
            ln, k = _ber_len(raw, j + 1)
        except (IndexError, ValueError):
            i = j + 1
            continue
        inner = raw[k:k + ln]
        if inner[:1] == b"\x30":            # that wraps the USM SEQUENCE
            user = _usm_username(inner)
            if user:
                return user
        i = j + 1
    return None


def _ber_len(data: bytes, i: int):
    """Decode one BER length starting at i; return (length, next_index)."""
    first = data[i]
    if first < 0x80:
        return first, i + 1
    count = first & 0x7F
    length = 0
    for j in range(count):
        length = (length << 8) | data[i + 1 + j]
    return length, i + 1 + count


def _ldap_simple_bind(raw: bytes):
    """Extract (dn, password) from an LDAP simple bind, or None. The password in
    a simple bind is sent in the clear; this only reads what was on the wire."""
    m = _LDAP_BIND_RE.search(raw)
    if not m:
        return None
    try:
        # position at the version INTEGER (0x02 0x01 vv) inside the bind request
        i = raw.index(b"\x02\x01", m.start())
        i += 3                                  # skip version INTEGER
        if raw[i] != 0x04:                      # name: OCTET STRING
            return None
        dn_len, i = _ber_len(raw, i + 1)
        dn = raw[i:i + dn_len]
        i += dn_len
        if raw[i] != 0x80:                      # [0] simple password
            return None
        pw_len, i = _ber_len(raw, i + 1)
        pw = raw[i:i + pw_len]
    except (IndexError, ValueError):
        return None
    if not pw:
        return None
    return (dn.decode("utf-8", "replace"), pw.decode("utf-8", "replace"))


def cleartext_credentials(raw: bytes, port=None) -> list:
    """Every cleartext secret in a payload: FTP/POP3 (USER/PASS), IMAP (LOGIN),
    SMTP (AUTH PLAIN), LDAP simple bind, SNMP v1/v2c community strings, and
    line-mode telnet (login:/Password:). Returns a list of dicts
    {kind, username, password} (username is "" for SNMP). These secrets were on
    the wire in the clear -- MATT reports them as recovered, no cracking.

    ``port`` is the service port the flow was on, if the capture recorded it. It
    disambiguates FTP (21) from POP3 (110/995), which the USER/PASS verbs cannot
    do on their own; when it is absent the banner heuristic and an ftp default
    stand in, exactly as before."""
    out = []

    u = _USERPASS_USER_RE.search(raw)
    p = _USERPASS_PASS_RE.search(raw)
    if u and p:
        # FTP and POP3 both use USER/PASS. The service port settles it when the
        # capture recorded one; otherwise the greeting tells them apart ("+OK" is
        # POP3, "220" is FTP); otherwise default to ftp.
        hinted = service_protocol(port)
        if hinted in ("ftp", "pop3"):
            kind = hinted
        elif b"+OK" in raw and b"220 " not in raw:
            kind = "pop3"
        else:
            kind = "ftp"
        out.append({"kind": kind,
                    "username": u.group(1).decode("latin-1").strip(),
                    "password": p.group(1).decode("latin-1").strip()})

    im = _IMAP_LOGIN_RE.search(raw)
    if im:
        out.append({"kind": "imap",
                    "username": im.group(1).decode("latin-1").strip().strip('"'),
                    "password": im.group(2).decode("latin-1").strip().strip('"')})

    for sm in _SMTP_PLAIN_RE.finditer(raw):
        try:
            decoded = base64.b64decode(sm.group(1), validate=True)
        except Exception:
            continue
        # AUTH PLAIN is authzid \0 authcid \0 password
        parts = decoded.split(b"\x00")
        if len(parts) == 3 and parts[2]:
            out.append({"kind": "smtp",
                        "username": parts[1].decode("latin-1") or parts[0].decode("latin-1"),
                        "password": parts[2].decode("latin-1")})

    ldap = _ldap_simple_bind(raw)
    if ldap and ldap[1]:
        out.append({"kind": "ldap", "username": ldap[0], "password": ldap[1]})

    community = _snmp_community(raw)
    if community:
        # SNMP has no user -- the community string is the secret on its own.
        out.append({"kind": "snmp", "username": "", "password": community})

    tl = _TELNET_LOGIN_RE.search(raw)
    tp = _TELNET_PASS_RE.search(raw)
    if tl and tp:
        user = _telnet_clean(tl.group(1))
        pw = _telnet_clean(tp.group(1))
        if user and pw:
            out.append({"kind": "telnet", "username": user, "password": pw})

    return out


# --------------------------------------------------------------------------
# candidate extraction from a raw payload
# --------------------------------------------------------------------------

_KV_PATTERNS = (
    ("username", re.compile(rb"(?:m4_fn|Username|username|USER)\s*=\s*([^&\r\n]+)")),
    ("domain", re.compile(rb"(?:m4_dn|Domain|domain|DOMAIN)\s*=\s*([^&\r\n]+)")),
    ("password", re.compile(rb"(?:m4_pw|Password|passwd|password|PASSWD)\s*=\s*([^&\r\n]+)")),
    ("login", re.compile(rb"(?:Login|LOGIN|user)\s*=\s*([^&\r\n]+)")),
)

_BARE_NTLM_RE = re.compile(rb"([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):([0-9a-fA-F]{16})")

_REQ_LINE_RE = re.compile(rb"(?im)^(?:GET|POST|PUT|PATCH|DELETE)[ \t]+(\S+)[ \t]+HTTP/")
_HOST_HDR_RE = re.compile(rb"(?im)^Host:[ \t]*([^\r\n]+)")


def _http_target(raw: bytes) -> "str | None":
    """The destination an HTTP credential is going to: ``Host`` header + request
    path, e.g. ``intranet.corp.local/portal/login``. None if this is not HTTP.

    This is what lets the prose say where a captured credential goes, so that a
    report with several credentials keeps each one's target distinct.
    """
    host_m = _HOST_HDR_RE.search(raw)
    path_m = _REQ_LINE_RE.search(raw)
    if not host_m and not path_m:
        return None
    host = host_m.group(1).decode("latin-1").strip() if host_m else ""
    path = path_m.group(1).decode("latin-1").strip() if path_m else ""
    if path[:7].lower() in ("http://", "https:/"):  # already absolute-form
        return path
    if host and path:
        return host + path
    return host or path or None


def candidates_from_payload(payload, source: str = "wire", port=None) -> list:
    """Pull every credential candidate out of one raw payload.

    Returns a list of dicts with ``kind``, ``hashcat_mode``, ``candidate``,
    ``decoded_via`` and (when the wire gave us one) ``username`` / ``domain``.
    Deterministic and side-effect free: same bytes in, same list out.

    ``port`` is the service port the payload was on, when the capture recorded
    one; it is used only to tell FTP from POP3 in the cleartext decoder.
    """
    if isinstance(payload, str):
        raw = _coerce_bytes(payload)
    else:
        raw = bytes(payload or b"")

    found: list = []
    seen: set = set()

    def add(kind, mode, candidate, via, **extra) -> None:
        key = (kind, candidate)
        if key in seen:
            return
        seen.add(key)
        item = {
            "kind": kind,
            "hashcat_mode": mode,
            "candidate": candidate,
            "decoded_via": via,
            "source": source,
        }
        item.update(extra)
        found.append(item)

    # Where an HTTP credential is going: the Host header plus the request target,
    # so a finding names its destination (e.g. "intranet.corp.local/login") and
    # two credentials in one report are never confused.
    http_target = _http_target(raw)
    dest = {"target": http_target} if http_target else {}

    # 1. explicit HTTP POST / form credentials. Field order is preserved, which
    #    is why m4_pw=... yields an md5 candidate and not invented prose.
    fields = {}
    for name, pattern in _KV_PATTERNS:
        match = pattern.search(raw)
        if match and name not in fields:
            method, text = decode_field(match.group(1))
            fields[name] = text
            if name == "password":
                add("md5", HASHCAT_MODES["md5"],
                    hashlib.md5(match.group(1)).hexdigest(), "md5(" + method + ")",
                    **dest)

    # 2. HTTP Basic: base64 of "user:pass". Only the colon form decodes, so a
    #    bare token is never invented into a credential pair.
    for match in re.finditer(rb"Basic\s+([A-Za-z0-9+/=]{8,})\s*", raw):
        try:
            decoded = base64.b64decode(match.group(1), validate=True)
        except Exception:
            continue
        method, text = decode_field(decoded)
        if method == "hex" or ":" not in text:
            continue
        user, _, secret = text.partition(":")
        if not user or not secret:
            continue
        add("http-basic", None, f"{user}:{secret}", "base64+utf-8",
            username=user, credential_bearing=True, protocol="http", **dest)

    # 3. NetNTLM v1 triplets sitting in the clear (LM:NT:SERVERCHALLENGE).
    for match in _BARE_NTLM_RE.finditer(raw):
        lm, nt, server = match.group(1), match.group(2), match.group(3)
        candidate = "{u}::{d}:{lm}:{nt}:{sc}".format(
            u=fields.get("username", ""), d=fields.get("domain", ""),
            lm=lm.decode().lower(), nt=nt.decode().lower(),
            sc=server.decode().lower())
        kind, mode = type_hash(candidate)
        add(kind, mode, candidate, "utf-8")

    # 4. a full 5600 candidate that arrived already assembled. The account name
    #    and domain are sent in the clear inside the hash, so lift them out and
    #    attach them -- the prose can then name who authenticated without any
    #    cracking having happened (the secret is still just a candidate).
    for line in raw.replace(b"\r", b"\n").split(b"\n"):
        line = line.strip()
        if _ntlmv2_shape(line):
            text = line.decode("ascii", "ignore")
            kind, mode = type_hash(text)
            extra = {}
            try:
                parsed = parse_ntlmv2(text)
                if parsed["username"]:
                    extra["username"] = parsed["username"]
                if parsed["domain"]:
                    extra["domain"] = parsed["domain"]
            except ValueError:
                pass
            server = ntlmv2_target(text)
            if server:
                extra["target"] = server   # e.g. "-> FILESERVER01"
            add(kind, mode, text, "utf-8", **extra)

    # 5. a PMKID or handshake line off a harvester's drop file.
    for line in raw.replace(b"\r", b"\n").split(b"\n"):
        line = line.strip()
        if line.count(b"*") in (3, 4, 5):
            kind, mode = type_hash(line)
            if kind in ("wpa-pmkid", "wpa-eh2912"):
                add(kind, mode, line.decode("ascii", "ignore"), "utf-8")

    # 5b. cleartext protocol logins (FTP/POP3, IMAP, SMTP, LDAP). The password
    #     was on the wire in the clear -- these are recovered credentials, no
    #     hashcat mode, credential-bearing, and carry the destination.
    for cred in cleartext_credentials(raw, port=port):
        u, pw = cred["username"], cred["password"]
        candidate = ("%s:%s" % (u, pw)) if u else pw   # SNMP has no user
        add(cred["kind"], None, candidate, "cleartext",
            username=u, credential_bearing=True, protocol=cred["kind"], **dest)

    # 5c. Kerberos roast lines ($krb5asrep$ / $krb5tgs$) off a roaster's output.
    #     The account (and the SPN, for TGS) ride in the clear in the hash, so
    #     they name the finding and its target.
    for line in raw.replace(b"\r", b"\n").split(b"\n"):
        line = line.strip()
        if (line.startswith(b"$krb5asrep$") or line.startswith(b"$krb5tgs$")
                or line.startswith(b"$krb5pa$")):
            text = line.decode("latin-1")
            kind, mode = type_hash(text)
            ident = kerberos_identity(text)
            extra = {k: ident[k] for k in ("username", "target") if ident.get(k)}
            add(kind, mode, text, "utf-8", **extra)

    # 5d. SNMPv3 reconnaissance: the username is clear even though the password
    #     is not. Surfaced as an informational finding (not credential-bearing),
    #     with a note that the auth params crack with hashcat -m 25100/25200.
    v3user = snmpv3_user(raw)
    if v3user:
        add("snmpv3", None, v3user, "snmpv3",
            username=v3user, credential_bearing=False)

    # 5e. TLS/HTTPS metadata: the SNI names the server an ENCRYPTED session is
    #     going to, and ALPN says whether it is HTTP/2 -- recon pulled from
    #     encrypted traffic without any decryption. QUIC/HTTP3 is detected too,
    #     though its SNI is AEAD-encrypted and not recoverable with the stdlib.
    sni = tls_sni(raw)
    if sni:
        alpn = tls_alpn(raw)
        extra = {"target": sni, "credential_bearing": False}
        if alpn:
            extra["protocol"] = "https/" + "+".join(alpn)
        add("tls-sni", None, sni, "tls", **extra)
    cert = tls_cert_names(raw)
    if cert and cert.get("subject_cn"):
        add("tls-cert", None, cert["subject_cn"], "tls",
            target=cert["subject_cn"], issuer=cert.get("issuer_cn", ""),
            sans=cert.get("sans", []), credential_bearing=False)
    if not found:
        quic = quic_info(raw)
        if quic:
            add("quic", None, quic, "quic", credential_bearing=False)

    # 5f. ARP: no secret rides in it, just who-has/is-at gossip, but it is the
    #     single most common thing a broadcast LAN capture picks up, so give
    #     it its own sentence instead of letting it pile into "raw" below.
    if not found:
        arp = arp_info(raw)
        if arp:
            summary = (f"who-has {arp['target_ip']} tell {arp['sender_ip']}"
                      if arp["op"] == "request" else
                      f"{arp['sender_ip']} is-at {arp['sender_mac']}")
            add("arp", None, summary, "arp", credential_bearing=False,
                host=arp["sender_ip"], **arp)

    # 5g. a handful of common, no-secret LAN discovery/broadcast protocols:
    #     labeled by their own signature so they read as what they are,
    #     instead of landing in the generic "raw" catch-all below.
    if not found:
        disc_kind = known_discovery_protocol(raw, port)
        if disc_kind:
            method, text = decode_field(raw)
            add(disc_kind, None, text, method, credential_bearing=False,
                protocol=disc_kind, discovery_label=_DISCOVERY_LABELS[disc_kind])

    # 6. nothing structured: keep the payload itself so a human can look at it.
    if not found and raw:
        method, text = decode_field(raw)
        kind, mode = type_hash(raw)
        add(kind if kind != "unknown" else "raw", mode, text, method)

    # 7. typing, provenance, and the credential-bearing flag. A candidate that
    #    was added as credential-bearing (http-basic and the cleartext logins --
    #    the password was literally on the wire) keeps that; everything else is
    #    credential-bearing exactly when it carries a crackable hashcat mode.
    for item in found:
        if "credential_bearing" not in item:
            item["credential_bearing"] = item["hashcat_mode"] is not None
        item.setdefault("username", fields.get("username", ""))
        item.setdefault("domain", fields.get("domain", ""))
        if not item["credential_bearing"]:
            item["prose_hint"] = "decoded only -- not a crackable credential"
    return found


# --------------------------------------------------------------------------
# whole-report candidate extraction (stage 1 output -> candidate list)
# --------------------------------------------------------------------------

def _coerce_bytes(blob) -> bytes:
    """Accept bytes, plain text, hex, or tshark colon-hex; return raw bytes.

    tshark's ``-x`` output hands payload back as a hex dump, and tcpdump hands
    back a bare hex run, so a hex-only string is unescaped before it is treated
    as text. Text that merely contains hex digits inside a longer ASCII string
    stays text, which is what keeps "user=alice" from becoming noise.
    """
    if isinstance(blob, (bytes, bytearray)):
        return bytes(blob)
    if not isinstance(blob, str):
        return b""
    text = blob.strip()
    if not text:
        return b""
    squashed = text.replace(":", "").replace(" ", "").replace("\n", "")
    if len(squashed) >= 2 and len(squashed) % 2 == 0 and _HEX_RE.match(squashed):
        try:
            return bytes.fromhex(squashed)
        except ValueError:  # pragma: no cover - regex already guarantees this
            pass
    return text.encode("utf-8", "surrogateescape")


def extract_candidates(report: dict) -> list:
    """Flatten a capture_report into a candidate list, tagging each with its host.

    Understands three report shapes, in this order:

      1. {"candidates": [...]}                    already extracted, passed through
      2. {"payloads": [...]}                      raw payloads from this run
      3. {"hosts": {ip: {"payloads": [...]}}}     per-host payloads

    A payload may be a string (text, hex, or tshark colon-hex) or a dict with
    ``payload`` plus host/protocol metadata. Decoding is always delegated to
    candidates_from_payload, so one payload found in shape 2 yields exactly the
    same candidates as the same payload in shape 3.
    """
    if not isinstance(report, dict):
        raise TypeError(f"extract_candidates expects a dict, got {type(report).__name__}")

    if isinstance(report.get("candidates"), list):
        return [dict(item) if isinstance(item, dict) else
                {"kind": "raw", "candidate": str(item)}
                for item in report["candidates"]]

    groups: list = []
    # Per-host payloads are collected FIRST, the flat top-level ``payloads`` list
    # LAST. In MATT's own live format the same wire bytes land in both
    # report["payloads"] and report["hosts"]["the wire"]["payloads"], so without
    # an order the flat mirror would be decoded as a second, host-less copy of
    # every finding. Decoding the host-attributed copy first means the mirror is
    # the one the dedupe below drops, and each credential is reported once, with
    # its host, instead of twice.
    hosts = report.get("hosts")
    if isinstance(hosts, dict):
        for host, info in hosts.items():
            if isinstance(info, dict) and isinstance(info.get("payloads"), list):
                groups.append((host, info["payloads"]))
            elif isinstance(info, dict) and isinstance(info.get("candidates"), list):
                for item in info["candidates"]:
                    found = dict(item)
                    found.setdefault("host", host)
                    groups.append((host, [found]))
    payloads = report.get("payloads")
    if isinstance(payloads, list):
        groups.append(("", payloads))

    out: list = []
    seen_blobs: set = set()
    for host, items in groups:
        for entry in items:
            meta: dict = {}
            protocol = ""
            if isinstance(entry, dict):
                if "candidate" in entry or "kind" in entry:
                    item = dict(entry)
                    if host and not item.get("host"):
                        item["host"] = host
                    out.append(item)
                    continue
                meta = dict(entry)
                blob = meta.pop("payload", b"")
                # src/dst are IPs off the capture's own summary line (tcpdump/
                # tshark), independent of anything the credential decoders find
                # in the payload bytes. They are the fallback for "whose
                # traffic was this" and "where did it go" -- a decoder-derived
                # host/target (an HTTP Host header, an NTLMv2 target server,
                # a TLS SNI) always wins when one exists, since that is the
                # application's own idea of its destination, not just the IP
                # a layer 3 header happened to carry.
                src_ip = meta.pop("src", None)
                dst_ip = meta.pop("dst", None)
                dport_val = meta.get("dport")
                # An explicit per-entry host wins outright; after that, a
                # specific source IP off THIS packet beats the group's own
                # label, because that label is "the wire" in MATT's own live
                # format -- a structural placeholder for "no host grouping
                # was done", not a real identity, and must never outrank an
                # actual fact about whose packet this was.
                explicit_host = meta.pop("host", None)
                host_here = explicit_host or src_ip or host
                protocol = meta.pop("protocol", "") or ""
                # Ports are decode hints, not finding fields: resolve the service
                # port here and drop them so findings keep their shape.
                svc_port = _pick_service_port(meta.pop("dport", None),
                                              meta.pop("sport", None))
            else:
                blob = entry
                host_here = host
                svc_port = None
                src_ip = dst_ip = dport_val = None

            raw = _coerce_bytes(blob)
            # The same wire bytes may appear under more than one group -- the
            # flat top-level mirror of a per-host payload, or the literal same
            # packet stored twice. Decode each distinct payload once; a second
            # copy would only re-emit candidates that are byte-for-byte equal.
            if raw and raw in seen_blobs:
                continue
            if raw:
                seen_blobs.add(raw)
            source = "wire" if not protocol else str(protocol)
            for item in candidates_from_payload(raw, source=source, port=svc_port):
                if host_here and not item.get("host"):
                    item["host"] = host_here
                if protocol and not item.get("protocol"):
                    item["protocol"] = protocol
                if dst_ip and not item.get("target"):
                    item["target"] = f"{dst_ip}:{dport_val}" if dport_val else dst_ip
                item.update({k: v for k, v in meta.items() if k not in item})
                out.append(item)
    return out


# --------------------------------------------------------------------------
# stage 2: prose
# --------------------------------------------------------------------------

_MODE_HINTS = {
    "5600": "NetNTLMv2. Crack offline with hashcat -m 5600 (domain and username "
            "are already in the candidate), or skip cracking entirely and relay "
            "it with ntlmrelayx to authenticate as this user.",
    "5500": "NetNTLMv1. Crack offline with hashcat -m 5500 (v1 answers leak fast "
            "and are sometimes reversible in minutes), or relay it with "
            "ntlmrelayx to authenticate without cracking at all.",
    "16800": "WPA PMKID. Crack offline with hashcat -m 16800 against a wordlist; "
             "no client has to reconnect for this one.",
    "22000": "Full WPA2 handshake. Crack offline with hashcat -m 22000; you have "
             "both nonces and the EAPOL frame.",
    "18200": "Kerberos AS-REP roast. Crack offline with hashcat -m 18200; this "
             "account has pre-auth disabled, so no password was needed to pull it.",
    "13100": "Kerberos TGS-REP (kerberoast). Crack offline with hashcat -m 13100; "
             "the secret is the service account's password.",
    "7500": "Kerberos AS-REQ pre-auth. Crack offline with hashcat -m 7500; the "
            "encrypted timestamp is derived from the user's password.",
    "0": "MD5 digest. Crack offline with hashcat -m 0 or check it against a "
         "rainbow table before burning GPU time.",
    "100": "SHA-1 digest. Crack offline with hashcat -m 100.",
    "1400": "SHA-256 digest. Crack offline with hashcat -m 1400.",
}


def stage2_prose(finding: dict) -> str:
    """Write the sentence a human reads, for one finding. No network, no model.

    Deliberately flat and factual: what was seen, where, what it is, and what
    the operator does next. It never states a password, because stage 2 has
    never recovered one.
    """
    kind = finding.get("kind") or "unknown"
    host = finding.get("host") or "an unidentified host"
    protocol = finding.get("protocol") or finding.get("source") or "unknown protocol"
    # "where" is where the credential GOES -- the destination service/host, so
    # that when a report holds several credentials, each sentence names its own
    # target and two findings can never be confused for each other.
    target = finding.get("target")
    where = f"{target} over {protocol}" if target else protocol
    mode = finding.get("hashcat_mode")
    candidate = (finding.get("candidate") or "").strip()

    if kind == "snmpv3":
        who = finding.get("username") or candidate or "an unnamed user"
        return (f"{host} spoke SNMPv3 as user {who!r} to {where}. SNMPv3 does not "
                "put the password on the wire, but the auth params can be cracked "
                "offline with hashcat -m 25100/25200.")

    if kind == "tls-sni":
        proto = finding.get("protocol") or "https"
        http2 = " (HTTP/2)" if "h2" in proto and "h2c" not in proto else ""
        return (f"{host} opened an encrypted TLS/HTTPS session{http2} to {candidate} "
                "(server name read from the ClientHello SNI, which is sent in the "
                "clear). The payload is encrypted; the destination is not.")

    if kind == "tls-cert":
        issuer = finding.get("issuer") or "an unknown CA"
        sans = finding.get("sans") or []
        tail = (" (SANs: " + ", ".join(sans[:6]) + ")") if sans else ""
        return (f"{host} presented a TLS certificate for {candidate}, issued by "
                f"{issuer!r}{tail}. Read from the ServerHello in the clear; the "
                "session payload stays encrypted.")

    if finding.get("discovery_label"):
        shown = candidate if (candidate and not candidate.startswith("hex:")) else None
        tail = f" Decoded: {shown}" if shown else ""
        dest = f" to {where}" if target else " on the LAN"
        return (f"{host} sent a {finding['discovery_label']}{dest}; not a "
                f"credential, nothing to crack.{tail}")

    if kind == "arp":
        if finding.get("op") == "request":
            return (f"{host} broadcast ARP: who has {finding.get('target_ip')}? "
                    f"tell {finding.get('sender_ip')} ({finding.get('sender_mac')}). "
                    "Address resolution, not a credential -- nothing to crack.")
        return (f"{host} sent an ARP reply: {finding.get('sender_ip')} is at "
                f"{finding.get('sender_mac')}. Address resolution, not a credential "
                "-- nothing to crack.")

    if kind == "quic":
        return (f"{host} opened a QUIC / HTTP3 connection ({candidate}). The SNI is "
                "inside an AEAD-encrypted QUIC Initial packet, so the hostname is "
                "not recoverable without the keys.")

    if mode is None:
        # a cleartext credential (FTP/IMAP/SMTP/LDAP/HTTP-Basic): the password was
        # already on the wire, so this is recovered, not awaiting a crack.
        if finding.get("credential_bearing"):
            who = finding.get("username")
            ident = f" as {who!r}" if who else ""
            return (
                f"{host} sent a cleartext {kind} credential{ident} to {where}, "
                f"no cracking needed. Recovered: {candidate}"
            )
        head = (
            f"{host} put {kind} traffic on the wire to {where}; it was "
            "decoded but does not match any hashcat format MATT knows, so it is "
            "kept verbatim for manual review."
        )
        if candidate:
            head += f" Decoded value: {candidate}"
        return head

    hint = _MODE_HINTS.get(str(mode), f"Crack offline with hashcat -m {mode}.")
    who = finding.get("username")
    if who:
        head = f"{host} authenticated to {where} as {who!r}"
    else:
        head = f"{host} authenticated to {where} without naming itself"
    return (
        f"{head}. Captured candidate is {kind} (hashcat mode {mode}): "
        f"{finding.get('candidate', '').strip()}. {hint}"
    )


def analyze(report: dict, model=None, model_name: str = "builtin:stage2_prose",
            base_url: str = None, env: dict = None) -> dict:
    """Stage 2. Turn a capture_report dict into an analysis dict.

    ``model`` is a callable that takes a finding dict and returns prose. When it
    is None -- the default, and the only thing the CLI does without
    ``--use-model`` -- prose comes from ``stage2_prose`` in this module. That
    path costs zero usage tokens because it never calls out at all: there is no
    reference to ``matt.model`` on this path, so there is no route from here to
    a socket when ``model`` is None.

    ``base_url`` and ``env`` exist so the CLI can record WHERE a model-backed
    run would send data, without this module importing one. They only populate
    ``analysis["model_endpoint"]``, and only when a model was supplied: a
    default run does not even read the key environment variables, so "no
    configuration" and "no calls" stay the single same fact.

    The input report is never mutated; the same dict can be analyzed twice.
    """
    if not isinstance(report, dict):
        raise TypeError(f"analyze expects a capture_report dict, got {type(report).__name__}")
    if model is not None and not callable(model):
        raise TypeError("model, when given, must be callable: analyze() will not "
                        "invent one for you")

    writer = model if model is not None else stage2_prose

    endpoint = None
    if model is not None and (base_url or env is not None):
        from . import model as _model  # local import: core itself stays socket-free

        try:
            endpoint = _model.resolve_endpoint(base_url=base_url, env=env)["base_url"]
        except _model.ModelConfigError:
            endpoint = None

    raw_candidates = report.get("candidates")
    if raw_candidates is None:
        raw_candidates = extract_candidates(report)

    hosts = report.get("hosts") or {}
    host_count = len(hosts) if isinstance(hosts, dict) else len(set(hosts))

    findings: list = []
    credential_bearing = 0
    for raw in raw_candidates:
        finding = dict(raw)
        if not finding.get("host"):
            finding["host"] = "the wire"
        if "credential_bearing" not in finding:
            finding["credential_bearing"] = finding.get("hashcat_mode") is not None
        prose = writer(finding)
        if not isinstance(prose, str) or not prose.strip():
            prose = stage2_prose(finding)
        finding["prose"] = prose.strip()
        credential_bearing += 1 if finding["credential_bearing"] else 0
        findings.append(finding)

    kinds: dict = {}
    for finding in findings:
        key = finding.get("kind", "unknown")
        kinds[key] = kinds.get(key, 0) + 1

    analyzed = dict(report)
    analyzed["analysis"] = {
        "engine": model_name if model is not None else "builtin:stage2_prose",
        "model_used": model_name if model is not None else None,
        "model_endpoint": endpoint,
        "network_calls": len(findings) if model is not None else 0,
        "generated_at": utc_now(),
        "host_count": host_count,
        "candidate_count": len(findings),
        "credential_bearing": credential_bearing,
        "kind_counts": kinds,
        "findings": findings,
    }
    return analyzed


# --------------------------------------------------------------------------
# capture_report.json
# --------------------------------------------------------------------------

def read_report(path: str) -> dict:
    """Load a capture_report.json written by an earlier run."""
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_report(report: dict, path: str) -> str:
    """Write ``report`` as UTF-8 JSON, non-ASCII preserved, and return ``path``.

    ensure_ascii=False keeps a real username like "skäfer" readable in the file
    instead of turning it into \\u00e4, which the operator then has to unescape
    by hand at 2am.
    """
    payload = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False)
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        raise FileNotFoundError(
            f"refusing to write {path}: no such directory {parent!r}")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.write("\n")
    return path
