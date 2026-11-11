"""Tests for MATT: hash typing, decoding, prose, the CLI, and the token guard.

unittest-native, so both of these work and must stay green:

    python3 -m unittest discover -s tests -v
    python3 -m pytest tests/ -v

The test the whole design rests on is TestStdlibOnlyGuard.test_core_imports_stdlib_only:
it asserts that nothing reachable from matt.core is a third-party or HTTP client
module. If someone later "just adds" requests to core for convenience, that test
fails, and the run that would have quietly cost tokens never happens.
"""

from __future__ import annotations

import ast
import io
import json
import os
import signal
import subprocess
import time
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Subprocess guards in TestStdlibOnlyGuard replace socket.socket with a function
# before importing matt, which works right up until urllib.request does `import
# ssl` and ssl does `class SSLSocket(socket)`. This process has already built ssl
# on a real socket module, so every child guard inherits that and stays import-
# safe; snapshot the real socket so a test that monkeypatches it cannot poison a
# later one.
REAL_SOCKET = sys.modules.get("socket")

from matt import capture, core, model, llmnr  # noqa: E402


# --------------------------------------------------------------------------
# fixtures: known-good wire shapes
# --------------------------------------------------------------------------

NTLMV2_AUTHENTICATOR = bytes.fromhex("0101000000000000" + "aabbccddeeff0011" + "00000000")
NTLMV2_PROOF = bytes.fromhex("68cd0d86" + "9b001dff" + "f59a593e" + "bdedce6a")
NTLMV2_CHALLENGE = bytes.fromhex("0123456789abcdef")
NTLMV2 = core.build_ntlmv2("skeith", "LISD", NTLMV2_AUTHENTICATOR, NTLMV2_PROOF,
                           NTLMV2_CHALLENGE)

# USER::DOMAIN:LM(16B):NT(16B):SERVERCHALLENGE(8B)
NETNTLMV1 = "skeith::LISD:" + "11" * 16 + ":" + "22" * 16 + ":" + "33" * 8

# hashcat 16800: <str><anonce-part>*<bssid>*<mac_ap>*<mac_cli>*<message>
# hashcat mode 22000 with a message-A shape is checked after this one, and a
# real message-A carries a >= 68-byte EAPOL frame; 64 bytes here is what a PMKID
# sweep actually produces, so the classifier must keep calling it 16800.
PMKID = ("STOREWiFi" + "ee" * 16 + "*" + "aa" * 6 + "*" + "bb" * 6 + "*" + "cc" * 6
         + "*" + "dd" * 16)

# hashcat 22000: <str><ap-nonce-part>*<bssid>*<mac_ap>*<mac_cli>*<s-nonce-part>*<message>
EH2912 = ("STOREWiFi" + "11" * 16 + "*" + "aa" * 6 + "*" + "bb" * 6 + "*" + "cc" * 6
          + "*" + "22" * 16 + "*" + "33" * 98)

MD5 = "5f4dcc3b5aa765d61d8327deb882cf99"  # md5("password")
SHA1 = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

SPEC_SAMPLES = [NTLMV2, NETNTLMV1, PMKID, EH2912, MD5, SHA1, SHA256]


def sample_report() -> dict:
    """A capture_report that looks like a real store-visit run: three hosts,
    one NTLMv2, one HTTP POST carrying an md5 password, one host with nothing on
    it. A non-ASCII username is in there on purpose: it exercises
    ensure_ascii=False further down.
    """
    return {
        "schema": core.SCHEMA_VERSION,
        "tool": "matt",
        "mode": "live",
        "interface": "wlan0",
        "gateway": "10.20.12.1",
        "clients": ["10.20.12.44", "10.20.12.57"],
        "hosts": {
            "10.20.12.44": {"payloads": [
                {"payload": NTLMV2, "protocol": "ntlmssp"},
            ]},
            "10.20.12.57": {"payloads": [
                {"payload": "POST /login HTTP/1.1\r\n"
                            "m4_fn=sk%C3%A4fer&m4_pw=hunter2&m4_dn=LISD\r\n",
                 "protocol": "http"},
            ]},
            "10.20.12.90": {"payloads": []},
        },
        "payloads": [],
        "capture": {"tool": "tcpdump", "returncode": 0, "note": ""},
    }


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="matt-test-")
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def path(self, name):
        return os.path.join(self.tmp, name)


# --------------------------------------------------------------------------
# 1. hash typing
# --------------------------------------------------------------------------

class TestTypeHash(unittest.TestCase):
    def test_ntlmv2_is_5600(self):
        self.assertEqual(core.type_hash(NTLMV2), ("ntlmv2", "5600"))

    def test_canonical_hashcat_5600_line_is_recognized(self):
        """The real hashcat -m 5600 example: USER::DOMAIN:SRVCHAL(8B):
        NTPROOF(16B):BLOB. Must classify as ntlmv2 -- this is the exact field
        order hashcat reads, so a hash MATT emits in this shape can actually be
        cracked (regression: MATT used to emit NTPROOF and SRVCHAL swapped,
        which hashcat rejected with a token-length error)."""
        line = ("admin::N46iSNekpT:08ca45b7d7ea58ee:"
                "88dcbe4446168966a153a0064958dac6:"
                "5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e00"
                "00000052920b85f78d013c31cdb3b92f5d765c783030")
        self.assertEqual(core.type_hash(line), ("ntlmv2", "5600"))

    def test_netntlmv1_is_5500(self):
        self.assertEqual(core.type_hash(NETNTLMV1), ("netntlmv1", "5500"))

    def test_wpa_pmkid_is_16800(self):
        self.assertEqual(core.type_hash(PMKID), ("wpa-pmkid", "16800"))

    def test_canonical_hashcat_16800_pmkid_is_recognized(self):
        """The real hcxtools/hashcat -m 16800 line: PMKID*MAC_AP*MAC_STA*ESSID."""
        line = ("2582a8281bf9d4308d6f5731d0e61c61"  # PMKID, 16 bytes
                "*4604ba734d4e"                      # MAC_AP, 6 bytes
                "*89acf0e761f4"                      # MAC_STA, 6 bytes
                "*53544f5245576946")                 # ESSID "STOREWiF", hex
        self.assertEqual(core.type_hash(line), ("wpa-pmkid", "16800"))
        # and it survives extraction off a harvester drop file
        found = core.candidates_from_payload(line.encode(), source="drop")
        self.assertTrue(any(c["kind"] == "wpa-pmkid" for c in found))

    def test_wpa_eh2912_is_22000(self):
        self.assertEqual(core.type_hash(EH2912), ("wpa-eh2912", "22000"))

    def test_md5_is_mode_0(self):
        self.assertEqual(core.type_hash(MD5), ("md5", "0"))

    def test_sha1_is_100(self):
        self.assertEqual(core.type_hash(SHA1), ("sha1", "100"))

    def test_sha256_is_1400(self):
        self.assertEqual(core.type_hash(SHA256), ("sha256", "1400"))

    def test_all_spec_types_resolve_exactly(self):
        """The five the spec names, plus the three digests, all resolve."""
        self.assertEqual({core.type_hash(p) for p in SPEC_SAMPLES}, {
            ("ntlmv2", "5600"), ("netntlmv1", "5500"), ("wpa-pmkid", "16800"),
            ("wpa-eh2912", "22000"), ("md5", "0"), ("sha1", "100"),
            ("sha256", "1400")})

    def test_modes_match_the_public_table(self):
        by_name = {NTLMV2: "ntlmv2", NETNTLMV1: "netntlmv1", PMKID: "wpa-pmkid",
                   EH2912: "wpa-eh2912", MD5: "md5", SHA1: "sha1", SHA256: "sha256"}
        for payload, name in by_name.items():
            self.assertEqual(core.type_hash(payload),
                             (name, core.HASHCAT_MODES[name]))

    def test_every_type_works_as_bytes_too(self):
        for payload in SPEC_SAMPLES:
            self.assertEqual(core.type_hash(payload),
                             core.type_hash(payload.encode("ascii")), payload[:24])

    def test_unknown_blob_returns_unknown_none(self):
        blob = "0123456789abcdef0123456789abcdef0123"  # 36 hex: no digest is 18 bytes
        self.assertEqual(core.type_hash(blob), ("unknown", None))

    def test_unknown_never_invents_a_mode(self):
        for blob in ("", "   ", b"\x00\x01\x02\x03", "hello world", "user=alice&pw=",
                     None, "zz" * 16, "aa" * 5):
            self.assertEqual(core.type_hash(blob), ("unknown", None), repr(blob))

    def test_a_real_ntlmv2_is_not_mislabeled_as_a_digest(self):
        kind, mode = core.type_hash(NTLMV2)
        self.assertEqual((kind, mode), ("ntlmv2", "5600"))
        self.assertNotEqual(mode, "0")

    def test_rejects_a_type_that_is_not_a_payload(self):
        with self.assertRaises(TypeError):
            core.type_hash(5600)


# --------------------------------------------------------------------------
# 2. decoding
# --------------------------------------------------------------------------

class TestDecoding(unittest.TestCase):
    def test_utf16le_decode(self):
        raw = "skeith".encode("utf-16le")
        self.assertEqual(core.decode_utf16le(raw), "skeith")
        self.assertEqual(core.decode_field(raw), ("utf-16le", "skeith"))

    def test_utf16le_nul_padding_is_stripped(self):
        raw = "LISD\\skeith".encode("utf-16le") + b"\x00\x00" * 4
        self.assertEqual(core.decode_utf16le(raw), "LISD\\skeith")

    def test_utf16le_non_ascii_survives(self):
        self.assertEqual(core.decode_utf16le("skäfer".encode("utf-16le")), "skäfer")

    def test_utf16le_odd_length_with_nul_tail(self):
        self.assertEqual(core.decode_utf16le("ab".encode("utf-16le") + b"\x00"), "ab")

    def test_utf16le_rejects_odd_length_without_nul(self):
        self.assertIsNone(core.decode_utf16le(b"\x00a\x01"))

    def test_utf16le_empty_input(self):
        self.assertEqual(core.decode_utf16le(b""), "")

    def test_utf16le_lone_surrogate_dropped_instead_of_crashing(self):
        # a corrupt length field yields an unpaired surrogate half: drop it, do
        # not raise, and do not put an unencodable char into a JSON report
        lone = bytes.fromhex("3dd8")          # U+D83D, a high surrogate, no pair
        self.assertEqual(core.decode_utf16le(lone), "")
        self.assertEqual(core.decode_utf16le(lone + "x".encode("utf-16le")), "x")
        json.dumps({"prose": core.decode_utf16le(lone)})

    def test_all_nul_field_is_empty_not_hex(self):
        self.assertEqual(core.decode_field(b"\x00" * 8), ("empty", ""))

    def test_binary_falls_back_to_hex(self):
        # 0xFF and 0x80 are illegal in UTF-16LE and in UTF-8 alike, so there is
        # no text reading of this field at all and it must go out as hex
        raw = b"\x00\x01\xff\xfe\x80\x81\x02\x03"
        method, text = core.decode_field(raw)
        self.assertEqual(method, "hex")
        self.assertTrue(text.startswith("hex:"))
        self.assertEqual(text, "hex:" + raw.hex())
        self.assertNotIn("\x00", text)

    def test_leading_nul_is_a_bom_not_a_letter(self):
        """0x00,0x01 must not silently become U+0100 with a BOM glued on the front.

        UTF-16LE will happily decode almost any even-length byte pair, so
        decode_utf16le strips the byte-order mark: what is left is only accepted
        as a username if it is printable, and a length field is not.
        """
        text = core.decode_utf16le(b"\x00\x01\x02\x03")
        self.assertNotIn("\ufeff", text)
        self.assertEqual(core.decode_utf16le(b"\xff\xfe" + "sk".encode("utf-16le")), "sk")
        # a real UTF-16LE field has a printable NUL-interleaved shape; a length
        # field does not, and the printable check is what separates them
        self.assertEqual(core.decode_field(b"\x05\x00\x00\x00"), ("hex", "hex:05000000"))

    def test_hex_fallback_is_distinguishable_from_text(self):
        self.assertEqual(core.decode_field(b"deadbeef")[0], "utf-8")
        self.assertTrue(core.decode_field(b"\xff\xfe\xff")[1].startswith("hex:"))

    def test_both_codecs_reading_the_same_ascii_is_labelled_utf8(self):
        # b"alice\r\n" is valid UTF-16LE too. The label is UTF-8 because there
        # are no interleaved NUL bytes, which is what a UTF-16LE field actually
        # looks like on the wire; the text is identical either way.
        method, text = core.decode_field(b"alice\r\n")
        self.assertEqual(method, "utf-8")
        self.assertEqual(text, "alice\r\n")
        # and the same name as NTLMSSP really sends it
        self.assertEqual(core.decode_field("alice".encode("utf-16le")),
                         ("utf-16le", "alice"))

    def test_latin_text_wins_the_tie_break(self):
        # "skäfer" is valid UTF-8 and valid-but-wrong UTF-16LE, so UTF-8 wins
        self.assertEqual(core.decode_field("skäfer".encode("utf-8")),
                         ("utf-8", "skäfer"))

    def test_a_real_username_survives_next_to_nul_padding(self):
        raw = "skeith".encode("utf-16le") + b"\x00" * 6
        self.assertEqual(core.decode_field(raw), ("utf-16le", "skeith"))

    def test_decode_field_rejects_str(self):
        with self.assertRaises(TypeError):
            core.decode_field("skeith")

    def test_decoding_is_deterministic(self):
        raw = NTLMV2_PROOF + b"\xff\xfe" + NTLMV2_CHALLENGE
        self.assertEqual(core.decode_field(raw), core.decode_field(raw))


# --------------------------------------------------------------------------
# 3. NTLMv2 roundtrip
# --------------------------------------------------------------------------

class TestNtlmv2Roundtrip(unittest.TestCase):
    def test_build_shape(self):
        self.assertEqual(
            NTLMV2,
            "skeith::LISD:0123456789abcdef:68cd0d869b001dfff59a593ebdedce6a:"
            "0101000000000000aabbccddeeff001100000000")

    def test_roundtrip(self):
        parsed = core.parse_ntlmv2(NTLMV2)
        self.assertEqual(parsed["username"], "skeith")
        self.assertEqual(parsed["realm"], "LISD")
        self.assertEqual(parsed["responsor"], NTLMV2_PROOF)
        self.assertEqual(parsed["challenge"], NTLMV2_CHALLENGE)
        self.assertEqual(parsed["authenticator"], NTLMV2_AUTHENTICATOR)
        rebuilt = core.build_ntlmv2(parsed["username"], parsed["realm"],
                                    parsed["authenticator"], parsed["responsor"],
                                    parsed["challenge"])
        self.assertEqual(rebuilt, NTLMV2)

    def test_roundtrip_with_unicode_username(self):
        candidate = core.build_ntlmv2("skäfer", "LISD", NTLMV2_AUTHENTICATOR,
                                      NTLMV2_PROOF, NTLMV2_CHALLENGE)
        self.assertEqual(core.parse_ntlmv2(candidate)["username"], "skäfer")

    def test_parse_rejects_wrong_field_count(self):
        with self.assertRaises(ValueError):
            core.parse_ntlmv2("skeith::LISD:0123:4567")

    def test_parse_survives_a_colon_in_the_upn(self):
        """'a:corp' is a legal account name and must not break the 5600 parse.

        Splitting left-to-right on ':' sees six fields and throws away the one
        credential type this tool exists to catch, so the hex fields are read
        off the end, anchored on '::'.
        """
        candidate = core.build_ntlmv2("a:corp", "LISD", NTLMV2_AUTHENTICATOR,
                                      NTLMV2_PROOF, NTLMV2_CHALLENGE)
        parsed = core.parse_ntlmv2(candidate)
        self.assertEqual(parsed["username"], "a:corp")
        self.assertEqual(parsed["realm"], "LISD")
        self.assertEqual(parsed["responsor"], NTLMV2_PROOF)
        self.assertEqual(core.ntlmv2_username(candidate), "a:corp")

    def test_ntlmv2_username_reads_the_identity_that_was_already_cleartext(self):
        self.assertEqual(core.ntlmv2_username(NTLMV2), "skeith")

    def test_parse_rejects_short_challenge(self):
        with self.assertRaises(ValueError):
            core.parse_ntlmv2(NTLMV2.replace(":0123456789abcdef:", ":0123:"))

    def test_build_validates_lengths(self):
        with self.assertRaises(ValueError):
            core.build_ntlmv2("u", "d", b"\x00" * 16, NTLMV2_PROOF, b"\x00" * 7)
        with self.assertRaises(ValueError):
            core.build_ntlmv2("u", "d", b"\x00" * 16, b"\x00" * 8, NTLMV2_CHALLENGE)

    def test_a_hash_never_becomes_a_password(self):
        """The honesty check: parsing yields bytes to crack, not a secret."""
        parsed = core.parse_ntlmv2(NTLMV2)
        self.assertNotIn("password", parsed)
        self.assertIsInstance(parsed["responsor"], bytes)

    def test_ntlmv2_target_reads_the_server_from_the_av_pairs(self):
        def av(avid, text):
            v = text.encode("utf-16le")
            return bytes([avid & 0xFF, avid >> 8, len(v) & 0xFF, len(v) >> 8]) + v
        blob = (bytes.fromhex("0101") + b"\x00\x00" + b"\x00\x00\x00\x00"
                + b"\x00" * 8 + b"\x11" * 8 + b"\x00\x00\x00\x00"
                + av(0x0002, "CORP") + av(0x0001, "FILESERVER01")
                + b"\x00\x00\x00\x00")
        cand = core.build_ntlmv2("jdoe", "CORP", blob, NTLMV2_PROOF, NTLMV2_CHALLENGE)
        self.assertEqual(core.ntlmv2_target(cand), "FILESERVER01")

    def test_ntlmv2_target_is_none_without_a_server_name(self):
        self.assertIsNone(core.ntlmv2_target(NTLMV2))

    def test_assembled_ntlmv2_payload_names_the_user(self):
        """The account name and domain ride in the clear inside a 5600 hash, so a
        captured NTLMv2 payload must come back with username/domain attached --
        without any cracking having happened."""
        found = core.candidates_from_payload(NTLMV2)
        self.assertEqual(len(found), 1, found)
        self.assertEqual(found[0]["kind"], "ntlmv2")
        self.assertEqual(found[0]["hashcat_mode"], "5600")
        self.assertEqual(found[0]["username"], "skeith")
        self.assertEqual(found[0]["domain"], "LISD")


# --------------------------------------------------------------------------
# 4. prose
# --------------------------------------------------------------------------

class TestStage2Prose(unittest.TestCase):
    def test_prose_names_mode_host_and_candidate(self):
        finding = {"kind": "ntlmv2", "hashcat_mode": "5600", "host": "10.20.12.44",
                   "protocol": "ntlmssp", "candidate": NTLMV2, "username": "skeith"}
        prose = core.stage2_prose(finding)
        self.assertTrue(prose.strip())
        for token in ("5600", "10.20.12.44", "skeith", NTLMV2):
            self.assertIn(token, prose)

    def test_prose_for_unknown_kind_is_still_nonempty(self):
        prose = core.stage2_prose({"kind": "unknown", "hashcat_mode": None,
                                   "host": "10.20.12.90", "candidate": "hex:00ff"})
        self.assertTrue(prose.strip())
        self.assertIn("manual review", prose)

    def test_prose_never_invents_a_password(self):
        for kind, mode in core.HASHCAT_MODES.items():
            prose = core.stage2_prose({"kind": kind, "hashcat_mode": mode,
                                       "candidate": "cand", "host": "h",
                                       "protocol": "p"})
            lowered = prose.lower()
            self.assertTrue(prose.strip())
            self.assertNotIn("password is", lowered)
            self.assertNotIn("cracked", lowered)

    def test_prose_survives_a_sparse_finding(self):
        self.assertTrue(core.stage2_prose({}).strip())

    def test_every_mode_has_a_hint(self):
        for mode in core.HASHCAT_MODES.values():
            self.assertIn(mode, core._MODE_HINTS)


# --------------------------------------------------------------------------
# 5. analyze(): token-free by default, stub-injectable
# --------------------------------------------------------------------------

class TestAnalyze(unittest.TestCase):
    def test_default_run_makes_zero_network_calls(self):
        analysis = core.analyze(sample_report())
        self.assertEqual(analysis["analysis"]["network_calls"], 0)
        self.assertIsNone(analysis["analysis"]["model_used"])
        self.assertEqual(analysis["analysis"]["engine"], "builtin:stage2_prose")

    def test_host_count_and_credential_bearing(self):
        stats = core.analyze(sample_report())["analysis"]
        self.assertEqual(stats["host_count"], 3)
        self.assertGreaterEqual(stats["credential_bearing"], 2)
        self.assertLessEqual(stats["credential_bearing"], stats["candidate_count"])

    def test_every_finding_has_nonempty_prose(self):
        for finding in core.analyze(sample_report())["analysis"]["findings"]:
            self.assertIsInstance(finding["prose"], str)
            self.assertTrue(finding["prose"].strip(), finding)

    def test_findings_keep_their_hashcat_mode(self):
        kinds = {f["kind"]: f["hashcat_mode"]
                 for f in core.analyze(sample_report())["analysis"]["findings"]}
        self.assertEqual(kinds.get("ntlmv2"), "5600")
        self.assertEqual(kinds.get("md5"), "0")

    def test_injected_stub_model_is_used_and_counted(self):
        calls = []

        def stub(finding):
            calls.append(finding["kind"])
            return "stub prose for " + finding["kind"]

        analysis = core.analyze(sample_report(), model=stub, model_name="stub")
        stats = analysis["analysis"]
        self.assertGreater(len(calls), 0)
        self.assertEqual(stats["model_used"], "stub")
        self.assertEqual(stats["network_calls"], stats["candidate_count"])
        for finding in stats["findings"]:
            self.assertTrue(finding["prose"].startswith("stub prose for"))

    def test_stub_returning_junk_falls_back_to_builtin_prose(self):
        for junk in ("", "   ", None, 42):
            analysis = core.analyze(sample_report(), model=lambda f, j=junk: j)
            for finding in analysis["analysis"]["findings"]:
                self.assertTrue(finding["prose"].strip(), junk)

    def test_analyze_does_not_mutate_its_input(self):
        report = sample_report()
        before = json.dumps(report, sort_keys=True, ensure_ascii=False)
        core.analyze(report)
        self.assertEqual(json.dumps(report, sort_keys=True, ensure_ascii=False), before)

    def test_analyze_twice_is_deterministic(self):
        one = core.analyze(sample_report())["analysis"]["findings"]
        two = core.analyze(sample_report())["analysis"]["findings"]
        self.assertEqual([f["prose"] for f in one], [f["prose"] for f in two])

    def test_empty_report_yields_zero_findings(self):
        stats = core.analyze({"hosts": {}, "payloads": []})["analysis"]
        self.assertEqual(stats["candidate_count"], 0)
        self.assertEqual(stats["credential_bearing"], 0)
        self.assertEqual(stats["network_calls"], 0)

    def test_pre_extracted_candidates_are_passed_through(self):
        report = {"hosts": {"1.2.3.4": {}},
                  "candidates": [{"kind": "ntlmv2", "hashcat_mode": "5600",
                                  "candidate": NTLMV2, "host": "1.2.3.4"}]}
        stats = core.analyze(report)["analysis"]
        self.assertEqual(stats["candidate_count"], 1)
        self.assertEqual(stats["credential_bearing"], 1)

    def test_live_report_mirror_is_not_double_counted(self):
        """The live CLI writes the same payloads into BOTH report['payloads']
        and report['hosts']['the wire']['payloads']. That mirror must decode to
        one finding per credential, not two (regression: it used to double)."""
        post = ("POST /login HTTP/1.1\r\n"
                "m4_fn=alice&m4_pw=hunter2&m4_dn=CORP\r\n")
        payloads = [{"payload": post, "protocol": "http"}]
        report = {
            "schema": core.SCHEMA_VERSION, "mode": "live", "interface": "wlan0",
            "payloads": payloads,
            "hosts": {"the wire": {"payloads": payloads}},
        }
        cands = core.extract_candidates(report)
        # exactly the candidates of ONE copy of the payload, not two
        self.assertEqual(len(cands), len(core.candidates_from_payload(
            core._coerce_bytes(post))))
        keys = [(c["kind"], c["candidate"]) for c in cands]
        self.assertEqual(len(keys), len(set(keys)), "duplicate candidates: %r" % keys)
        # and the surviving copy keeps its host attribution, not the flat "" one
        self.assertTrue(all(c.get("host") == "the wire" for c in cands))

    def test_http_credential_names_its_destination(self):
        """A captured web login must record WHERE it goes (Host + path), so two
        logins in one report are never mixed up and the prose names the target."""
        payload = ("POST /portal/login HTTP/1.1\r\nHost: intranet.corp.local\r\n"
                   "\r\nUsername=msmith&Password=Summer2026!")
        found = core.candidates_from_payload(payload)
        md5 = [c for c in found if c["kind"] == "md5"][0]
        self.assertEqual(md5["target"], "intranet.corp.local/portal/login")
        self.assertEqual(md5["username"], "msmith")
        prose = core.stage2_prose(dict(md5, host="10.0.4.50"))
        self.assertIn("intranet.corp.local/portal/login", prose)
        self.assertIn("msmith", prose)

    def test_model_must_be_callable(self):
        with self.assertRaises(TypeError):
            core.analyze(sample_report(), model="gpt")
        with self.assertRaises(TypeError):
            core.analyze("not a report")

    def test_none_model_is_the_builtin_writer_not_an_implicit_call(self):
        """analyze(report, None) must be indistinguishable from analyze(report)."""
        plain = core.analyze(sample_report())["analysis"]["findings"]
        explicit = core.analyze(sample_report(), model=None)["analysis"]["findings"]
        self.assertEqual([f["prose"] for f in plain], [f["prose"] for f in explicit])


# --------------------------------------------------------------------------
# 6. report files
# --------------------------------------------------------------------------

class TestWriteReport(TempDirCase):
    def test_writes_valid_utf8_json(self):
        target = self.path("capture_report.json")
        core.write_report(core.analyze(sample_report()), target)
        with open(target, "rb") as handle:
            raw = handle.read()
        raw.decode("utf-8")  # must not raise
        json.loads(raw.decode("utf-8"))

    def test_non_ascii_is_preserved_not_escaped(self):
        target = self.path("report.json")
        core.write_report({"user": "skäfer", "note": "Søren ✓"}, target)
        with open(target, "rb") as handle:
            text = handle.read().decode("utf-8")
        self.assertIn("skäfer", text)
        self.assertNotIn("\\u00e4", text)

    def test_roundtrip_through_disk(self):
        target = self.path("capture_report.json")
        analysis = core.analyze(sample_report())
        core.write_report(analysis, target)
        reread = core.analyze(core.read_report(target))["analysis"]["findings"]
        self.assertEqual([f["prose"] for f in reread],
                         [f["prose"] for f in analysis["analysis"]["findings"]])

    def test_missing_directory_is_loud(self):
        with self.assertRaises(FileNotFoundError):
            core.write_report({}, self.path("nope/report.json"))


# --------------------------------------------------------------------------
# 7. the token guard
# --------------------------------------------------------------------------

class TestStdlibOnlyGuard(TempDirCase):
    """core.py may import the standard library and nothing else.

    Enforced two ways on purpose: AST over the source (catches an import hidden
    inside a function) and sys.modules after a real import (catches a transitive
    dependency the source does not mention).
    """

    HTTP_WORDS = ("http", "urllib", "requests", "socket", "ssl", "aiohttp",
                  "httpx", "grpc", "anthropic", "openai")
    BANNED_IN_CORE = ("urllib", "requests", "http", "httpx", "aiohttp", "socket",
                      "anthropic", "openai")

    def stdlib_names(self):
        if hasattr(sys, "stdlib_module_names"):
            return set(sys.stdlib_module_names)
        import sysconfig  # pragma: no cover - py<3.10 fallback
        return set(sys.builtin_module_names) | {
            name.split(".")[0] for name in os.listdir(
                os.path.join(sysconfig.get_paths()["stdlib"]))}

    def imports_in(self, path, module_level_only=False):
        """Top-level import names in ``path``, including ones buried in functions.

        module_level_only=True answers the stricter question: what does merely
        importing this file pull in? That is the difference between "this module
        needs socket" and "this module opens a socket when you ask it to", and
        the token guard cares about the first one.
        """
        with open(path, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        nodes = tree.body if module_level_only else ast.walk(tree)
        names = set()
        for node in nodes:
            if isinstance(node, ast.Import):
                names.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    names.add(node.module.split(".")[0])
        return names

    def top_level_imports(self, path):
        return self.imports_in(path)

    def core_path(self):
        return os.path.join(REPO_ROOT, "matt", "core.py")

    def test_core_file_exists(self):
        self.assertTrue(os.path.isfile(self.core_path()))

    def test_core_imports_stdlib_only(self):
        allowed = self.stdlib_names() | {"matt", "__future__"}
        offenders = sorted(self.top_level_imports(self.core_path()) - allowed)
        self.assertEqual(offenders, [],
                         "matt/core.py must import the standard library only, "
                         f"found third-party: {offenders}")

    def test_core_never_imports_an_http_client(self):
        for name in self.top_level_imports(self.core_path()):
            self.assertNotIn(name, self.BANNED_IN_CORE,
                             f"{name} is a network module and must not appear in "
                             "matt/core.py: that is how a free run starts costing "
                             "tokens")

    def test_no_http_module_is_reachable_from_core(self):
        before = set(sys.modules)
        import importlib
        importlib.reload(core)
        newly = set(sys.modules) - before
        allowed = self.stdlib_names()
        offenders = sorted(n.split(".")[0] for n in newly
                           if any(word in n.lower() for word in self.HTTP_WORDS)
                           and n.split(".")[0] not in allowed)
        self.assertEqual(offenders, [])

    def test_no_module_talks_at_import_time(self):
        """Importing the package must not construct a socket or spawn a process.

        The network modules are pre-imported with the REAL socket module first,
        then every socket constructor is boomed: an import-time connection would
        still trip, and ssl gets to build on a real socket class instead of the
        trap.
        """
        code = (
            "import http.client, ssl, urllib.request  # real socket, loaded first\n"
            "import socket, subprocess, sys\n"
            "def boom(*a, **k):\n"
            "    raise AssertionError('socket constructed at import time')\n"
            "for name in ('socket', 'create_connection', 'create_server'):\n"
            "    setattr(socket, name, boom)\n"
            "subprocess.Popen = boom\n"
            "subprocess.run = boom\n"
            f"sys.path.insert(0, {REPO_ROOT!r})\n"
            "import matt, matt.core, matt.capture, matt.model, matt.cli\n"
            "import os\n"
            "print('IMPORTS-CLEAN' if 'socket' in sys.modules else 'NO-SOCKET-IMPORT')\n"
        )
        proc = subprocess.run([sys.executable, "-I", "-c", code],
                              capture_output=True, text=True, timeout=120)
        self.assertIn("IMPORTS-CLEAN", proc.stdout, proc.stderr)

    def test_core_and_capture_never_import_socket_at_all(self):
        """Stronger, cheaper guard: the offline half of MATT must not need socket.

        core.py and capture.py are what run when no model is configured. Neither
        may import socket at module level, so merely importing them cannot drag
        in the network stack; capture.py may still import it inside a function,
        which is how it reads the routing table on demand. model.py is excluded
        on purpose: it legitimately imports urllib, and the import-time probe
        above covers it.
        """
        for name in ("core.py", "capture.py"):
            path = os.path.join(REPO_ROOT, "matt", name)
            module_level = self.imports_in(path, module_level_only=True)
            self.assertNotIn("socket", module_level,
                             f"matt/{name} imports socket at module level; it is "
                             "on the zero-token path")
            self.assertNotIn("urllib", module_level,
                             f"matt/{name} imports urllib at module level")
            self.assertTrue(os.path.getsize(path))

    def test_the_guard_actually_guards(self):
        """Prove the AST check fails on a file that imports requests."""
        probe = os.path.join(self.tmp, "probe_core.py")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("import requests\nimport json\n")
        allowed = self.stdlib_names() | {"matt", "__future__"}
        self.assertEqual(sorted(self.top_level_imports(probe) - allowed), ["requests"])


# --------------------------------------------------------------------------
# 8. model.py: the one and only network call
# --------------------------------------------------------------------------

class TestModel(unittest.TestCase):
    def test_sentinel_aliases(self):
        self.assertEqual(model.LEGACY_SENTINEL, "iiiCLAUDEiii")
        self.assertEqual(model.API_SENTINEL, "__ANTHROPIC__")

    def test_legacy_sentinel_is_rewritten_to_the_real_one(self):
        endpoint = model.resolve_endpoint(
            base_url="https://proxy.example/" + model.LEGACY_SENTINEL + "/v1",
            api_key="k", env={})
        self.assertNotIn(model.LEGACY_SENTINEL, endpoint["base_url"])
        self.assertIn(model.API_SENTINEL, endpoint["base_url"])

    def test_no_endpoint_raises_loudly(self):
        with self.assertRaises(model.ModelConfigError) as ctx:
            model.resolve_endpoint(env={})
        message = str(ctx.exception)
        self.assertIn("--use-model", message)
        self.assertIn("endpoint", message.lower())
        self.assertIn("MATT_MODEL_URL", message)

    def test_endpoint_without_key_raises_loudly(self):
        with self.assertRaises(model.ModelConfigError) as ctx:
            model.resolve_endpoint(base_url="https://api.example.test", env={})
        self.assertIn("no API key", str(ctx.exception))

    def test_no_silent_fallback_to_the_default_endpoint(self):
        """A key alone must not quietly send captured credentials to the public API."""
        with self.assertRaises(model.ModelConfigError):
            model.resolve_endpoint(api_key="sk-test", env={})

    def test_default_endpoint_needs_an_explicit_opt_in(self):
        endpoint = model.resolve_endpoint(api_key="sk-test",
                                          env={"MATT_ALLOW_DEFAULT_ENDPOINT": "1"})
        self.assertEqual(endpoint["base_url"], model.DEFAULT_BASE_URL)

    def test_build_request_shape(self):
        url, headers, body = model.build_request(
            {"base_url": "https://api.example.test", "api_key": "sk-test",
             "model": "claude-sonnet-5-5"}, "hello")
        self.assertEqual(url, "https://api.example.test/v1/messages")
        self.assertEqual(headers["x-api-key"], "sk-test")
        self.assertEqual(headers["anthropic-version"], "2023-06-01")
        self.assertEqual(body["model"], "claude-sonnet-5-5")
        self.assertEqual(body["messages"][0]["content"], "hello")

    def test_call_model_makes_exactly_one_request(self):
        seen = []

        def opener(url, headers, payload):
            seen.append((url, json.loads(payload.decode("utf-8"))))
            return json.dumps({"content": [{"type": "text",
                                            "text": "prose here"}]}).encode("utf-8")

        text = model.call_model("hello", base_url="https://api.example.test",
                                api_key="k", env={}, opener=opener)
        self.assertEqual(text, "prose here")
        self.assertEqual(len(seen), 1)

    def test_empty_completion_is_an_error_not_a_fabrication(self):
        def opener(url, headers, payload):
            return b'{"content": [{"type": "text", "text": "  "}]}'

        with self.assertRaises(model.ModelTransportError):
            model.call_model("hi", base_url="https://api.example.test", api_key="k",
                             env={}, opener=opener)

    def test_garbage_response_is_an_error(self):
        def opener(url, headers, payload):
            return b"<html>502 bad gateway</html>"

        with self.assertRaises(model.ModelTransportError):
            model.call_model("hi", base_url="https://api.example.test", api_key="k",
                             env={}, opener=opener)

    def test_no_endpoint_never_reaches_the_opener(self):
        calls = []

        def opener(url, headers, payload):  # pragma: no cover - must not run
            calls.append(url)

        with self.assertRaises(model.ModelConfigError):
            model.call_model("hi", env={}, opener=opener)
        self.assertEqual(calls, [])

    def test_analyze_with_model_writer_costs_one_call_per_finding(self):
        calls = []

        def opener(url, headers, payload):
            calls.append(url)
            return json.dumps({"content": [{"type": "text",
                                            "text": "model prose"}]}).encode()

        writer = model.model_writer(base_url="https://api.example.test", api_key="k",
                                    env={}, opener=opener)
        report = sample_report()
        expected = len(core.extract_candidates(report))
        stats = core.analyze(report, model=writer, model_name="fake")["analysis"]
        self.assertEqual(len(calls), expected)
        self.assertEqual(stats["network_calls"], stats["candidate_count"])
        self.assertTrue(all(f["prose"] == "model prose" for f in stats["findings"]))


# --------------------------------------------------------------------------
# 9. capture helpers
# --------------------------------------------------------------------------

class TestCaptureHelpers(unittest.TestCase):
    ROUTE = ("Iface\tDestination\tGateway \tFlags\tRef\tUse\tMetric\tMask\tMtt\tWin"
             "\tIrtt\n"
             "wlan0\t00000000\t010CB40A\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
             "wlan0\t000C140A\t00000000\t0001\t0\t0\t303\t00FCFFFF\t0\t0\t0\n")

    def test_discover_gateway_reads_the_default_route(self):
        self.assertEqual(capture.discover_gateway(self.ROUTE), "10.180.12.1")

    def test_discover_gateway_without_a_default_route(self):
        header, _, non_default = self.ROUTE.splitlines()
        with self.assertRaises(capture.GatewayDiscoveryError):
            capture.discover_gateway(header + "\n" + non_default + "\n")

    def test_discover_clients_skips_failed_neighbours(self):
        neigh = ("10.20.12.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
                 "10.20.12.44 dev wlan0 lladdr 11:22:33:44:55:66 REACHABLE\n"
                 "10.20.12.99 dev wlan0 FAILED\n")
        self.assertEqual(capture.discover_clients(neigh), ["10.20.12.1", "10.20.12.44"])

    def test_root_gate(self):
        capture.require_root(0)
        with self.assertRaises(PermissionError):
            capture.require_root(1000)

    def test_interface_gate(self):
        capture.require_interface("lo")
        with self.assertRaises(FileNotFoundError) as ctx:
            capture.require_interface("wlan9")
        self.assertIn("wlan9", str(ctx.exception))

    def test_authorization_gate(self):
        capture.require_authorization(True)
        with self.assertRaises(PermissionError) as ctx:
            capture.require_authorization(False)
        self.assertIn("--i-have-written-authorization", str(ctx.exception))

    def test_signal_144_is_reported_as_a_crashed_capture(self):
        note = capture.capture_note(capture.SIGNAL_144)
        self.assertIn("144", note)
        self.assertIn("CRASHED", note)
        self.assertNotIn("0 credentials", note)
        self.assertEqual(capture.SIGNAL_144, core.SIGNAL_144)

    def test_missing_binary_is_recorded_not_raised(self):
        def runner(cmd, kwargs):
            return subprocess.CompletedProcess(cmd, 127, stdout="", stderr="")

        result = capture.capture_payloads("wlan0", duration=0.01,
                                         capture_tool="definitely-not-a-tool",
                                         runner=runner)
        self.assertEqual(result["returncode"], 127)
        self.assertIn("not found", result["note"])

    def test_hexdump_payloads_become_candidates(self):
        """A tcpdump hex row is 16 bytes, so the ASCII is what gets recovered.

        NTLMv2 bytes do not survive a hexdump: the printable-only tail is all
        that decodes, which is exactly why the prose says "authenticated without
        naming itself" rather than inventing a username.
        """
        row = "0x0000:  6100 6c00 6900 6300 6500 0d00 0a00 ff00"
        fake = subprocess.CompletedProcess(["tcpdump"], 0, stdout=row + "\n",
                                           stderr="")
        result = capture.capture_payloads("wlan0", duration=0.01,
                                         capture_tool="tcpdump",
                                         runner=lambda c, k: fake)
        self.assertEqual(len(result["payloads"]), 1)
        self.assertEqual(result["payloads"][0]["payload"],
                         "61006c006900630065000d000a00ff00")
        found = core.candidates_from_payload(result["payloads"][0]["payload"])
        self.assertTrue(found)
        self.assertIn("alice", found[0]["candidate"])

    def test_multi_row_packet_is_reassembled_into_one_payload(self):
        """A real packet spans many hex rows; its bytes must come back as ONE
        payload so a credential that crosses a 16-byte boundary is still found.
        Regression: rows used to be stored individually, shredding every real
        NTLMv2/HTTP-POST/PMKID credential across payload boundaries."""
        post = b"POST /login HTTP/1.1\r\nUsername=alice&Password=hunter2\r\n"
        # render the bytes as a tcpdump -X packet: summary line + 16-byte rows
        rows = ["12:00:00.0 IP 10.0.0.5.80 > 10.0.0.9.443: Flags [P.], length %d"
                % len(post)]
        for i in range(0, len(post), 16):
            chunk = post[i:i + 16]
            hexpart = " ".join(chunk[j:j + 2].hex() for j in range(0, len(chunk), 2))
            rows.append("\t0x%04x:  %s" % (i, hexpart))
        stdout = "\n".join(rows) + "\n"
        fake = subprocess.CompletedProcess(["tcpdump"], 0, stdout=stdout, stderr="")
        result = capture.capture_payloads("wlan0", duration=0.01,
                                          capture_tool="tcpdump",
                                          runner=lambda c, k: fake)
        self.assertEqual(len(result["payloads"]), 1, result["payloads"])
        self.assertEqual(bytes.fromhex(result["payloads"][0]["payload"]), post)
        found = core.candidates_from_payload(
            core._coerce_bytes(result["payloads"][0]["payload"]))
        kinds = {c["kind"] for c in found}
        self.assertIn("md5", kinds)  # Password=hunter2 -> an md5 candidate

    def test_two_packets_are_two_payloads(self):
        """Offset resetting to 0 marks the next packet even without a summary."""
        stdout = ("\t0x0000:  4854 5450 2f31 2e31 2032 3030 204f 4b0d\n"
                  "\t0x0010:  0a48 6f73 743a 2061 0d0a 0d0a 0000 0000\n"
                  "12:00:00 IP a > b: Flags [P.]\n"
                  "\t0x0000:  6100 6c00 6900 6300 6500 0d00 0a00 ff00\n")
        fake = subprocess.CompletedProcess(["tcpdump"], 0, stdout=stdout, stderr="")
        result = capture.capture_payloads("wlan0", duration=0.01,
                                          capture_tool="tcpdump",
                                          runner=lambda c, k: fake)
        self.assertEqual(len(result["payloads"]), 2, result["payloads"])

    def test_summary_line_ports_are_parsed(self):
        self.assertEqual(
            capture.parse_summary_ports(
                "12:00:00.1 IP 10.0.0.9.54321 > 10.0.0.5.21: Flags [P.]"),
            {"src": "10.0.0.9", "sport": 54321, "dst": "10.0.0.5", "dport": 21})
        v6 = capture.parse_summary_ports(
            "12:00:00.1 IP6 fe80::1.546 > ff02::1:2.547: UDP")
        self.assertEqual((v6["sport"], v6["dport"]), (546, 547))
        self.assertIsNone(capture.parse_summary_ports("tcpdump: 3 packets captured"))

    def test_capture_attaches_ports_so_ftp_and_pop3_are_told_apart(self):
        """The real win: identical USER/PASS verbs on different ports label
        correctly end to end, which the verbs alone cannot do."""
        def pkt(summary, payload):
            rows = [summary]
            for i in range(0, len(payload), 16):
                chunk = payload[i:i + 16]
                hx = " ".join(chunk[j:j + 2].hex() for j in range(0, len(chunk), 2))
                rows.append("\t0x%04x:  %s" % (i, hx))
            return rows
        out = (pkt("11:11:11.1 IP 10.0.0.9.5001 > 10.0.0.5.21: Flags [P.]",
                   b"USER alice\r\nPASS s3cret\r\n")
               + pkt("11:11:12.2 IP 10.0.0.9.5002 > 10.0.0.6.110: Flags [P.]",
                     b"USER bob\r\nPASS hunter2\r\n"))
        fake = subprocess.CompletedProcess(["tcpdump"], 0,
                                           stdout="\n".join(out) + "\n", stderr="")
        result = capture.capture_payloads("wlan0", duration=0.01,
                                          capture_tool="tcpdump",
                                          runner=lambda c, k: fake)
        self.assertEqual(result["payloads"][0]["dport"], 21)
        self.assertEqual(result["payloads"][1]["dport"], 110)
        findings = core.analyze({"payloads": result["payloads"]})["analysis"]["findings"]
        by_user = {f["username"]: f["kind"] for f in findings}
        self.assertEqual(by_user["alice"], "ftp")
        self.assertEqual(by_user["bob"], "pop3")

    def test_large_packet_reassembles_and_decodes_a_buried_credential(self):
        """Enterprise grade: a large (jumbo / GRO-coalesced) packet must
        reassemble into ONE payload and a credential buried deep inside it must
        still be decoded -- not lost to a packet-size or row-count limit."""
        body = (b"A" * 48000
                + b"\r\nUsername=enterprise_admin&Password=Ent3rprise!2026\r\n"
                + b"B" * 2000)
        rows = ["12:00:00 IP 10.0.0.5.443 > 10.0.0.9.80: Flags [P.], length %d"
                % len(body)]
        for i in range(0, len(body), 16):
            chunk = body[i:i + 16]
            hexpart = " ".join(chunk[j:j + 2].hex() for j in range(0, len(chunk), 2))
            rows.append("\t0x%06x:  %s" % (i, hexpart))
        fake = subprocess.CompletedProcess(["tcpdump"], 0,
                                           stdout="\n".join(rows) + "\n", stderr="")
        result = capture.capture_payloads("wlan0", duration=0.01,
                                          capture_tool="tcpdump",
                                          runner=lambda c, k: fake)
        self.assertEqual(len(result["payloads"]), 1)
        self.assertEqual(bytes.fromhex(result["payloads"][0]["payload"]), body)
        found = core.candidates_from_payload(
            bytes.fromhex(result["payloads"][0]["payload"]))
        users = {f.get("username") for f in found if f.get("credential_bearing")}
        self.assertIn("enterprise_admin", users)

    def test_hexdump_row_parses_both_tool_layouts(self):
        rows = {
            # tcpdump: "0xOFFSET:" prefix, hex in 4-byte runs, ASCII gutter
            "0x0000:  6100 6c00 6900 6300 6500 0d00 0a00 ff00": (
                "61006c006900630065000d000a00ff00"),
            "0x0010:  4854 5450 2f31 2e31 2032 3030 204f 4b0d": (
                "485454502f312e3120323030204f4b0d"),
            "0x0000:  4500 0054 1c46 4000 4006 b1e4 0a00 0005:": (
                "450000541c4640004006b1e40a000005"),
            # tshark -x: offset column, single-byte hex, double-space gutter
            "0000   45 00 00 54 1c 46 40 00  40 06 b1 e4 0a 00 00 05": (
                "450000541c4640004006b1e40a000005"),
        }
        for row, expected in rows.items():
            self.assertEqual(capture.hexdump_row(row), expected, row)

    def test_hexdump_row_ignores_everything_that_is_not_a_hex_row(self):
        for row in ("12:34:56.789012 IP 10.0.0.5.445 > 10.0.0.1.49152: Flags [S]",
                    "0x0000:  4500 0054",              # a real short final row
                    "total packets received: 12",
                    "tcpdump: verbose output suppressed",
                    "",
                    "   "):
            self.assertIsNone(capture.hexdump_row(row), row)

    def test_hexdump_row_does_not_swallow_the_ascii_gutter(self):
        """The gutter is the payload printed as text, so it is made of hex letters.

        tcpdump puts it after only two spaces, and words like "OK" and "alice"
        are legal hex characters. Anything that finds the hex by splitting on
        whitespace either swallows them into the payload or rejects a perfectly
        good row, and a payload that gained two bytes decodes every NTLM field
        one byte to the left. So the hex is located by shape instead, and these
        rows must come back at exactly 32 hex digits.
        """
        rows = {
            "0x0010:  4854 5450 2f31 2e31 2032 3030 204f 4b0d  HTTP/1. 200 OK.":
                "485454502f312e3120323030204f4b0d",
            "0x0010:  4854 5450 2f31 2e31 2032 3030 204f 4b0d  HTTP/1. OK  alice":
                "485454502f312e3120323030204f4b0d",
            "0x0030:  4500 0054 1c46 4000 4006 b1e4 0a00 0005  OK":
                "450000541c4640004006b1e40a000005",
            "0010  4854 5450 2f31 2e31 2032 3030 204f 4b0d  :HTTP/1. OK.":
                "485454502f312e3120323030204f4b0d",
        }
        for row, expected in rows.items():
            got = capture.hexdump_row(row)
            self.assertEqual(got, expected, row)
            self.assertEqual(len(got), 32, row)

    def test_gutter_that_starts_with_a_hex_character_is_not_dropped(self):
        """The ASCII gutter is the payload as text, so it often begins with a hex
        character (byte 0x34 is '4', 0x61 is 'a'). The row must still parse to its
        full hex body. Regression: a greedy hex-run bridged the two-space gap into
        that first gutter character and rejected the whole row, silently dropping
        a large fraction of every real capture."""
        rows = {
            "\t0x0010:  340f 2dc6 9283 5da9 2607 6bc0 0000 0000  4.-...].&.k.....":
                "340f2dc692835da926076bc000000000",
            "\t0x0000:  6100 6c00 6900 6300 6500 0d00 0a00 6200  a.l.i.c.e...b.":
                "61006c006900630065000d000a006200",
        }
        for row, expected in rows.items():
            self.assertEqual(capture.hexdump_row(row), expected, row)

    def test_dry_run_touches_nothing(self):
        result = capture.capture_payloads("wlan0", dry_run=True)
        self.assertEqual(result["payloads"], [])
        self.assertIn("dry run", result["note"])
        self.assertFalse(capture.start_ettercap("wlan0", "10.0.0.1",
                                                dry_run=True)["started"])

    def test_hexdump_payloads_become_candidates(self):
        """A tcpdump hex row is 16 bytes, so the ASCII is what gets recovered.

        NTLMv2 bytes do not survive a hexdump: the printable-only tail is all
        that decodes, which is exactly why the prose says "authenticated without
        naming itself" rather than inventing a username.
        """
        fake = subprocess.CompletedProcess(
            ["tcpdump"], 0,
            stdout="0x0000:  6100 6c00 6900 6300 6500 0d00 0a00 ff00\n", stderr="")
        result = capture.capture_payloads("wlan0", duration=0.01,
                                         capture_tool="tcpdump",
                                         runner=lambda c, k: fake)
        self.assertEqual(len(result["payloads"]), 1)
        self.assertEqual(result["payloads"][0]["payload"], "61006c006900630065000d000a00ff00")
        found = core.candidates_from_payload(result["payloads"][0]["payload"])
        self.assertTrue(found)
        self.assertIn("alice", found[0]["candidate"])

    def test_hexdump_rows_that_are_not_hex_are_ignored(self):
        stdout = ("12:34:56.789012 IP 10.0.0.5.445 > 10.0.0.1.49152: Flags [S]\n"
                  "0x0000:  4500 0054 1c46 4000 4006 b1e4 0a00 0005\n")
        fake = subprocess.CompletedProcess(["tcpdump"], 0, stdout=stdout, stderr="")
        result = capture.capture_payloads("wlan0", duration=0.01,
                                         capture_tool="tcpdump",
                                         runner=lambda c, k: fake)
        self.assertEqual(len(result["payloads"]), 1)

    def test_tcpdump_command_requests_a_hex_dump(self):
        """The tcpdump invocation must ask for hex, or hexdump_row sees nothing.

        hexdump_row() parses tcpdump's -X layout; a command without a hex flag
        prints only summary lines and every capture comes back empty.
        """
        seen = {}

        def runner(cmd, kwargs):
            seen["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        capture.capture_payloads("wlan0", duration=1, capture_tool="tcpdump",
                                 runner=runner)
        self.assertTrue(
            {"-X", "-x", "-XX", "-xx"} & set(seen["cmd"]),
            "tcpdump command has no hex flag: %r" % (seen["cmd"],))

    def test_max_packets_controls_the_capture_cap(self):
        seen = {}

        def runner(cmd, kwargs):
            seen["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        capture.capture_payloads("wlan0", duration=1, capture_tool="tcpdump",
                                 runner=runner)
        self.assertNotIn("-c", seen["cmd"])            # default: no cap
        capture.capture_payloads("wlan0", duration=1, capture_tool="tcpdump",
                                 runner=runner, max_packets=300)
        self.assertIn("-c", seen["cmd"])
        self.assertIn("300", seen["cmd"])

    def test_tshark_autostop_condition_is_a_real_argument(self):
        """tshark -a must be followed by its condition, not by -x."""
        seen = {}

        def runner(cmd, kwargs):
            seen["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        capture.capture_payloads("wlan0", duration=30, capture_tool="tshark",
                                 runner=runner)
        cmd = seen["cmd"]
        self.assertIn("-x", cmd)
        if "-a" in cmd:
            arg = cmd[cmd.index("-a") + 1]
            self.assertFalse(arg.startswith("-"),
                             "tshark -a swallowed the next flag: %r" % (cmd,))
            self.assertTrue(arg.startswith("duration:"), cmd)

    def test_discover_gateway_skips_short_route_lines(self):
        """A truncated routing line must be skipped, not crash on fields[3]."""
        route = "Iface Dest Gateway\n" "eth0 00000000 0102A8C0\n"  # only 3 cols
        with self.assertRaises(capture.GatewayDiscoveryError):
            capture.discover_gateway(route=route)

    def test_stop_daemon_escalates_to_sigkill(self):
        """A process that ignores SIGTERM must still get SIGKILL."""
        sent = []
        alive = {"v": True}

        def fake_kill(pid, sig):
            if sig == 0:
                if alive["v"]:
                    return
                raise ProcessLookupError
            sent.append(sig)
            if sig == signal.SIGKILL:
                alive["v"] = False  # SIGKILL is the one it cannot ignore

        orig_kill, orig_sleep = os.kill, time.sleep
        os.kill, time.sleep = fake_kill, lambda _s: None
        try:
            capture.stop_daemon(424242)
        finally:
            os.kill, time.sleep = orig_kill, orig_sleep
        self.assertIn(signal.SIGTERM, sent)
        self.assertIn(signal.SIGKILL, sent)


# --------------------------------------------------------------------------
# 10. CLI
# --------------------------------------------------------------------------

class TestCli(TempDirCase):
    def setUp(self):
        super().setUp()
        # an operator's own ANTHROPIC_API_KEY must not leak into the
        # "misconfigured --use-model" expectations
        self._saved_env = {k: os.environ.pop(k, None) for k in (
            "MATT_MODEL_URL", "ANTHROPIC_BASE_URL", "ANTHROPIC_API_BASE",
            "MATT_MODEL_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
            "MATT_ALLOW_DEFAULT_ENDPOINT", "MATT_MODEL", "ANTHROPIC_MODEL")}

    def tearDown(self):
        for key, value in self._saved_env.items():
            if value is not None:
                os.environ[key] = value
        super().tearDown()

    def cli(self, *argv):
        from matt import cli
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_parser_advertises_every_gate(self):
        from matt import cli
        text = cli.build_parser().format_help()
        for flag in ("--analyze-only", "--i-have-written-authorization",
                     "--use-model", "--iface"):
            self.assertIn(flag, text)

    def test_analyze_only_offline_is_token_free(self):
        report = self.path("capture_report.json")
        core.write_report(sample_report(), report)
        code, out, err = self.cli("--analyze-only", report)
        self.assertEqual(code, 0, err)
        self.assertIn("offline analysis", out)
        self.assertIn("network calls made:  0", out)
        self.assertIn("prose engine:        builtin:stage2_prose", out)
        self.assertTrue(os.path.exists(self.path("matt_analysis.json")))

    def test_analyze_only_writes_re_readable_json(self):
        report = self.path("capture_report.json")
        core.write_report(sample_report(), report)
        self.cli("--analyze-only", report, "--analysis", self.path("a.json"))
        with open(self.path("a.json"), "rb") as handle:
            data = json.loads(handle.read().decode("utf-8"))
        self.assertEqual(data["analysis"]["network_calls"], 0)
        self.assertTrue(all(f["prose"].strip() for f in data["analysis"]["findings"]))

    def test_analyze_only_on_a_missing_file(self):
        code, out, err = self.cli("--analyze-only", self.path("gone.json"))
        self.assertEqual(code, 2)
        self.assertIn("no such capture report", err)

    def test_analyze_only_on_a_corrupt_file(self):
        bad = self.path("bad.json")
        with open(bad, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        code, out, err = self.cli("--analyze-only", bad)
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", err)

    def test_live_refuses_without_root(self):
        code, out, err = self.cli("--iface", "lo", "--euid", "1000",
                                  "--i-have-written-authorization")
        self.assertEqual(code, 2)
        self.assertIn("refusing to run", err)
        self.assertIn("root", err)

    def test_live_refuses_without_the_authorization_flag(self):
        code, out, err = self.cli("--iface", "lo", "--euid", "0")
        self.assertEqual(code, 2)
        self.assertIn("--i-have-written-authorization", err)

    def test_live_refuses_a_nonexistent_interface(self):
        code, out, err = self.cli("--iface", "wlan9", "--euid", "0",
                                  "--i-have-written-authorization")
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)

    def test_live_without_iface_is_configured_away(self):
        code, out, err = self.cli("--euid", "0", "--i-have-written-authorization")
        self.assertEqual(code, 2)
        self.assertIn("--iface", err)

    def test_gates_are_checked_before_any_model_config(self):
        """Non-root must be refused even if --use-model is also misconfigured."""
        code, out, err = self.cli("--iface", "lo", "--euid", "1000", "--use-model")
        self.assertEqual(code, 2)
        self.assertIn("refusing to run", err)

    def test_use_model_without_config_fails_loudly(self):
        report = self.path("capture_report.json")
        core.write_report(sample_report(), report)
        code, out, err = self.cli("--analyze-only", report, "--use-model")
        self.assertEqual(code, 4)
        self.assertIn("--use-model", err)
        self.assertIn("endpoint", err.lower())

    def test_dry_run_needs_nothing(self):
        code, out, err = self.cli("--iface", "wlan0", "--dry-run")
        self.assertEqual(code, 0, err)
        self.assertIn("dry run", out)

    def test_identify_cli_reverses_a_common_hash(self):
        code, out, err = self.cli("--identify", "5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertEqual(code, 0, err)
        self.assertIn("MD5", out)
        self.assertIn("password", out)   # reversed

    def test_watch_rejects_a_missing_directory(self):
        code, out, err = self.cli("--watch", self.path("nope-does-not-exist"))
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)

    def test_auto_reverse_fills_the_secret_for_a_common_hash(self):
        import hashlib
        body = ("POST /x HTTP/1.1\r\nHost: h\r\n\r\n"
                "Username=joe&Password=letmein")
        report = {"hosts": {"h": {"payloads": [{"payload": body, "protocol": "http"}]}},
                  "payloads": []}
        path = self.path("capture_report.json")
        core.write_report(report, path)
        code, out, err = self.cli("--analyze-only", path, "--table")
        self.assertEqual(code, 0, err)
        self.assertIn("letmein", out)   # md5(letmein) reversed instantly

    def test_version_flag(self):
        from matt import cli
        out = io.StringIO()
        with self.assertRaises(SystemExit) as cm, redirect_stdout(out):
            cli.build_parser().parse_args(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("matt", out.getvalue())

    def test_table_output_has_a_row_per_credential(self):
        report = self.path("capture_report.json")
        core.write_report(sample_report(), report)
        code, out, err = self.cli("--analyze-only", report, "--table")
        self.assertEqual(code, 0, err)
        self.assertIn("SECRET / CRACKED", out)
        self.assertIn("HOST", out)
        # the md5 web login and the ntlmv2 both show up as rows
        self.assertIn("ntlmv2", out)
        self.assertIn("md5", out)

    def test_json_output_is_valid_and_pipeable(self):
        report = self.path("capture_report.json")
        core.write_report(sample_report(), report)
        code, out, err = self.cli("--analyze-only", report, "--json")
        self.assertEqual(code, 0, err)
        data = json.loads(out)  # must be clean JSON, nothing else on stdout
        self.assertIn("findings", data)
        self.assertEqual(data["candidate_count"], len(data["findings"]))
        self.assertEqual(data["network_calls"], 0)

    def test_no_flag_means_no_http_attempt_anywhere(self):
        """Booms in place, then run the whole default path in a child process."""
        code = (
            "import http.client, ssl, urllib.request  # real socket, loaded first\n"
            "import os, socket, sys\n"
            "def boom(*a, **k):\n"
            "    raise AssertionError('HTTP attempted without --use-model')\n"
            "for name in ('socket', 'create_connection', 'create_server'):\n"
            "    setattr(socket, name, boom)\n"
            f"sys.path.insert(0, {REPO_ROOT!r})\n"
            "from matt import cli, core\n"
            f"report_path = core.write_report({sample_report()!r}, "
            f"os.path.join({self.tmp!r}, 'capture_report.json'))\n"
            "assert cli.main(['--analyze-only', report_path, '--analysis', "
            f"os.path.join({self.tmp!r}, 'analysis.json')]) == 0\n"
            "print('ZERO-NETWORK-OK')\n"
        )
        proc = subprocess.run([sys.executable, "-c", code], capture_output=True,
                              text=True, timeout=120)
        self.assertIn("ZERO-NETWORK-OK", proc.stdout, proc.stderr)


# --------------------------------------------------------------------------
# 11. interactive UI (banner + menu)
# --------------------------------------------------------------------------

class TestUi(unittest.TestCase):
    def test_banner_renders_and_strips_to_plain(self):
        from matt import ui
        art = ui.banner()                 # colour form keeps ANSI codes
        self.assertTrue(art.strip())
        plain = ui.banner(color=False)    # plain form has no escape codes
        self.assertNotIn("\033", plain)
        self.assertTrue(plain.strip())

    def test_header_has_no_escape_codes_off_a_tty(self):
        from matt import ui
        header = ui.render_header(io.StringIO())  # not a tty -> stripped
        self.assertNotIn("\033", header)
        self.assertIn("MANATTHETOP", header.replace(" ", ""))

    def test_paint_only_colours_a_tty(self):
        from matt import ui
        self.assertEqual(ui.paint("x", "red", stream=io.StringIO()), "x")
        self.assertNotIn("\033", ui.green("ok", stream=io.StringIO()))

    def test_menu_quit_is_a_clean_zero(self):
        from matt import ui
        calls = []
        code = ui.run_menu(None, lambda a: calls.append(a) or 99,
                           reader=lambda p="": "q", writer=lambda *a: None,
                           clear=lambda: None)
        self.assertEqual(code, 0)
        self.assertEqual(calls, [], "quitting must not run anything")

    def test_menu_analyze_builds_the_expected_argv(self):
        from matt import ui
        calls = []
        answers = iter(["1", "somereport.json", "", "q"])
        code = ui.run_menu(
            None, lambda a: (calls.append(a), 0)[1],
            reader=lambda p="": next(answers, "q"),
            writer=lambda *a: None, clear=lambda: None)
        self.assertEqual(code, 0)
        self.assertTrue(calls, "menu never dispatched the analyze action")
        self.assertIn("--analyze-only", calls[0])
        self.assertIn("somereport.json", calls[0])
        self.assertIn("--no-banner", calls[0])

    def test_menu_mitm_requires_typed_authorization(self):
        """Choosing live MITM but not typing YES must run nothing and return 2."""
        from matt import ui
        calls = []
        # 3=MITM, iface, duration, gateway(blank), authorization(not YES), then quit
        answers = iter(["3", "wlan0", "5", "", "no", "", "q"])
        code = ui.run_menu(
            None, lambda a: (calls.append(a), 0)[1],
            reader=lambda p="": next(answers, "q"),
            writer=lambda *a: None, clear=lambda: None)
        self.assertEqual(calls, [], "unauthorized MITM must not dispatch a run")


# --------------------------------------------------------------------------
# 12. crack (hashcat orchestration) -- no real hashcat needed
# --------------------------------------------------------------------------

class TestCrack(unittest.TestCase):
    def _findings(self):
        return [
            {"kind": "ntlmv2", "hashcat_mode": "5600", "candidate": NTLMV2,
             "host": "WKS-07", "username": "skeith"},
            {"kind": "md5", "hashcat_mode": "0", "host": "web", "username": "bob",
             "target": "site/login", "candidate": MD5},
            {"kind": "http-basic", "hashcat_mode": None, "candidate": "a:b",
             "host": "h3"},
            {"kind": "unknown", "hashcat_mode": None, "candidate": "hex:00",
             "host": "h4"},
        ]

    def test_crackable_keeps_only_hashcat_modes(self):
        from matt import crack
        self.assertEqual({c["kind"] for c in crack.crackable(self._findings())},
                         {"ntlmv2", "md5"})

    def test_group_by_mode(self):
        from matt import crack
        self.assertEqual(set(crack.group_by_mode(self._findings())), {"5600", "0"})

    def test_parse_outfile_handles_colons_inside_the_hash(self):
        from matt import crack
        text = NTLMV2 + ":Password1\n" + MD5 + ":password\n"
        rec = crack.parse_outfile(text)
        self.assertEqual(rec[NTLMV2.lower()], "Password1")
        self.assertEqual(rec[MD5], "password")

    def test_crack_maps_recovered_plaintext_back_to_each_finding(self):
        from matt import crack

        def fake_runner(cmd, timeout):
            outfile = cmd[cmd.index("-o") + 1]
            if outfile.endswith("_0.txt"):          # the md5 run cracks
                with open(outfile, "w", encoding="utf-8") as fh:
                    fh.write(MD5 + ":password\n")
            # the 5600 run writes no outfile -> exhausted
            return None

        results = crack.crack(self._findings(), wordlist="/dev/null",
                              runner=fake_runner)
        by = {r["kind"]: r for r in results}
        self.assertEqual(by["md5"]["plaintext"], "password")
        self.assertEqual(by["md5"]["target"], "site/login")
        self.assertIsNone(by["ntlmv2"]["plaintext"])
        # http-basic / unknown are not crackable, so they never appear
        self.assertEqual(set(by), {"md5", "ntlmv2"})

    def test_crack_reports_hashcat_errors_without_raising(self):
        from matt import crack

        def boom(cmd, timeout):
            raise OSError("hashcat exploded")

        results = crack.crack(self._findings(), wordlist="/dev/null", runner=boom)
        self.assertTrue(all(r["plaintext"] is None for r in results))
        self.assertTrue(any(r["note"] for r in results))


# --------------------------------------------------------------------------
# 13. cleartext protocol logins (FTP/POP3, IMAP, SMTP, LDAP)
# --------------------------------------------------------------------------

class TestCleartextLogins(unittest.TestCase):
    def test_ftp_user_pass(self):
        c = core.cleartext_credentials(b"220 ProFTPD\r\nUSER alice\r\nPASS S3cr3t!\r\n")
        self.assertEqual(c, [{"kind": "ftp", "username": "alice",
                              "password": "S3cr3t!"}])

    def test_imap_login(self):
        c = core.cleartext_credentials(b"a1 LOGIN bob hunter2\r\n")
        self.assertEqual(c[0], {"kind": "imap", "username": "bob",
                                "password": "hunter2"})

    def test_smtp_auth_plain(self):
        import base64
        raw = b"AUTH PLAIN " + base64.b64encode(b"\x00carol\x00Summer2026!") + b"\r\n"
        c = core.cleartext_credentials(raw)
        self.assertEqual(c[0], {"kind": "smtp", "username": "carol",
                                "password": "Summer2026!"})

    def test_ldap_simple_bind(self):
        dn, pw = b"cn=admin,dc=corp,dc=local", b"Adm1nPass"
        bind = (b"\x60" + bytes([3 + 2 + len(dn) + 2 + len(pw)]) + b"\x02\x01\x03"
                + b"\x04" + bytes([len(dn)]) + dn + b"\x80" + bytes([len(pw)]) + pw)
        msg = b"\x30" + bytes([3 + len(bind)]) + b"\x02\x01\x01" + bind
        c = core.cleartext_credentials(msg)
        self.assertEqual(c[0]["kind"], "ldap")
        self.assertEqual(c[0]["password"], "Adm1nPass")

    def test_cleartext_through_candidates_is_credential_bearing(self):
        found = core.candidates_from_payload(b"USER alice\r\nPASS pw\r\n")
        ftp = [f for f in found if f["kind"] == "ftp"][0]
        self.assertTrue(ftp["credential_bearing"])
        self.assertEqual(ftp["username"], "alice")
        self.assertIsNone(ftp["hashcat_mode"])

    def test_cleartext_prose_says_recovered_not_crack(self):
        f = {"kind": "ftp", "hashcat_mode": None, "candidate": "alice:pw",
             "host": "10.0.0.9", "username": "alice", "credential_bearing": True,
             "target": "ftp.corp.local"}
        p = core.stage2_prose(f)
        self.assertIn("cleartext", p.lower())
        self.assertIn("alice:pw", p)
        self.assertIn("ftp.corp.local", p)

    def test_pop3_is_told_apart_from_ftp_by_the_banner(self):
        pop = core.cleartext_credentials(b"+OK POP3 ready\r\nUSER dave\r\nPASS pw\r\n")
        ftp = core.cleartext_credentials(b"220 FTP ready\r\nUSER dave\r\nPASS pw\r\n")
        self.assertEqual(pop[0]["kind"], "pop3")
        self.assertEqual(ftp[0]["kind"], "ftp")

    def test_port_tells_ftp_from_pop3_with_no_banner(self):
        up = b"USER dave\r\nPASS pw\r\n"              # identical verbs, no banner
        self.assertEqual(core.cleartext_credentials(up, port=21)[0]["kind"], "ftp")
        self.assertEqual(core.cleartext_credentials(up, port=110)[0]["kind"], "pop3")
        self.assertEqual(core.cleartext_credentials(up, port=995)[0]["kind"], "pop3")
        # no port -> unchanged default (back-compat)
        self.assertEqual(core.cleartext_credentials(up)[0]["kind"], "ftp")

    def test_port_overrides_when_present_and_candidates_threads_it(self):
        up = b"USER dave\r\nPASS pw\r\n"
        self.assertEqual(
            core.candidates_from_payload(up, port=110)[0]["kind"], "pop3")
        self.assertEqual(
            core.candidates_from_payload(up, port=21)[0]["kind"], "ftp")

    def test_service_port_resolution_prefers_a_known_port_either_side(self):
        # a server->client packet carries the service port as the SOURCE port
        self.assertEqual(core._pick_service_port(54321, 110), 110)
        self.assertEqual(core._pick_service_port(21, 54321), 21)
        self.assertEqual(core._pick_service_port(50000, 50001), 50000)
        self.assertEqual(core.service_protocol(995), "pop3")

    def test_snmp_community_string(self):
        comm = b"public"
        snmp = (b"\x30\x19\x02\x01\x01\x04" + bytes([len(comm)]) + comm
                + b"\xa0\x0c\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x00")
        c = core.cleartext_credentials(snmp)
        self.assertEqual(c[0]["kind"], "snmp")
        self.assertEqual(c[0]["password"], "public")
        self.assertEqual(c[0]["username"], "")

    def test_snmp_is_not_falsely_found_in_plain_http(self):
        self.assertEqual(
            core.cleartext_credentials(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), [])

    def test_telnet_line_mode_login(self):
        tn = b"\xff\xfd\x18login: admin\r\nPassword: Sup3rSecret\r\n"
        c = core.cleartext_credentials(tn)
        self.assertEqual(c[0]["kind"], "telnet")
        self.assertEqual(c[0]["username"], "admin")
        self.assertEqual(c[0]["password"], "Sup3rSecret")

    def test_snmpv3_username_is_surfaced_as_recon(self):
        def tlv(tag, val):
            return bytes([tag, len(val)]) + val
        usm = tlv(0x30, tlv(0x04, b"\x80\x00\x1f\x88") + tlv(0x02, b"\x01")
                  + tlv(0x02, b"\x02") + tlv(0x04, b"netadmin")
                  + tlv(0x04, b"\x00" * 12) + tlv(0x04, b""))
        msg = tlv(0x30, tlv(0x02, b"\x03") + tlv(0x30, b"\x00")
                  + tlv(0x04, usm) + tlv(0x04, b""))
        self.assertEqual(core.snmpv3_user(msg), "netadmin")
        f = core.candidates_from_payload(msg)[0]
        self.assertEqual(f["kind"], "snmpv3")
        self.assertEqual(f["username"], "netadmin")
        self.assertFalse(f["credential_bearing"])   # username is recon, not a secret
        self.assertIn("25100", core.stage2_prose(f))

    def test_snmp_candidate_has_no_colon_prefix(self):
        comm = b"private"
        snmp = (b"\x30\x1a\x02\x01\x00\x04" + bytes([len(comm)]) + comm
                + b"\xa0\x0c\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x00")
        f = core.candidates_from_payload(snmp)[0]
        self.assertEqual(f["kind"], "snmp")
        self.assertEqual(f["candidate"], "private")   # not ":private"
        self.assertTrue(f["credential_bearing"])


# --------------------------------------------------------------------------
# 14. Kerberos roasting (AS-REP 18200, TGS-REP 13100)
# --------------------------------------------------------------------------

class TestKerberos(unittest.TestCase):
    ASREP = "$krb5asrep$23$asmith@CORP.LOCAL:" + "ab" * 16 + "$" + "cd" * 110
    TGS = ("$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db01.corp.local:1433*$"
           + "ef" * 16 + "$" + "12" * 160)

    def test_asrep_is_18200(self):
        self.assertEqual(core.type_hash(self.ASREP), ("krb5asrep", "18200"))

    def test_tgs_is_13100(self):
        self.assertEqual(core.type_hash(self.TGS), ("krb5tgs", "13100"))

    def test_asrep_identity(self):
        ident = core.kerberos_identity(self.ASREP)
        self.assertEqual(ident["username"], "asmith")
        self.assertEqual(ident["target"], "CORP.LOCAL")

    def test_tgs_identity_names_the_spn(self):
        ident = core.kerberos_identity(self.TGS)
        self.assertEqual(ident["username"], "svc_sql")
        self.assertEqual(ident["target"], "MSSQLSvc/db01.corp.local:1433")

    PA = "$krb5pa$23$asmith$CORP.LOCAL$" + "ab" * 60

    def test_preauth_is_7500(self):
        self.assertEqual(core.type_hash(self.PA), ("krb5pa", "7500"))

    def test_preauth_identity(self):
        ident = core.kerberos_identity(self.PA)
        self.assertEqual(ident["username"], "asmith")
        self.assertEqual(ident["target"], "CORP.LOCAL")

    def test_roast_through_candidates_carries_user_and_target(self):
        for line, user, target, mode in (
                (self.ASREP, "asmith", "CORP.LOCAL", "18200"),
                (self.TGS, "svc_sql", "MSSQLSvc/db01.corp.local:1433", "13100")):
            f = core.candidates_from_payload(line)[0]
            self.assertEqual(f["hashcat_mode"], mode)
            self.assertEqual(f["username"], user)
            self.assertEqual(f["target"], target)
            self.assertTrue(f["credential_bearing"])


# --------------------------------------------------------------------------
# 15. hash identification + common-hash reversal
# --------------------------------------------------------------------------

class TestIdentifyReverse(unittest.TestCase):
    def test_identify_32hex_lists_md5_and_ntlm(self):
        names = [n for n, _ in core.identify_hash("a" * 32)]
        self.assertIn("MD5", names)
        self.assertIn("NTLM", names)

    def test_identify_bcrypt_by_prefix(self):
        res = core.identify_hash("$2b$12$" + "a" * 53)
        self.assertEqual(len(res), 1)
        name, mode = res[0]
        self.assertIn("bcrypt", name)
        self.assertEqual(mode, "3200")

    def test_identify_sha512_by_length(self):
        names = [n for n, _ in core.identify_hash("a" * 128)]
        self.assertIn("SHA-512", names)

    def test_identify_mysql_star_form(self):
        res = core.identify_hash("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19")
        self.assertEqual(len(res), 1)
        name, mode = res[0]
        self.assertIn("MySQL", name)
        self.assertEqual(mode, "300")

    def test_identify_kerberos_prefix(self):
        res = core.identify_hash("$krb5tgs$23$*a$b$c*$d$e")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0][1], "13100")
        self.assertIn("TGS", res[0][0])

    def test_identify_phpass_and_argon(self):
        self.assertIn("phpass", core.identify_hash("$P$B" + "a" * 30)[0][0])
        self.assertIn("Argon2", core.identify_hash("$argon2id$v=19$m=65536,t=3")[0][0])

    def test_identify_crc_and_murmur_by_short_length(self):
        names = [n for n, _ in core.identify_hash("deadbeef")]  # 8 hex
        self.assertTrue(any("CRC-32" in n for n in names))

    def test_tls_sni_from_clienthello(self):
        sni = b"login.microsoftonline.com"
        ext = (b"\x00\x00" + bytes([0, len(sni) + 5]) + bytes([0, len(sni) + 3])
               + b"\x00" + bytes([0, len(sni)]) + sni)
        pkt = (b"\x16\x03\x01\x00\x50\x01\x00\x00\x4c\x03\x03" + b"\x00" * 32
               + b"\x00\x00\x02\x13\x01\x01\x00" + ext)
        self.assertEqual(core.tls_sni(pkt), "login.microsoftonline.com")
        f = core.candidates_from_payload(pkt)[0]
        self.assertEqual(f["kind"], "tls-sni")
        self.assertEqual(f["target"], "login.microsoftonline.com")
        self.assertFalse(f["credential_bearing"])

    def test_reverse_common_md5(self):
        self.assertEqual(core.reverse_hash("5f4dcc3b5aa765d61d8327deb882cf99"),
                         "password")

    def test_md4_matches_rfc1320_vectors(self):
        self.assertEqual(core._md4(b"").hex(), "31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(core._md4(b"abc").hex(), "a448017aaf21d8525fc10ae87aa6729d")

    def test_reverse_common_ntlm(self):
        # NTLM(password) = MD4(UTF-16LE("password")); uses MATT's own MD4 so the
        # test does not depend on the platform OpenSSL offering md4.
        ntlm = core._md4("password".encode("utf-16le")).hex()
        self.assertEqual(ntlm, "8846f7eaee8fb117ad06bdd830b7586c")
        self.assertEqual(core.reverse_hash(ntlm), "password")

    def test_reverse_unknown_is_none(self):
        self.assertIsNone(core.reverse_hash("deadbeef" * 4))

    def test_reverse_is_case_insensitive(self):
        self.assertEqual(core.reverse_hash("5F4DCC3B5AA765D61D8327DEB882CF99"),
                         "password")


# --------------------------------------------------------------------------
# 16. wi-fi handshake + web dashboard + TLS ALPN/QUIC
# --------------------------------------------------------------------------

class TestTlsAlpnQuic(unittest.TestCase):
    def _clienthello(self, sni, alpn=None):
        se = (b"\x00\x00" + bytes([0, len(sni) + 5]) + bytes([0, len(sni) + 3])
              + b"\x00" + bytes([0, len(sni)]) + sni)
        exts = se
        if alpn is not None:
            exts += (b"\x00\x10" + bytes([0, len(alpn) + 2]) + bytes([0, len(alpn)])
                     + alpn)
        return (b"\x16\x03\x01\x01\x00\x01\x00\x00\xfc\x03\x03" + b"\x00" * 32
                + b"\x00\x00" + exts)

    def test_alpn_marks_http2(self):
        pkt = self._clienthello(b"www.google.com", alpn=b"\x02h2\x08http/1.1")
        self.assertEqual(core.tls_alpn(pkt), ["h2", "http/1.1"])
        f = core.candidates_from_payload(pkt)[0]
        self.assertIn("h2", f.get("protocol", ""))
        self.assertIn("HTTP/2", core.stage2_prose(f))

    def test_quic_v1_detected(self):
        pkt = b"\xc0\x00\x00\x00\x01\x08" + b"\xaa" * 8
        self.assertIn("QUIC", core.quic_info(pkt))
        f = core.candidates_from_payload(pkt)[0]
        self.assertEqual(f["kind"], "quic")


class TestWifiHandshake(unittest.TestCase):
    def test_command_builders(self):
        from matt import wifi
        self.assertIn("airmon-ng", wifi.monitor_start("wlan1"))
        self.assertEqual(wifi.capture("wlan1mon", "AA", "6", "p")[:2],
                         ["sudo", "airodump-ng"])
        d = wifi.deauth("wlan1mon", "AA:BB", client="CC:DD", count=3)
        self.assertIn("--deauth", d)
        self.assertIn("3", d)
        self.assertIn("-c", d)
        self.assertEqual(wifi.convert_22000("x.cap", "o"),
                         ["hcxpcapngtool", "-o", "o", "x.cap"])

    def test_plan_is_in_order(self):
        from matt import wifi
        labels = [label for label, _ in wifi.plan("wlan1", "AA", "6")]
        self.assertEqual(labels,
                         ["monitor on", "capture", "deauth", "convert", "monitor off"])

    def test_orchestrate_runs_the_pipeline_with_injected_runner(self):
        from matt import wifi
        out = os.path.join(self._tmp(), "hs.22000")
        steps = []

        class _P:
            def terminate(self_inner):
                steps.append("terminate")

        def runner(cmd):
            steps.append(cmd[1] if len(cmd) > 1 else cmd[0])
            if "hcxpcapngtool" in cmd:
                with open(out, "w") as fh:
                    fh.write("WPA*02*...")

        def popen(cmd):
            steps.append("popen")
            return _P()

        res = wifi.orchestrate("wlan1", "AA:BB", "6", out=out, capture_secs=0.1,
                               runner=runner, popen=popen,
                               which=lambda t: "/usr/bin/" + t)
        self.assertTrue(res["ok"])
        self.assertIn("deauth sent", res["steps"])
        self.assertIn("aireplay-ng", steps)

    def _tmp(self):
        import tempfile
        d = tempfile.mkdtemp(prefix="matt-wpa-test-")
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d


class TestDashboard(unittest.TestCase):
    def test_collect_findings(self):
        from matt import dashboard
        import tempfile
        d = tempfile.mkdtemp(prefix="matt-dash-")
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        analysis = core.analyze({"hosts": {"h": {"payloads": [
            {"payload": "USER bob\r\nPASS Secret1\r\n", "protocol": "ftp"}]}},
            "payloads": []})
        core.write_report(analysis, os.path.join(d, "matt_analysis.json"))
        res = dashboard.collect_findings(d)
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["rows"][0]["user"], "bob")
        self.assertEqual(res["rows"][0]["secret"], "Secret1")

    def test_page_is_self_contained_html(self):
        from matt import dashboard
        self.assertIn("<title>", dashboard.PAGE)
        self.assertIn("findings.json", dashboard.PAGE)


# --------------------------------------------------------------------------
# 17. TLS certificate names + LLMNR/NBT-NS poisoning
# --------------------------------------------------------------------------

class TestTlsCert(unittest.TestCase):
    def test_subject_issuer_and_sans(self):
        def strtlv(s):
            return b"\x0c" + bytes([len(s)]) + s
        cn = core._CN_OID
        blob = (b"....." + cn + strtlv(b"DigiCert TLS CA") + b"...."
                + cn + strtlv(b"www.example.com")
                + core._SAN_OID + b"\x04\x20\x30\x1e"
                + b"\x82\x0f" + b"www.example.com" + b"\x82\x0b" + b"example.com")
        got = core.tls_cert_names(blob)
        self.assertEqual(got["subject_cn"], "www.example.com")
        self.assertEqual(got["issuer_cn"], "DigiCert TLS CA")
        self.assertIn("example.com", got["sans"])
        f = [x for x in core.candidates_from_payload(blob) if x["kind"] == "tls-cert"][0]
        self.assertEqual(f["target"], "www.example.com")
        self.assertIn("DigiCert", core.stage2_prose(f))


class TestLlmnr(unittest.TestCase):
    def _llmnr_query(self, name):
        hdr = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
        return hdr + q + b"\x00\x01\x00\x01"

    def test_llmnr_parse_and_response(self):
        import socket
        q = self._llmnr_query("FILESERVER")
        self.assertEqual(llmnr.parse_llmnr_query(q)["name"], "FILESERVER")
        resp = llmnr.build_llmnr_response(q, "10.0.0.5")
        self.assertEqual(socket.inet_ntoa(resp[-4:]), "10.0.0.5")
        self.assertEqual(resp[:2], q[:2])            # txid echoed

    def test_llmnr_ignores_a_response_packet(self):
        resp = b"\x12\x34\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00"
        self.assertIsNone(llmnr.parse_llmnr_query(resp))

    def test_netbios_decode_and_response(self):
        import socket
        name = b"WORKSTATION1   "[:16].ljust(16, b"\x20")
        enc = b"".join(bytes([0x41 + ((b >> 4) & 0xF), 0x41 + (b & 0xF)]) for b in name)[:32]
        nq = (b"\xaa\xbb\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20" + enc
              + b"\x00\x00\x20\x00\x01")
        self.assertEqual(llmnr.parse_nbtns_query(nq)["name"], "WORKSTATION1")
        rn = llmnr.build_nbtns_response(nq, "10.0.0.5")
        self.assertEqual(socket.inet_ntoa(rn[-4:]), "10.0.0.5")

    def test_poison_loop_logs_victims_with_injected_sockets(self):
        q = self._llmnr_query("PRINTER")

        class _Sock:
            def __init__(s):
                s.queue = [(q, ("10.0.0.42", 5355))]
                s.sent = []
            def recvfrom(s, n):
                return s.queue.pop(0)
            def sendto(s, data, addr):
                s.sent.append((data, addr))
            def close(s):
                pass

        sk = _Sock()
        calls = {"n": 0}

        def clock():
            calls["n"] += 1
            return 0 if calls["n"] < 3 else 100   # run one iteration then stop

        def select_fn(rlist, w, x, t):
            return (rlist if sk.queue else []), [], []

        log = llmnr.poison("10.0.0.5", duration=10, sock_factory=lambda: {sk: "llmnr"},
                           select_fn=select_fn, clock=clock)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["name"], "PRINTER")
        self.assertEqual(log[0]["victim"], "10.0.0.42")
        self.assertTrue(sk.sent)


if __name__ == "__main__":
    unittest.main(verbosity=2)
