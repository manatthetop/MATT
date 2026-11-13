"""Tests for TLS decryption from a Key Log File (matt/tlsdecrypt.py).

Nothing here runs tshark or touches an interface: the runner is a fake that
returns canned tshark output, so the parsing and wiring are tested in isolation.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from matt import capture, tlsdecrypt  # noqa: E402

FOLLOW = (
    "===================================================================\n"
    "Follow: tls,raw\n"
    "Filter: tls.stream eq 0\n"
    "Node 0: 127.0.0.1:18443\n"
    "Node 1: 127.0.0.1:47188\n"
    "\t504f5354202f6c6f67696e\n"
    "485454502f312e31\n"
    "===================================================================\n"
)


class TestParseFollowRaw(unittest.TestCase):
    def test_nodes_and_directions(self):
        endpoints, blocks = tlsdecrypt.parse_follow_raw(FOLLOW)
        self.assertEqual(endpoints, {0: ("127.0.0.1", 18443),
                                     1: ("127.0.0.1", 47188)})
        self.assertEqual(blocks, [(1, "504f5354202f6c6f67696e"),
                                  (0, "485454502f312e31")])

    def test_ipv6_endpoint(self):
        text = "Node 0: [::1]:443\nNode 1: [::1]:50000\n\t6162\n"
        endpoints, blocks = tlsdecrypt.parse_follow_raw(text)
        self.assertEqual(endpoints[0], ("::1", 443))
        self.assertEqual(blocks, [(1, "6162")])

    def test_empty_dump(self):
        self.assertEqual(tlsdecrypt.parse_follow_raw(""), ({}, []))


class TestDecryptPcap(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.keylog = os.path.join(self._dir.name, "keys.log")
        with open(self.keylog, "w") as fh:
            fh.write("CLIENT_RANDOM 00 11\n")
        self.calls = []

    def tearDown(self):
        self._dir.cleanup()

    def runner_for(self, streams_out, follow_out):
        def runner(cmd, kwargs):
            self.calls.append(cmd)
            if "-Y" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=streams_out,
                                                   stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=follow_out,
                                               stderr="")
        return runner

    def test_decrypted_blocks_become_payloads_with_endpoints(self):
        runner = self.runner_for("0\n0\n", FOLLOW)
        result = tlsdecrypt.decrypt_pcap("cap.pcap", self.keylog, runner=runner)
        self.assertEqual(result["streams"], 1)
        self.assertEqual(len(result["payloads"]), 2)
        client, server = result["payloads"]
        self.assertEqual(client["src"], "127.0.0.1")
        self.assertEqual(client["sport"], 47188)
        self.assertEqual(client["dport"], 18443)
        self.assertEqual(client["via"], "tls-keylog")
        self.assertEqual(bytes.fromhex(client["payload"]), b"POST /login")
        self.assertEqual(server["sport"], 18443)
        self.assertEqual(server["dport"], 47188)

    def test_keylog_is_passed_to_tshark(self):
        runner = self.runner_for("0\n", FOLLOW)
        tlsdecrypt.decrypt_pcap("cap.pcap", self.keylog, runner=runner)
        for cmd in self.calls:
            self.assertIn("tls.keylog_file:" + self.keylog, cmd)

    def test_missing_keylog_is_a_note_not_a_run(self):
        runner = self.runner_for("0\n", FOLLOW)
        result = tlsdecrypt.decrypt_pcap("cap.pcap",
                                         os.path.join(self._dir.name, "nope.log"),
                                         runner=runner)
        self.assertEqual(self.calls, [])
        self.assertEqual(result["payloads"], [])
        self.assertIn("missing or empty", result["note"])

    def test_no_tls_in_capture(self):
        result = tlsdecrypt.decrypt_pcap("cap.pcap", self.keylog,
                                         runner=self.runner_for("", ""))
        self.assertEqual(result["streams"], 0)
        self.assertEqual(result["note"], "no TLS sessions in the capture")

    def test_tls_present_but_no_key_match(self):
        result = tlsdecrypt.decrypt_pcap("cap.pcap", self.keylog,
                                         runner=self.runner_for("0\n", ""))
        self.assertEqual(result["streams"], 1)
        self.assertEqual(result["payloads"], [])
        self.assertIn("none decrypted", result["note"])


class TestCapturePcapPath(unittest.TestCase):
    def test_pcap_is_written_then_read_back_for_hex(self):
        row = "0x0000:  6100 6c00 6900 6300 6500 0d00 0a00 ff00"
        read_back = subprocess.CompletedProcess(
            ["tcpdump"], 0, stdout=row + "\n", stderr="")
        capture_run = subprocess.CompletedProcess(["tcpdump"], 0, stdout="",
                                                  stderr="")
        seen = []

        def runner(cmd, kwargs):
            seen.append(cmd)
            return capture_run if "-w" in cmd else read_back

        result = capture.capture_payloads("wlan0", duration=0.01,
                                          capture_tool="tcpdump", runner=runner,
                                          pcap_path="/tmp/x.pcap")
        self.assertIn("-w", seen[0])
        self.assertIn("/tmp/x.pcap", seen[0])
        self.assertNotIn("-X", seen[0])
        self.assertIn("-r", seen[1])
        self.assertEqual(result["pcap"], "/tmp/x.pcap")
        self.assertEqual(len(result["payloads"]), 1)

    def test_pcap_needs_tcpdump(self):
        result = capture.capture_payloads("wlan0", duration=0.01,
                                          capture_tool="tshark",
                                          runner=lambda c, k: None,
                                          pcap_path="/tmp/x.pcap")
        self.assertIn("needs tcpdump", result["note"])


if __name__ == "__main__":
    unittest.main()
