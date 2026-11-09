"""Tests for SYN scanning. Run with:  python -m unittest -v

Most tests use stand-ins for scapy, so they run anywhere, even without
scapy installed or admin rights. The live tests at the bottom send real
raw packets, so they only run as root on Linux with scapy installed.
"""

import importlib.util
import os
import socket
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

import scanner
import synscan
from scanner import CLOSED, FILTERED, OPEN

SA, S, RA, R, A = 0x12, 0x02, 0x14, 0x04, 0x10  # TCP flag combinations


class TestClassify(unittest.TestCase):
    def test_syn_ack_is_open(self):
        self.assertEqual(synscan.classify(SA), OPEN)

    def test_bare_syn_is_open(self):
        # A SYN back without ACK ("simultaneous open") still means it's listening.
        self.assertEqual(synscan.classify(S), OPEN)

    def test_rst_is_closed(self):
        self.assertEqual(synscan.classify(RA), CLOSED)
        self.assertEqual(synscan.classify(R), CLOSED)

    def test_icmp_error_is_filtered(self):
        self.assertEqual(synscan.classify(None, is_icmp=True), FILTERED)

    def test_no_reply_is_filtered(self):
        self.assertEqual(synscan.classify(None), FILTERED)

    def test_unexpected_flags_are_filtered(self):
        self.assertEqual(synscan.classify(A), FILTERED)


def fake_scapy(use_pcap=True, routes=None, macs=None):
    """A minimal stand-in for scapy: routing table and ARP answers only."""
    routes = routes or {}
    macs = macs or {}
    calls = []

    def getmacbyip(ip):
        calls.append(ip)
        return macs.get(ip)
    route = SimpleNamespace(route=lambda ip: routes.get(ip, ("eth0", "10.0.0.5", "10.0.0.1")))
    return SimpleNamespace(conf=SimpleNamespace(use_pcap=use_pcap, route=route),
                           getmacbyip=getmacbyip, arp_calls=calls)


class TestProblem(unittest.TestCase):
    def test_scapy_missing(self):
        with mock.patch.object(synscan, "_load_scapy", side_effect=ImportError):
            self.assertIn("pip install scapy", synscan.problem())

    def test_linux_without_root(self):
        with mock.patch.object(synscan, "_load_scapy", return_value=fake_scapy()), \
             mock.patch.object(sys, "platform", "linux"), \
             mock.patch("os.geteuid", create=True, return_value=1000):
            self.assertIn("sudo", synscan.problem())

    def test_linux_as_root(self):
        with mock.patch.object(synscan, "_load_scapy", return_value=fake_scapy()), \
             mock.patch.object(sys, "platform", "linux"), \
             mock.patch("os.geteuid", create=True, return_value=0):
            self.assertIsNone(synscan.problem())

    def test_windows_without_npcap(self):
        with mock.patch.object(synscan, "_load_scapy", return_value=fake_scapy(use_pcap=False)), \
             mock.patch.object(sys, "platform", "win32"):
            self.assertIn("npcap.com", synscan.problem())

    def test_windows_without_admin(self):
        with mock.patch.object(synscan, "_load_scapy", return_value=fake_scapy()), \
             mock.patch.object(sys, "platform", "win32"), \
             mock.patch.object(synscan, "_is_windows_admin", return_value=False):
            self.assertIn("Run as administrator", synscan.problem())

    def test_windows_ready(self):
        with mock.patch.object(synscan, "_load_scapy", return_value=fake_scapy()), \
             mock.patch.object(sys, "platform", "win32"), \
             mock.patch.object(synscan, "_is_windows_admin", return_value=True):
            self.assertIsNone(synscan.problem())


class TestNeedsConnectScan(unittest.TestCase):
    def setUp(self):
        routes = {"10.0.0.5": ("eth0", "10.0.0.5", "0.0.0.0")}  # our own address
        for target, value in ((synscan, "_load_scapy"), (synscan, "own_addresses")):
            patcher = mock.patch.object(target, value)
            self.addCleanup(patcher.stop)
            setattr(self, value, patcher.start())
        self._load_scapy.return_value = fake_scapy(routes=routes)
        self.own_addresses.return_value = frozenset({"192.168.1.7"})

    def test_loopback_works_only_on_linux(self):
        for platform, expected in (("linux", False), ("win32", True), ("darwin", True)):
            with mock.patch.object(sys, "platform", platform):
                self.assertEqual(synscan.needs_connect_scan("127.0.0.1"), expected, platform)

    def test_own_lan_address(self):
        self.assertTrue(synscan.needs_connect_scan("192.168.1.7"))

    def test_address_the_route_says_is_ours(self):
        self.assertTrue(synscan.needs_connect_scan("10.0.0.5"))

    def test_other_hosts(self):
        self.assertFalse(synscan.needs_connect_scan("10.0.0.9"))
        self.assertFalse(synscan.needs_connect_scan("8.8.8.8"))


class TestUnreachableHosts(unittest.TestCase):
    def test_hosts_without_arp_reply_are_skipped(self):
        local = ("eth0", "10.0.0.5", "0.0.0.0")
        scapy = fake_scapy(
            routes={"10.0.0.2": local, "10.0.0.3": local, "8.8.8.8": ("eth0", "10.0.0.5", "10.0.0.1"),
                    "1.1.1.1": ("eth0", "10.0.0.5", "10.0.0.1")},
            macs={"10.0.0.2": "aa:bb:cc:00:00:02", "10.0.0.1": "aa:bb:cc:00:00:01"},
        )
        with mock.patch.object(synscan, "_load_scapy", return_value=scapy):
            dead = synscan.unreachable_hosts(["10.0.0.2", "10.0.0.3", "8.8.8.8", "1.1.1.1", "127.0.0.1"])
        self.assertEqual(dead, {"10.0.0.3"})
        # The router is asked once for both remote hosts, and loopback needs no ARP.
        self.assertEqual(sorted(scapy.arp_calls), ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_no_router_means_remote_hosts_unreachable(self):
        scapy = fake_scapy(macs={})  # router doesn't answer ARP
        with mock.patch.object(synscan, "_load_scapy", return_value=scapy):
            self.assertEqual(synscan.unreachable_hosts(["8.8.8.8"]), {"8.8.8.8"})


class TestSynScan(unittest.TestCase):
    def test_unreachable_hosts_are_not_probed(self):
        tasks = [("10.0.0.3", 80), ("10.0.0.1", 80), ("10.0.0.1", 81)]
        with mock.patch.object(synscan, "unreachable_hosts", return_value={"10.0.0.3"}), \
             mock.patch.object(synscan, "send_probes",
                               return_value={("10.0.0.1", 80): OPEN}) as send:
            result = synscan.syn_scan(tasks, 1.0)
        self.assertEqual(send.call_args.args[0], [("10.0.0.1", 80), ("10.0.0.1", 81)])
        # Unanswered and unreachable probes are filtered; order is preserved.
        self.assertEqual(list(result.items()),
                         [(("10.0.0.3", 80), FILTERED), (("10.0.0.1", 80), OPEN),
                          (("10.0.0.1", 81), FILTERED)])


@unittest.skipUnless(importlib.util.find_spec("scapy"), "needs scapy installed")
class TestSendProbes(unittest.TestCase):
    """Checks what grapevine hands to scapy and how it reads the replies,
    without sending real packets (so no admin rights needed)."""

    def test_probes_and_replies(self):
        scapy = synscan._load_scapy()
        seen = {}

        def fake_sr(packets, **options):
            seen["packets"], seen["options"] = packets, options
            answered = [
                (packets[0], scapy.IP(src="10.0.0.1") / scapy.TCP(flags="SA")),
                (packets[1], scapy.IP(src="10.0.0.1") / scapy.TCP(flags="RA")),
                (packets[2], scapy.IP(src="10.0.0.254") / scapy.ICMP(type=3, code=13)),
            ]
            return answered, packets[3:]
        tasks = [("10.0.0.1", 22), ("10.0.0.1", 23), ("10.0.0.1", 24), ("10.0.0.1", 25)]
        with mock.patch.object(scapy, "sr", side_effect=fake_sr):
            result = synscan.send_probes(tasks, 1.0, retries=1, batch_size=100)

        self.assertEqual(result, {("10.0.0.1", 22): OPEN, ("10.0.0.1", 23): CLOSED,
                                  ("10.0.0.1", 24): FILTERED})
        first = seen["packets"][0]
        self.assertEqual((first[scapy.IP].dst, first[scapy.TCP].dport), ("10.0.0.1", 22))
        self.assertEqual(str(first[scapy.TCP].flags), "S")
        self.assertGreaterEqual(first[scapy.TCP].sport, 40000)
        # Without chainCC, scapy would swallow Ctrl+C.
        self.assertTrue(seen["options"]["chainCC"])
        self.assertEqual(seen["options"]["retry"], 1)

    def test_batches(self):
        scapy = synscan._load_scapy()
        sizes = []
        with mock.patch.object(scapy, "sr", side_effect=lambda pk, **_: (sizes.append(len(pk)), ([], pk))[1]):
            synscan.send_probes([("10.0.0.1", p) for p in range(1, 251)], 1.0, 1, batch_size=100)
        self.assertEqual(sizes, [100, 100, 50])


class TestOwnAddresses(unittest.TestCase):
    def test_returns_addresses_and_is_cached(self):
        synscan.own_addresses.cache_clear()
        first = synscan.own_addresses()
        self.assertIsInstance(first, frozenset)
        self.assertIs(synscan.own_addresses(), first)


def can_send_raw_packets() -> bool:
    return (sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0
            and importlib.util.find_spec("scapy") is not None)


@unittest.skipUnless(can_send_raw_packets(), "needs root on Linux with scapy installed")
class TestLiveSynScan(unittest.TestCase):
    def setUp(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.open_port = self.server.getsockname()[1]
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.closed_port = s.getsockname()[1]

    def tearDown(self):
        self.server.close()

    def test_open_and_closed(self):
        result = synscan.syn_scan([("127.0.0.1", self.open_port), ("127.0.0.1", self.closed_port)], 1.0)
        self.assertEqual(result, {("127.0.0.1", self.open_port): OPEN,
                                  ("127.0.0.1", self.closed_port): CLOSED})

    def test_agrees_with_connect_scan(self):
        tasks = [("127.0.0.1", p) for p in (self.open_port, self.closed_port, 1, 2, 3)]
        self.assertEqual(synscan.syn_scan(tasks, 1.0), scanner.scan_ports(tasks, 1.0, 10))

    def test_service_never_sees_a_connection(self):
        # The whole point of a half-open scan: nothing reaches accept().
        synscan.syn_scan([("127.0.0.1", self.open_port)], 1.0)
        self.server.settimeout(0.5)
        with self.assertRaises(socket.timeout):
            self.server.accept()


if __name__ == "__main__":
    unittest.main()
