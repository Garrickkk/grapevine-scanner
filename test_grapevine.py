"""End-to-end tests for the grapevine command line. Run with:  python -m unittest -v"""

import contextlib
import errno
import io
import socket
import unittest
from unittest import mock

import grapevine
import synscan
from discovery import HostStatus

# Generous timeout so localhost probes behave the same on Windows (see test_scanner.py).
SLOW_OK = ["-t", "3"]


def run_cli(args):
    """Run grapevine with these arguments; return (exit code, output, errors)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = grapevine.main(args)
        except SystemExit as exc:  # argparse exits on invalid arguments
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class TestBadInput(unittest.TestCase):
    def test_bad_port(self):
        code, _, err = run_cli(["127.0.0.1", "-p", "99999"])
        self.assertEqual(code, 2)
        self.assertIn("out of range", err)

    def test_bad_host(self):
        code, _, err = run_cli(["no-such-host.invalid", "-p", "80"])
        self.assertEqual(code, 2)
        self.assertIn("could not resolve", err)

    def test_network_too_big(self):
        code, _, err = run_cli(["10.0.0.0/8"])
        self.assertEqual(code, 2)
        self.assertIn("limit", err)

    def test_zero_workers(self):
        code, _, err = run_cli(["127.0.0.1", "-w", "0"])
        self.assertEqual(code, 2)

    def test_discover_only_and_skip_discovery_conflict(self):
        code, _, err = run_cli(["127.0.0.1", "-sn", "-Pn"])
        self.assertEqual(code, 2)
        self.assertIn("not allowed with", err)


class TestSynScanOption(unittest.TestCase):
    def test_conflicts(self):
        for extra in ("--sequential", "-sn"):
            code, _, err = run_cli(["127.0.0.1", "-sS", extra])
            self.assertEqual(code, 2)
            self.assertIn("can't be combined", err)

    def test_clear_error_when_syn_scan_impossible(self):
        with mock.patch.object(synscan, "problem", return_value="SYN scanning needs root privileges."):
            code, out, err = run_cli(["127.0.0.1", "-sS"])
        self.assertEqual(code, 1)
        self.assertIn("needs root", err)
        self.assertNotIn("Discovering", out)  # stops before scanning anything

    def test_own_address_gets_connect_scan(self):
        up = {ip: HostStatus(True, "tcp/80 open") for ip in ("10.0.0.5", "10.0.0.9")}
        with mock.patch.object(synscan, "problem", return_value=None), \
             mock.patch.object(synscan, "needs_connect_scan", side_effect=lambda ip: ip == "10.0.0.5"), \
             mock.patch.object(synscan, "syn_scan", return_value={("10.0.0.9", 22): "open"}) as syn, \
             mock.patch.object(grapevine, "scan_ports", return_value={("10.0.0.5", 22): "closed"}) as connect, \
             mock.patch.object(grapevine, "discover", return_value=up):
            code, out, _ = run_cli(["10.0.0.5,10.0.0.9", "-sS", "-p", "22", "-n", "--no-detect"])
        self.assertEqual(code, 0)
        self.assertIn("SYN scan", out)
        self.assertIn("10.0.0.5 is this computer", out)
        self.assertEqual(syn.call_args.args[0], [("10.0.0.9", 22)])
        self.assertEqual(connect.call_args.args[0], [("10.0.0.5", 22)])
        self.assertRegex(out, r"22/tcp\s+open")


class TestScans(unittest.TestCase):
    def setUp(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.port = str(self.server.getsockname()[1])

    def tearDown(self):
        self.server.close()

    def test_port_scan(self):
        code, out, _ = run_cli(["127.0.0.1", "-p", self.port, "-n", "--no-detect", *SLOW_OK])
        self.assertEqual(code, 0)
        self.assertRegex(out, rf"{self.port}/tcp\s+open")
        self.assertIn("1 host(s) scanned, 1 up", out)

    def test_discover_only(self):
        code, out, _ = run_cli(["127.0.0.1", "-sn", "-n", *SLOW_OK])
        self.assertEqual(code, 0)
        self.assertIn("HOST", out)
        self.assertRegex(out, r"127\.0\.0\.1\s+tcp/\d+ (open|refused)")
        self.assertNotIn("Scanning ports", out)

    def test_skip_discovery(self):
        with mock.patch.object(grapevine, "discover") as discover:
            code, out, _ = run_cli(["127.0.0.1", "-Pn", "-p", self.port, "-n", "--no-detect"])
        discover.assert_not_called()
        self.assertEqual(code, 0)
        self.assertIn("assumed (-Pn)", out)
        self.assertRegex(out, rf"{self.port}/tcp\s+open")

    def test_host_down(self):
        down = {"10.9.9.9": HostStatus()}
        with mock.patch.object(grapevine, "discover", return_value=down):
            code, out, _ = run_cli(["10.9.9.9", "-n"])
        self.assertEqual(code, 0)
        self.assertIn("Host seems down", out)
        self.assertIn("-Pn", out)
        self.assertNotIn("Scanning ports", out)

    def test_several_hosts_reported_in_order(self):
        up = {ip: HostStatus(True, "tcp/80 open") for ip in ("10.0.0.10", "10.0.0.9")}
        states = {("10.0.0.9", 80): "open", ("10.0.0.10", 80): "closed"}
        with mock.patch.object(grapevine, "discover", return_value=up), \
             mock.patch.object(grapevine, "scan_ports", return_value=states):
            code, out, _ = run_cli(["10.0.0.10,10.0.0.9", "-p", "80", "-n", "--no-detect"])
        self.assertEqual(code, 0)
        # Sorted numerically (10.0.0.9 before 10.0.0.10), not as text.
        self.assertLess(out.index("10.0.0.9\n"), out.index("10.0.0.10\n"))
        self.assertIn("No open ports (1 closed, 0 filtered)", out)

    def test_running_out_of_open_files(self):
        error = OSError(errno.EMFILE, "Too many open files")
        with mock.patch.object(grapevine, "discover", side_effect=error):
            code, _, err = run_cli(["127.0.0.1", "-w", "500"])
        self.assertEqual(code, 1)
        self.assertIn("Lower -w", err)


if __name__ == "__main__":
    unittest.main()
