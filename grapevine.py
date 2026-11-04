#!/usr/bin/env python3
"""grapevine v0.4: a TCP port and network scanner.

Takes single hosts or whole networks, finds which hosts are up, scans their
ports (open, closed or filtered) with a connect scan or a SYN (half-open)
scan, then talks to every open port to identify the service and version
running on it.

Only scan hosts and networks you own or have explicit permission to test.
"""

from __future__ import annotations

import argparse
import errno
import ipaddress
import sys
import time

import services
import synscan
from discovery import (DISCOVERY_PORTS, HostStatus, discover, is_randomized,
                       looks_intercepted, reverse_dns)
from scanner import CLOSED, FILTERED, OPEN, run_parallel, scan_ports
from targets import parse_ports, parse_targets

__version__ = "0.4.0"

Task = tuple[str, int]  # (ip, port)


def detect_services(tasks: list[Task], timeout: float, workers: int,
                    names: dict[str, str] | None = None) -> dict[Task, services.ServiceInfo]:
    """Identify the service on each open (ip, port), several at a time.

    names maps IPs to the hostname the user typed. It's passed along so TLS
    and HTTP requests reach the right site on servers hosting several sites.
    """
    names = names or {}
    infos = run_parallel(
        lambda task: services.detect(task[0], task[1], timeout, names.get(task[0])),
        tasks, workers,
    )
    return dict(zip(tasks, infos))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="grapevine: hear what every port has to say. "
                    "TCP port and network scanner with service detection (v0.4).",
        epilog="Only scan hosts and networks you own or have permission to test. "
               "scanme.nmap.org is allowed for practice.",
    )
    parser.add_argument("targets", nargs="+", metavar="TARGET",
                        help="IP, hostname, network (192.168.1.0/24) or range "
                             "(192.168.1.10-50); several allowed")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help='ports to scan: "80", "1-1024", "22,80,443" (default: 1-1024)')
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="seconds to wait for each port (default: 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="number of threads (default: 100)")
    parser.add_argument("-sS", "--syn", action="store_true",
                        help="SYN (half-open) scan: faster and stealthier; needs admin "
                             "rights and scapy (plus Npcap on Windows)")
    parser.add_argument("--sequential", action="store_true",
                        help="scan one port at a time (for comparing speed)")
    parser.add_argument("-a", "--all", action="store_true",
                        help="show closed and filtered ports too")
    parser.add_argument("-b", "--banners", action="store_true",
                        help="show the raw banner each service sent")
    parser.add_argument("--no-detect", action="store_true",
                        help="skip service detection (faster, ports only)")
    parser.add_argument("--detect-timeout", type=float, default=2.0,
                        help="seconds to wait for a service to answer (default: 2.0)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("-sn", "--discover-only", action="store_true",
                      help="only find which hosts are up, don't scan their ports")
    mode.add_argument("-Pn", "--skip-discovery", action="store_true",
                      help="treat every host as up (for hosts that ignore discovery probes)")
    parser.add_argument("-n", "--no-dns", action="store_true",
                        help="don't look up hostnames of live hosts")
    parser.add_argument("--version", action="version", version=f"grapevine {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.timeout <= 0 or args.detect_timeout <= 0 or args.workers < 1:
        print("error: timeouts must be > 0 and workers must be >= 1", file=sys.stderr)
        return 2
    try:
        ports = [] if args.discover_only else parse_ports(args.ports)
        targets = parse_targets(args.targets)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.syn and (args.sequential or args.discover_only):
        other = "--sequential" if args.sequential else "-sn"
        print(f"error: -sS can't be combined with {other}", file=sys.stderr)
        return 2
    if args.syn:
        reason = synscan.problem()
        if reason:
            print(f"error: {reason}", file=sys.stderr)
            return 1

    ips = [t.ip for t in targets]
    typed_names = {t.ip: t.name for t in targets if t.name}
    print_header(args, targets, ports)

    start = time.perf_counter()
    results: dict[Task, str] = {}
    infos: dict[Task, services.ServiceInfo] = {}
    try:
        # 1. Host discovery
        phase = time.perf_counter()
        if args.skip_discovery:
            status = {ip: HostStatus(up=True, reason="assumed (-Pn)") for ip in ips}
            print(f"Host discovery skipped (-Pn): treating all {len(ips)} host(s) as up")
        else:
            progress("Discovering hosts...")
            status = discover(ips, args.timeout, args.workers)
            live_count = sum(host.up for host in status.values())
            print(f"{live_count} of {len(ips)} up ({time.perf_counter() - phase:.2f}s)")
            shared = looks_intercepted(status)
            if shared:
                print(f"Warning: every host answered the same way ({shared}). On a real network\n"
                      "that's unlikely: a proxy or firewall may be answering on their behalf.\n"
                      "Use -b on a few hosts to see what is really responding.")
        live = [ip for ip in ips if status[ip].up]
        names = {} if args.no_dns else reverse_dns(live, args.workers)
        names.update(typed_names)  # what the user typed beats reverse DNS

        # 2. Port scan
        if live and ports:
            # The computer doing the scan can't SYN-scan its own addresses.
            self_ips = {ip for ip in live if synscan.needs_connect_scan(ip)} if args.syn else set()
            if self_ips:
                print(f"Note: {', '.join(sort_ips(list(self_ips)))} is this computer, which can't "
                      "be SYN-scanned; using a connect scan for it.")
            phase = time.perf_counter()
            progress("Scanning ports...")
            tasks = [(ip, port) for ip in live for port in ports]
            results = scan_ports_with(args, tasks, self_ips)
            print(f"{len(live)} host(s) x {len(ports)} port(s) ({time.perf_counter() - phase:.2f}s)")

        # 3. Service detection
        open_tasks = [task for task, state in results.items() if state == OPEN]
        if open_tasks and not args.no_detect:
            phase = time.perf_counter()
            progress("Detecting services...")
            infos = detect_services(open_tasks, args.detect_timeout, args.workers, typed_names)
            print(f"{len(open_tasks)} open port(s) ({time.perf_counter() - phase:.2f}s)")
    except KeyboardInterrupt:
        print("\nScan cancelled.")
        return 130
    except OSError as exc:
        if exc.errno not in (errno.EMFILE, errno.ENFILE):
            raise
        # Each thread holds an open socket, and the OS limits how many files
        # a program may have open (only 256 by default on macOS).
        print(f"\nerror: the system ran out of open files with {args.workers} threads. "
              "Lower -w and try again.", file=sys.stderr)
        return 1
    elapsed = time.perf_counter() - start

    print()
    if not live:
        print_nobody_home(len(ips))
    elif args.discover_only:
        print_live_hosts(live, status, names)
    else:
        print_port_report(live, status, names, results, infos, args.all, args.banners)
    print_summary(len(ips), len(live), results, elapsed)
    return 0


def scan_ports_with(args: argparse.Namespace, tasks: list[Task],
                    self_ips: set[str]) -> dict[Task, str]:
    """Run the port scan the user chose: SYN scan (-sS) or connect scan.

    self_ips are this computer's own addresses, which always get a connect scan.
    """
    if not args.syn:
        return scan_ports(tasks, args.timeout, args.workers, args.sequential)
    self_tasks = [task for task in tasks if task[0] in self_ips]
    syn_tasks = [task for task in tasks if task[0] not in self_ips]
    results = scan_ports(self_tasks, args.timeout, args.workers) if self_tasks else {}
    if syn_tasks:
        results.update(synscan.syn_scan(syn_tasks, args.timeout))
    return {task: results[task] for task in tasks}


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def progress(label: str) -> None:
    print(f"{label:<22}", end="", flush=True)


def print_header(args: argparse.Namespace, targets: list, ports: list[int]) -> None:
    if len(targets) == 1:
        t = targets[0]
        shown = f"{t.name} ({t.ip})" if t.name else t.ip
    else:
        shown = f"{' '.join(args.targets)} ({len(targets)} hosts)"
    if args.discover_only:
        print(f"Discovering hosts in {shown}\n")
        return
    if args.syn:
        mode = "SYN scan"
    elif args.sequential:
        mode = "sequential connect scan"
    else:
        mode = f"connect scan, {args.workers} threads"
    print(f"Scanning {shown}: {len(ports)} port(s), {mode}\n")


def sort_ips(ips: list[str]) -> list[str]:
    return sorted(ips, key=ipaddress.IPv4Address)


def host_title(ip: str, names: dict[str, str]) -> str:
    return f"{ip} ({names[ip]})" if ip in names else ip


def mac_text(mac: str) -> str:
    return f"{mac} (random or virtual)" if mac and is_randomized(mac) else mac


def print_nobody_home(count: int) -> None:
    probes = ", ".join(str(p) for p in DISCOVERY_PORTS)
    if count == 1:
        print(f"Host seems down: no reply on tcp/{probes} and no ARP reply.")
        print("If it's up but blocking these probes, try -Pn.")
    else:
        print("No hosts found up. If they're up but blocking discovery probes, try -Pn.")


def print_live_hosts(live: list[str], status: dict[str, HostStatus], names: dict[str, str]) -> None:
    print(f"{'HOST':<17}{'NAME':<26}{'REASON':<18}MAC")
    for ip in sort_ips(live):
        host = status[ip]
        line = f"{ip:<17}{names.get(ip, ''):<26}{host.reason:<18}{mac_text(host.mac)}"
        print(line.rstrip())


def print_port_report(live: list[str], status: dict[str, HostStatus], names: dict[str, str],
                      results: dict[Task, str], infos: dict[Task, services.ServiceInfo],
                      show_all: bool, show_banners: bool) -> None:
    detecting = bool(infos)
    any_guess = False
    for index, ip in enumerate(sort_ips(live)):
        if index:
            print()
        host = status[ip]
        print(host_title(ip, names))
        details = f"Host is up: {host.reason}"
        if host.mac:
            details += f" | MAC {mac_text(host.mac)}"
        print(f"  {details}")

        rows = [(port, state) for (h, port), state in results.items()
                if h == ip and (show_all or state == OPEN)]
        if not rows:
            states = [state for (h, _), state in results.items() if h == ip]
            print(f"  No open ports ({states.count(CLOSED)} closed, {states.count(FILTERED)} filtered)")
            continue

        header = f"{'PORT':<10}{'STATE':<10}{'SERVICE':<16}VERSION" if detecting else f"{'PORT':<10}STATE"
        print(f"  {header}")
        for port, state in rows:
            line = f"  {str(port) + '/tcp':<10}{state:<10}"
            info = infos.get((ip, port))
            if info:
                line += f"{info.label:<16}{info.details}"
                any_guess = any_guess or info.label.endswith("?")
            print(line.rstrip())
            if show_banners and info and info.banner:
                print(f"  {'':<10}|_ {info.banner}")

    if any_guess:
        print("\n? = guessed from the port number; the service didn't say what it is")


def print_summary(total: int, up: int, results: dict[Task, str], elapsed: float) -> None:
    summary = f"{total} host(s) scanned, {up} up"
    if results:
        states = list(results.values())
        summary += (f" | {states.count(OPEN)} open, {states.count(CLOSED)} closed, "
                    f"{states.count(FILTERED)} filtered port(s)")
    print(f"\n{summary} | finished in {elapsed:.2f}s")


if __name__ == "__main__":
    sys.exit(main())
