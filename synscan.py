"""SYN (half-open) scanning with scapy.

A normal connect scan completes the TCP handshake on every port:

    grapevine -> SYN, port -> SYN/ACK, grapevine -> ACK   (connection made)

A SYN scan builds the packets itself and stops halfway:

    grapevine -> SYN, port -> SYN/ACK                      (port is open)
    then the operating system sends RST, which cancels the half-made
    connection, because it never asked for one itself.

The service never receives a connection, so it never logs one, and a whole
batch of probes can be sent at once and the replies collected together,
which makes this much faster against firewalled hosts.

Crafting raw packets needs admin rights (root/sudo, or "Run as
administrator" on Windows) and scapy (pip install scapy). Windows also
needs Npcap (https://npcap.com).
"""

from __future__ import annotations

import functools
import ipaddress
import logging
import os
import random
import socket
import sys

from scanner import CLOSED, FILTERED, OPEN, run_parallel

BATCH_SIZE = 2048  # probes sent per round before waiting for replies

# TCP flag bits
SYN = 0x02
RST = 0x04

_scapy = None


def _load_scapy():
    """Import scapy only when a SYN scan is requested: the import takes ~2 s."""
    global _scapy
    if _scapy is None:
        # Keep scapy's start-up warnings (e.g. about IPv6 routes) off the screen.
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        import scapy.all
        _scapy = scapy.all
    return _scapy


def problem() -> str | None:
    """Explain why a SYN scan can't run here, or return None if it can."""
    try:
        scapy = _load_scapy()
    except ImportError:
        return "SYN scanning needs scapy. Install it with:  pip install scapy"
    except Exception as exc:  # scapy can fail in odd ways on broken setups
        return f"scapy failed to load ({exc})"

    if sys.platform == "win32":
        if not scapy.conf.use_pcap:
            return ("SYN scanning on Windows needs Npcap. Install it from "
                    "https://npcap.com (default options), then try again.")
        if not _is_windows_admin():
            return ("SYN scanning needs administrator rights. Right-click your terminal, "
                    "choose 'Run as administrator', and try again.")
    elif os.geteuid() != 0:
        return "SYN scanning needs root privileges. Run it with sudo."
    return None


def _is_windows_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def classify(tcp_flags: int | None, is_icmp: bool = False) -> str:
    """Turn the reply to a SYN probe into a port state.

    - SYN/ACK        -> open (the port wants to continue the handshake)
    - RST            -> closed
    - ICMP error     -> filtered (a firewall or router rejected the probe)
    - no reply       -> filtered (dropped somewhere)
    """
    if is_icmp or tcp_flags is None:
        return FILTERED
    if tcp_flags & SYN:
        return OPEN
    if tcp_flags & RST:
        return CLOSED
    return FILTERED


def syn_scan(tasks: list[tuple[str, int]], timeout: float, retries: int = 1,
             batch_size: int = BATCH_SIZE) -> dict[tuple[str, int], str]:
    """SYN-scan a list of (ip, port) pairs and return the state of each.

    Probes that get no reply are sent again `retries` times, so a single
    lost packet doesn't make an open port look filtered.
    """
    # Hosts on the local network that don't answer ARP can't be sent anything,
    # so skip them up front (see unreachable_hosts for why this matters).
    dead = unreachable_hosts(sorted({ip for ip, _ in tasks}))
    results = send_probes([task for task in tasks if task[0] not in dead],
                          timeout, retries, batch_size)
    # Anything that never answered is filtered. Keep the original order.
    return {task: results.get(task, FILTERED) for task in tasks}


def send_probes(tasks: list[tuple[str, int]], timeout: float, retries: int,
                batch_size: int) -> dict[tuple[str, int], str]:
    """Send SYN probes in batches and classify every reply that comes back."""
    scapy = _load_scapy()
    # One random high source port for the whole scan. (scapy's default is
    # port 20, which some firewalls treat specially.)
    sport = random.randint(40000, 60000)
    results: dict[tuple[str, int], str] = {}

    for start in range(0, len(tasks), batch_size):
        batch = tasks[start:start + batch_size]
        packets = [scapy.IP(dst=ip) / scapy.TCP(sport=sport, dport=port, flags="S")
                   for ip, port in batch]
        # chainCC=True: without it, scapy swallows Ctrl+C and keeps going.
        answered, _ = scapy.sr(packets, timeout=timeout, retry=retries,
                               verbose=0, chainCC=True)
        for sent, reply in answered:
            key = (sent[scapy.IP].dst, sent[scapy.TCP].dport)
            if reply.haslayer(scapy.ICMP):
                results[key] = classify(None, is_icmp=True)
            elif reply.haslayer(scapy.TCP):
                results[key] = classify(int(reply[scapy.TCP].flags))
    return results


def unreachable_hosts(ips: list[str], workers: int = 64) -> set[str]:
    """Find hosts that can't be reached at all, before sending them anything.

    Raw packets on a local network need the destination's MAC address, so
    scapy asks for it with ARP before *every* packet. If nobody answers,
    each packet waits ~2 s, and scapy doesn't remember the failure: with
    -Pn, an empty address and 1024 ports would take about 40 minutes.
    Asking once per host, all hosts at the same time, takes ~2 s in total.
    """
    scapy = _load_scapy()
    hops = {ip: _next_hop(ip) for ip in ips}
    to_resolve = sorted({hop for hop in hops.values() if hop})
    macs = dict(zip(to_resolve, run_parallel(scapy.getmacbyip, to_resolve, workers)))
    return {ip for ip, hop in hops.items() if hop and not macs[hop]}


def _next_hop(ip: str) -> str | None:
    """The address whose MAC is needed to reach ip: the host itself if it's on
    the local network, otherwise the router. None for loopback (no ARP)."""
    if ipaddress.ip_address(ip).is_loopback:
        return None
    _, _, gateway = _load_scapy().conf.route.route(ip)
    return ip if gateway == "0.0.0.0" else gateway


def needs_connect_scan(ip: str) -> bool:
    """Is this address the computer doing the scan? scapy can't SYN-scan it.

    Packets to your own address never leave the computer, so scapy can't
    send or capture them the normal way (it waits for an ARP reply from
    yourself that never comes). Only Linux handles 127.0.0.1 itself, so
    everywhere else, and for this computer's network address on every OS,
    grapevine uses a connect scan instead. Nmap has the same limitation.
    """
    if ipaddress.ip_address(ip).is_loopback:
        return not sys.platform.startswith("linux")
    if ip in own_addresses():
        return True
    _, source, _ = _load_scapy().conf.route.route(ip)
    return source == ip  # we'd be sending to ourselves


@functools.lru_cache(maxsize=1)
def own_addresses() -> frozenset[str]:
    """This computer's own IPv4 addresses (besides 127.0.0.1). Looked up once."""
    addresses: set[str] = set()
    try:
        addresses.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    try:
        # "Connecting" a UDP socket sends nothing, but makes the OS pick the
        # address it would use to reach the network, i.e. our LAN address.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.connect(("10.255.255.255", 1))
            addresses.add(udp.getsockname()[0])
    except OSError:
        pass
    return frozenset(addresses)
