# grapevine

**Hear what every port has to say.** A TCP port and network scanner written in Python, built step by step to learn how tools like Nmap work.

## Features

- **Host discovery:** finds live hosts with TCP ping and the ARP cache, including devices that ignore all probes
- **Port scanning:** threaded TCP connect scan, or a faster and stealthier SYN (half-open) scan with `-sS`, with open / closed / filtered states
- **Service detection:** identifies SSH, HTTP(S), FTP, SMTP, MySQL, Redis and more, with versions
- **Flexible targets:** single IPs, CIDR networks, ranges and hostnames
- **Requirements:** Python 3.10+. The default scan needs no dependencies or admin rights; `-sS` needs admin rights and [scapy](https://scapy.net) (`pip install scapy`), plus [Npcap](https://npcap.com) on Windows

## How it works

1. **Discover:** probe a few common ports and read the ARP cache to find which hosts are up.
2. **Scan:** check each port of each live host: an accepted connection = **open**, a refusal = **closed**, no reply = **filtered**.
   - The default **connect scan** completes the full TCP handshake on every port.
   - The **SYN scan** (`-sS`) builds the packets itself and stops halfway: it sends a SYN, and a SYN/ACK reply proves the port is open, then the connection is cancelled before it's made. The service never sees a connection, and probes are sent in batches instead of waiting on each one, which makes it much faster against firewalls. Your own computer's addresses always get a connect scan, because raw packets to yourself never leave the machine.
3. **Detect:** read each open port's greeting (or send an HTTP/TLS request) and match it to a product and version.

## Benchmark

Ports 1-1024 on a real home router, scanned from Windows 11:

| | Connect scan (`-t 3`) | SYN scan (`-sS`) |
|---|---|---|
| Port scan | 22.79 s | **3.69 s** |
| Total | 34.87 s | **13.74 s** |
| Results | 3 open, 1019 closed, 2 filtered | identical |

Windows waits about 2 seconds before reporting a closed port to a normal connection, which slows connect scans down. The SYN scan reads the router's raw replies directly, so it sees each closed port's answer the instant it arrives.

## Roadmap

- [x] v0.1: port scanner
- [x] v0.2: service and version detection
- [x] v0.3: network scanning and host discovery
- [x] v0.4: SYN (half-open) scanning with scapy
- [ ] v1.0: CVE lookups, scan history, HTML reports
