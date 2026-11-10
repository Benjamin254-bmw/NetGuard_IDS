# ADR 0011: Capture with an AF_PACKET socket and a purpose-built parser (Scapy kept for ARP)
Status: accepted. The requirements recommend Scapy; this records a measured deviation.

Decision: packets are read from a raw AF_PACKET socket with a kernel BPF filter (IPv4 and ARP only)
and parsed by `capture/parser.py`. Scapy remains a dependency for active ARP discovery and for
building test frames (it is the oracle in the parser tests).

Evidence (`lab/bench_parser.py`, identical frames; sandbox, Python 3.12, x86_64; re-run on your
own machine, absolute numbers will differ):
- netguard parser: 397,129 frames/s
- Scapy `Ether(b)[IP].src`: 8,395 frames/s (47x slower)
- Scapy src/dst/port extraction: 8,011 frames/s (50x slower)
A Scapy sniffer would cap this monitor near 8,000 frames/s per core before any analysis, losing
packets on a busy small network. The parser is checked against Scapy-built frames, every
truncation of every frame, and 40,000 random inputs (it must never raise).

Consequences and limits:
- The kernel filter and a 320-byte snap length mean payloads are never copied: only headers and,
  for DNS queries, the queried name are read. Raw bytes live only in the in-memory queue.
- Timestamps are taken in user space when a frame is read (not kernel receive time), so latency
  measured against a pcap includes the capture-thread scheduling delay (typically sub-millisecond).
- Kernel buffer overflow is counted from the socket's own statistics (`PACKET_STATISTICS`), verified
  by a test that forces real overflow.
- On loopback every frame is delivered twice (outgoing and incoming); the outgoing copy is dropped
  so counts match tcpdump. Found by comparing against tcpdump, not by inspection.
- IPv4 and ARP only (IPv6 is out of MVP scope); VLAN tags (one level) are handled.
