#!/usr/bin/env python3
"""Traffic generator executed INSIDE a lab namespace (stdlib only).

    python driver.py <scenario> '<json params>' <source-ip>

Every socket is bound to <source-ip> so each trial has its own source address and its events can be
attributed exactly. Prints one JSON object describing what was ACTUALLY done (attempts, successes,
achieved duration and rate): the evaluation reports achieved rather than requested figures.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time

VICTIM = "10.10.10.10"
UDP_SINK_PORT = 9001
DNS_PORT = 53


def _q(name: str) -> bytes:
    body = b"".join(bytes([len(x)]) + x.encode() for x in name.split("."))
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + body + b"\x00\x00\x01\x00\x01"


def _tcp(src: str, port: int, timeout: float = 2.0, payload: bytes = b"") -> str:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.bind((src, 0))
        s.connect((VICTIM, port))
        if payload:
            s.sendall(payload)
            s.recv(100)
        return "open"
    except ConnectionRefusedError:
        return "refused"
    except OSError:
        return "error"
    finally:
        s.close()


def _pace(t0: float, done: int, total: int, seconds: float) -> None:
    delay = t0 + seconds * done / total - time.time()
    if delay > 0:
        time.sleep(delay)


def connect_ports(src: str, p: dict) -> dict:
    ports, interval, repeat = p["ports"], p["interval"], p["repeat"]
    t0, out = time.time(), {"open": 0, "refused": 0, "error": 0}
    for _ in range(repeat):
        for port in ports:
            out[_tcp(src, port, payload=b"GET / HTTP/1.0\r\n\r\n" if port == 8080 else b"")] += 1
            if interval:
                time.sleep(interval)
    return {"attempts": sum(out.values()), **out, "seconds": round(time.time() - t0, 2)}


def flood(src: str, p: dict) -> dict:
    ports, n, seconds = p["ports"], p["n"], p["seconds"]
    t0, out = time.time(), {"open": 0, "refused": 0, "error": 0}
    for i in range(n):
        out[_tcp(src, ports[i % len(ports)], timeout=3.0, payload=b"GET / HTTP/1.0\r\n\r\n")] += 1
        _pace(t0, i + 1, n, seconds)
    return {"attempts": n, **out, "seconds": round(time.time() - t0, 2)}


def dns(src: str, p: dict) -> dict:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind((src, 0))
    if p.get("names"):
        names = list(p["names"])
        total = p["queries"]
    elif p.get("label"):
        names = ["a" * p["label"] + ".lab.test"]
        total = p["queries"]
    else:
        names = [f"h{j}.lab.test" for j in range(max(1, p["distinct"]))]
        total = p["queries"]
    t0 = time.time()
    seen = set()
    for i in range(total):
        name = names[i % len(names)]
        seen.add(name)
        u.sendto(_q(name), (VICTIM, DNS_PORT))
        if p["seconds"]:
            _pace(t0, i + 1, total, p["seconds"])
    return {"queries": total, "distinct": len(seen), "seconds": round(time.time() - t0, 2)}


def _udp_stream(src: str, mbps: float, seconds: float) -> dict:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind((src, 0))
    size = 1400
    pps = mbps * 1_000_000 / (size + 42)  # wire bytes per packet incl. headers
    total = int(pps * seconds)
    t0, buf = time.time(), b"z" * size
    for i in range(total):
        u.sendto(buf, (VICTIM, UDP_SINK_PORT))
        if i % 100 == 99:
            _pace(t0, i + 1, total, seconds)
    dt = time.time() - t0
    return {
        "packets": total,
        "seconds": round(dt, 2),
        "achieved_mbps": round(total * (size + 42) / dt / 1e6, 2),
    }


def udp_rate(src: str, p: dict) -> dict:
    return _udp_stream(src, p["mbps"], p["seconds"])


def normal_mix(src: str, p: dict) -> dict:
    http = sum(
        _tcp(src, 8080, timeout=3.0, payload=b"GET / HTTP/1.0\r\n\r\n") == "open"
        for _ in range(p["http"])
    )
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind((src, 0))
    for i in range(p["dns"]):
        u.sendto(_q(f"www{i % p['dns_names']}.example.org"), (VICTIM, DNS_PORT))
        time.sleep(0.05)
    for _ in range(p["udp"]):
        u.sendto(b"x" * 64, (VICTIM, UDP_SINK_PORT))
    ping = subprocess.run(  # noqa: S603
        ["ping", "-c", str(p["ping"]), "-i", "0.2", "-W", "1", "-I", src, VICTIM],  # noqa: S607
        capture_output=True,
        check=False,
    ).returncode
    out = {"http_ok": http, "ping_rc": ping}
    if p["bulk_mbps"]:
        out["bulk"] = _udp_stream(src, p["bulk_mbps"], p["bulk_seconds"])
    return out


SCENARIOS = {f.__name__: f for f in (connect_ports, flood, dns, udp_rate, normal_mix)}

if __name__ == "__main__":
    name, params, source = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3]
    print(json.dumps(SCENARIOS[name](source, params)))
