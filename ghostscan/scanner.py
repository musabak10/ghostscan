"""Core async scanning logic."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass
from typing import AsyncIterator, Optional

from .services import HTTP_PORTS, service_name

MAX_HOSTS = 1024


@dataclass
class PortResult:
    host: str
    port: int
    state: str
    service: str
    banner: Optional[str] = None
    latency_ms: Optional[float] = None


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,8000-8100' into a sorted list of unique ports."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    if not ports:
        raise ValueError("no ports specified")
    if any(not 0 < p < 65536 for p in ports):
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def expand_targets(target: str) -> list[str]:
    """Return a hostname/IP as-is, or expand a CIDR block into host IPs."""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return [target]
    hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
    if len(hosts) > MAX_HOSTS:
        raise ValueError(f"{target} expands to {len(hosts)} hosts (max {MAX_HOSTS})")
    return hosts


async def _grab_banner(reader, writer, host: str, port: int, timeout: float) -> Optional[str]:
    try:
        if port in HTTP_PORTS:
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    text = data.decode("utf-8", errors="replace").strip()
    return " ".join(text.split())[:120] or None


async def probe(host: str, port: int, timeout: float, banner: bool) -> Optional[PortResult]:
    """Try one TCP connect. Returns a PortResult only if the port is open."""
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    latency = (time.perf_counter() - start) * 1000
    text = await _grab_banner(reader, writer, host, port, timeout) if banner else None
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return PortResult(host, port, "open", service_name(port), text, round(latency, 2))


async def scan(
    hosts: list[str],
    ports: list[int],
    timeout: float = 1.0,
    concurrency: int = 500,
    banner: bool = False,
) -> AsyncIterator[PortResult]:
    """Scan hosts x ports and yield open ports as soon as they are found."""
    sem = asyncio.Semaphore(concurrency)

    async def worker(h: str, p: int) -> Optional[PortResult]:
        async with sem:
            return await probe(h, p, timeout, banner)

    tasks = [asyncio.ensure_future(worker(h, p)) for h in hosts for p in ports]
    try:
        for fut in asyncio.as_completed(tasks):
            result = await fut
            if result:
                yield result
    finally:
        for t in tasks:
            t.cancel()
