"""Command line interface."""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
import time
from dataclasses import asdict

from . import __version__
from .scanner import PortResult, expand_targets, parse_ports, scan
from .services import TOP_PORTS

BANNER = r"""
   ________  ______  ___________________  ___    _   __
  / ____/ / / / __ \/ ___/_  __/ ___/ __ \/   |  / | / /
 / / __/ /_/ / / / /\__ \ / /  \__ \/ / / / /| | /  |/ /
/ /_/ / __  / /_/ /___/ // /  ___/ / /_/ / ___ |/ /|  /
\____/_/ /_/\____//____//_/  /____/\____/_/  |_/_/ |_/
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ghostscan",
        description="Fast async TCP port scanner. Only scan systems you own or are authorized to test.",
    )
    p.add_argument("target", help="hostname, IP, or CIDR (e.g. 192.168.1.0/24)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-p", "--ports", help="ports, e.g. 22,80,8000-8100 (default: top common ports)")
    g.add_argument("--all", action="store_true", help="scan all 65535 ports")
    p.add_argument("-t", "--timeout", type=float, default=1.0, help="connect timeout in seconds (default 1.0)")
    p.add_argument("-c", "--concurrency", type=int, default=500, help="max simultaneous connections (default 500)")
    p.add_argument("-b", "--banner", action="store_true", help="grab service banners")
    p.add_argument("-o", "--output", help="write results to file (.json or .csv)")
    p.add_argument("--json", action="store_true", help="print results as JSON to stdout")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("-V", "--version", action="version", version=f"ghostscan {__version__}")
    return p


def _color(enabled: bool):
    if not enabled:
        return lambda code, s: s
    return lambda code, s: f"\033[{code}m{s}\033[0m"


def _write_output(path: str, results: list[PortResult]) -> None:
    rows = [asdict(r) for r in results]
    with open(path, "w", newline="", encoding="utf-8") as f:
        if path.lower().endswith(".csv"):
            w = csv.DictWriter(f, fieldnames=list(PortResult.__dataclass_fields__))
            w.writeheader()
            w.writerows(rows)
        else:
            json.dump(rows, f, indent=2)


async def _run(args, hosts, ports) -> list[PortResult]:
    c = _color(sys.stdout.isatty() and not args.no_color and not args.json)
    results: list[PortResult] = []
    async for r in scan(hosts, ports, args.timeout, args.concurrency, args.banner):
        results.append(r)
        if not args.json:
            line = f"{c(32, 'OPEN')}  {r.host}:{r.port:<5} {c(36, r.service):<18} {r.latency_ms}ms"
            if r.banner:
                line += f"  {c(90, r.banner)}"
            print(line, flush=True)
    return results


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        hosts = expand_targets(args.target)
        ports = list(range(1, 65536)) if args.all else parse_ports(args.ports) if args.ports else TOP_PORTS
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if not args.json:
        print(BANNER)
        print(f"[*] {len(hosts)} host(s), {len(ports)} port(s), concurrency={args.concurrency}\n")

    start = time.perf_counter()
    try:
        results = asyncio.run(_run(args, hosts, ports))
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130

    results.sort(key=lambda r: (r.host, r.port))
    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        print(f"\n[+] {len(results)} open port(s) in {time.perf_counter() - start:.2f}s")
    if args.output:
        _write_output(args.output, results)
        print(f"[+] saved to {args.output}", file=sys.stderr)
    return 0
