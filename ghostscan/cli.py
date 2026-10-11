"""Command line interface."""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import sys
import textwrap
import time
from dataclasses import asdict

from . import __version__
from .scanner import PortResult, expand_targets, parse_ports, scan
from .services import RISK_ORDER, TOP_PORTS

BANNER = r"""
   ________  ______  ___________________  ___    _   __
  / ____/ / / / __ \/ ___/_  __/ ___/ __ \/   |  / | / /
 / / __/ /_/ / / / /\__ \ / /  \__ \/ / / / /| | /  |/ /
/ /_/ / __  / /_/ /___/ // /  ___/ / /_/ / ___ |/ /|  /
\____/_/ /_/\____//____//_/  /____/\____/_/  |_/_/ |_/
"""

RISK_COLOR = {"high": 31, "medium": 33, "low": 32, "info": 90}

TEXT = {
    "en": {
        "summary": "{n} open port(s) in {t:.2f}s",
        "review": "Needs attention (high/medium risk):",
        "none": "No high or medium risk ports found.",
        "risk": "Risk levels describe exposure if the port is reachable from an untrusted network.",
    },
    "tr": {
        "summary": "{n} açık port bulundu ({t:.2f} sn)",
        "review": "Dikkat edilmesi gerekenler (yüksek/orta risk):",
        "none": "Yüksek veya orta riskli port bulunamadı.",
        "risk": "Risk seviyesi, portun güvenilmeyen bir ağdan erişilebilir olması durumundaki tehlikeyi gösterir.",
    },
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ghostscan",
        description="Fast async TCP port scanner that explains what it finds. "
        "Only scan systems you own or are authorized to test.",
    )
    p.add_argument("target", help="hostname, IP, or CIDR (e.g. 192.168.1.0/24)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-p", "--ports", help="ports, e.g. 22,80,8000-8100 (default: common ports)")
    g.add_argument("--all", action="store_true", help="scan all 65535 ports")
    p.add_argument("-t", "--timeout", type=float, default=1.0, help="connect timeout in seconds (default 1.0)")
    p.add_argument("-c", "--concurrency", type=int, default=500, help="max simultaneous connections (default 500)")
    p.add_argument("--no-banner", action="store_true", help="skip banner grabbing (faster, less detail)")
    p.add_argument("-b", "--banner", action="store_true", help=argparse.SUPPRESS)  # kept for compatibility
    p.add_argument("--brief", action="store_true", help="one line per port, no explanations")
    p.add_argument("--lang", choices=["en", "tr"], default="en", help="language of explanations (default en)")
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
            json.dump(rows, f, indent=2, ensure_ascii=False)


def _print_result(r: PortResult, c, brief: bool) -> None:
    risk_tag = c(RISK_COLOR[r.risk], f"[{r.risk.upper()}]".ljust(8))
    where = f"{r.host}:{r.port}".ljust(22)
    service = c(36, r.service.ljust(16))
    version = f" {c(1, r.version)}" if r.version else ""
    print(f"{c(32, 'OPEN')}  {where}{service}{risk_tag}{version}", flush=True)
    if brief:
        return
    for line in textwrap.wrap(r.description, 90):
        print(f"      {line}")
    if r.banner:
        print(f"      {c(90, 'banner: ' + r.banner)}")
    print()


async def _run(args, hosts, ports) -> list[PortResult]:
    c = _color(sys.stdout.isatty() and not args.no_color and not args.json)
    results: list[PortResult] = []
    async for r in scan(hosts, ports, args.timeout, args.concurrency, not args.no_banner, args.lang):
        results.append(r)
        if not args.json:
            _print_result(r, c, args.brief)
    return results


def _print_summary(results: list[PortResult], elapsed: float, lang: str, c) -> None:
    t = TEXT[lang]
    print(f"[+] {t['summary'].format(n=len(results), t=elapsed)}")
    risky = [r for r in results if RISK_ORDER[r.risk] >= RISK_ORDER["medium"]]
    if not results:
        return
    if risky:
        print(f"\n{t['review']}")
        for r in sorted(risky, key=lambda r: -RISK_ORDER[r.risk]):
            tag = c(RISK_COLOR[r.risk], f"[{r.risk.upper()}]".ljust(8))
            print(f"  {tag} {r.host}:{r.port} {r.service}")
    else:
        print(f"\n{t['none']}")
    print(f"\n{c(90, t['risk'])}")


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):  # avoid UnicodeEncodeError on Windows consoles/pipes
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if os.name == "nt":
        os.system("")  # enable ANSI colors in the Windows console

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
        print(json.dumps([asdict(r) for r in results], indent=2, ensure_ascii=False))
    else:
        c = _color(sys.stdout.isatty() and not args.no_color)
        _print_summary(results, time.perf_counter() - start, args.lang, c)
    if args.output:
        _write_output(args.output, results)
        print(f"[+] saved to {args.output}", file=sys.stderr)
    return 0
