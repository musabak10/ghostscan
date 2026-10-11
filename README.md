# 👻 GhostScan

**A fast, dependency-free async TCP port scanner that tells you what it found and what it means.**

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)

GhostScan uses Python's `asyncio` to probe hundreds of ports concurrently. For every open port it explains what the service is, rates how risky it is when exposed, and identifies the product and version from its banner (e.g. `OpenSSH 9.6p1`, `nginx 1.24.0`). It is pure standard library, so there is nothing to install besides Python.

> ⚠️ **Legal notice:** Only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction. The author takes no responsibility for misuse.

## Features

- ⚡ Async TCP connect scanning with a configurable concurrency limit
- 🎯 Single host, hostname, or CIDR range (e.g. `192.168.1.0/24`)
- 📖 **Plain-language explanation** for 50+ well-known services, in English or Turkish (`--lang tr`)
- 🚦 **Risk levels** (`HIGH` / `MEDIUM` / `LOW` / `INFO`) and an end-of-scan summary of ports that need attention
- 🔎 **Banner-based fingerprinting:** detects SSH, HTTP, FTP, SMTP, ... even on non-standard ports, and extracts product versions
- 📦 Export to JSON or CSV, or pipe JSON to other tools (`jq`, scripts)
- 🎨 Colored terminal output (auto-disabled when piped)
- 🧪 Tested, typed, zero third-party dependencies

## Installation

```bash
git clone https://github.com/<your-username>/ghostscan.git
cd ghostscan
pip install .
```

Or run it directly without installing:

```bash
python -m ghostscan 127.0.0.1
```

## Usage

```bash
# Scan the most common ports
ghostscan scanme.nmap.org

# Custom ports and ranges
ghostscan 192.168.1.10 -p 22,80,443,8000-8100

# Explanations in Turkish
ghostscan 127.0.0.1 --lang tr

# One line per port, no explanations
ghostscan 192.168.1.10 --brief

# Scan a whole subnet and save the results
ghostscan 192.168.1.0/24 -p 22,80,443,3389 -o results.csv

# All 65535 ports, faster timeout, higher concurrency
ghostscan 10.0.0.5 --all -t 0.5 -c 1000

# JSON output for scripting
ghostscan 127.0.0.1 --json | jq '.[] | select(.risk == "high")'
```

### Example output

```text
[*] 1 host(s), 4 port(s), concurrency=500

OPEN  127.0.0.1:2222        ssh             [LOW]    OpenSSH 9.6p1
      Secure Shell: remote login and file transfer. Safe with key auth, but a constant
      brute-force target. Disable password login.
      banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu

OPEN  127.0.0.1:3389        rdp             [HIGH]
      Remote Desktop. Top target for brute force and ransomware; use VPN, MFA and NLA.

OPEN  127.0.0.1:8000        http-alt        [LOW]    Python http.server (Python 3.12.3)
      Alternate web port, often a dev server (e.g. python -m http.server, Django).
      Check what it serves.

[+] 3 open port(s) in 0.42s

Needs attention (high/medium risk):
  [HIGH]   127.0.0.1:3389 rdp
```

### Options

| Option | Description |
|---|---|
| `-p, --ports` | Ports to scan, e.g. `22,80,8000-8100` |
| `--all` | Scan all 65535 ports |
| `-t, --timeout` | Connect timeout in seconds (default `1.0`) |
| `-c, --concurrency` | Max simultaneous connections (default `500`) |
| `--lang {en,tr}` | Language of the explanations (default `en`) |
| `--brief` | One line per port, no explanations |
| `--no-banner` | Skip banner grabbing (faster, less detail) |
| `-o, --output` | Save results to `.json` or `.csv` |
| `--json` | Print results as JSON |
| `--no-color` | Disable colors |

### How to read the risk levels

| Level | Meaning |
|---|---|
| `HIGH` | Commonly abused or often unauthenticated (SMB, RDP, Telnet, Redis, Docker API...). Should not be reachable from untrusted networks. |
| `MEDIUM` | Needs care: databases, mail, directory and management services. |
| `LOW` | Normal services that are fine when kept updated and configured properly. |
| `INFO` | Informational, or unknown service. |

Risk describes **exposure if the port is reachable from an untrusted network**. An open port on your own machine is not automatically a problem.

## Use as a library

```python
import asyncio
from ghostscan.scanner import scan

async def main():
    async for r in scan(["127.0.0.1"], [22, 80, 443], timeout=1.0, banner=True):
        print(r.port, r.service, r.version, r.risk)

asyncio.run(main())
```

## Limitations

- TCP connect scan only (no UDP, no SYN scan). It is visible in the target's logs.
- Banner grabbing does not speak TLS, so HTTPS services are identified by port only.
- Version detection covers common products only and relies on what the service reports. Treat results as hints, not proof.

## Development

```bash
pip install pytest
pytest
```

## Roadmap

- [ ] TLS certificate inspection
- [ ] Closed/filtered state detection
- [ ] Subdomain enumeration module
- [ ] HTML report export

## Contributing

Pull requests are welcome. Please open an issue first to discuss larger changes.

## License

[MIT](LICENSE)
