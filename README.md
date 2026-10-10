# 👻 GhostScan

**A fast, dependency-free async TCP port scanner with banner grabbing and JSON/CSV export.**

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)

GhostScan uses Python's `asyncio` to probe hundreds of ports concurrently, prints open ports the moment they are found, and identifies services by port and banner. It ships as a single pure-stdlib package, so there is nothing to install besides Python.

> ⚠️ **Legal notice:** Only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction. The author takes no responsibility for misuse.

## Features

- ⚡ Async TCP connect scanning with a configurable concurrency limit
- 🎯 Single host, hostname, or CIDR range (e.g. `192.168.1.0/24`)
- 🔍 Service detection for 50+ well-known ports
- 🪪 Optional banner grabbing (SSH, FTP, SMTP, HTTP `HEAD`, ...)
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

# Custom ports and ranges, with banner grabbing
ghostscan 192.168.1.10 -p 22,80,443,8000-8100 -b

# Scan a whole subnet and save the results
ghostscan 192.168.1.0/24 -p 22,80,443 -o results.csv

# All 65535 ports, faster timeout, higher concurrency
ghostscan 10.0.0.5 --all -t 0.5 -c 1000

# JSON output for scripting
ghostscan 127.0.0.1 --json | jq '.[] | select(.service == "ssh")'
```

### Example output

```text
[*] 1 host(s), 52 port(s), concurrency=500

OPEN  127.0.0.1:22    ssh                0.21ms  SSH-2.0-OpenSSH_9.6
OPEN  127.0.0.1:80    http               0.18ms  HTTP/1.0 200 OK Server: nginx

[+] 2 open port(s) in 1.04s
```

### Options

| Option | Description |
|---|---|
| `-p, --ports` | Ports to scan, e.g. `22,80,8000-8100` |
| `--all` | Scan all 65535 ports |
| `-t, --timeout` | Connect timeout in seconds (default `1.0`) |
| `-c, --concurrency` | Max simultaneous connections (default `500`) |
| `-b, --banner` | Grab service banners |
| `-o, --output` | Save results to `.json` or `.csv` |
| `--json` | Print results as JSON |
| `--no-color` | Disable colors |

> Tip: if you hit `Too many open files`, raise the limit with `ulimit -n 4096` or lower `-c`.

## Use as a library

```python
import asyncio
from ghostscan.scanner import scan

async def main():
    async for r in scan(["127.0.0.1"], [22, 80, 443], timeout=1.0, banner=True):
        print(r.port, r.service, r.banner)

asyncio.run(main())
```

## Development

```bash
pip install pytest
pytest
```

## Roadmap

- [ ] UDP scanning
- [ ] Subdomain enumeration module
- [ ] TLS certificate inspection
- [ ] HTML report export

## Contributing

Pull requests are welcome. Please open an issue first to discuss larger changes.

## License

[MIT](LICENSE)
