"""Identify services and versions from banners."""

from __future__ import annotations

import re
from typing import Optional

# Canonical port whose description fits a service detected from its banner.
CANONICAL_PORT = {"ssh": 22, "ftp": 21, "http": 80, "smtp": 25, "pop3": 110, "imap": 143}

# (regex, format string filled with the regex groups)
VERSION_PATTERNS = [
    (re.compile(r"OpenSSH[_-]([\w.]+)"), "OpenSSH {0}"),
    (re.compile(r"dropbear[_-]([\w.]+)", re.I), "Dropbear {0}"),
    (re.compile(r"vsFTPd ([\w.]+)", re.I), "vsFTPd {0}"),
    (re.compile(r"ProFTPD ([\w.]+)", re.I), "ProFTPD {0}"),
    (re.compile(r"SimpleHTTP/([\w.]+) Python/([\w.]+)"), "Python http.server (Python {1})"),
    (re.compile(r"\bnginx/([\w.]+)", re.I), "nginx {0}"),
    (re.compile(r"\bApache/([\w.]+)", re.I), "Apache {0}"),
    (re.compile(r"Microsoft-IIS/([\w.]+)", re.I), "Microsoft IIS {0}"),
    (re.compile(r"lighttpd/([\w.]+)", re.I), "lighttpd {0}"),
    (re.compile(r"\bExim ([\w.]+)", re.I), "Exim {0}"),
    (re.compile(r"\bPostfix\b", re.I), "Postfix"),
]

_SERVER_HEADER = re.compile(r"Server:\s*(\S+)", re.I)


def guess_service(banner: str) -> Optional[str]:
    """Guess the real protocol from a banner, regardless of the port number."""
    up = banner.lstrip().upper()
    if up.startswith("SSH-"):
        return "ssh"
    if up.startswith("HTTP/"):
        return "http"
    if up.startswith("220"):
        if "FTP" in up:
            return "ftp"
        if "SMTP" in up:
            return "smtp"
    if up.startswith("+OK"):
        return "pop3"
    if up.startswith("* OK") and "IMAP" in up:
        return "imap"
    return None


def detect_version(banner: str) -> Optional[str]:
    """Extract a human-readable product/version from a banner."""
    for pattern, fmt in VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            return fmt.format(*m.groups())
    m = _SERVER_HEADER.search(banner)
    if m:
        return m.group(1).replace("/", " ")
    return None
