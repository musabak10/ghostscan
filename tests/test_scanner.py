import asyncio

import pytest

from ghostscan.scanner import expand_targets, parse_ports, scan


def test_parse_ports():
    assert parse_ports("80,22,100-102") == [22, 80, 100, 101, 102]
    assert parse_ports("5-3") == [3, 4, 5]


def test_parse_ports_invalid():
    with pytest.raises(ValueError):
        parse_ports("70000")
    with pytest.raises(ValueError):
        parse_ports("")


def test_expand_targets():
    assert expand_targets("example.com") == ["example.com"]
    assert expand_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    with pytest.raises(ValueError):
        expand_targets("10.0.0.0/8")


def test_scan_finds_open_port_and_banner():
    async def run():
        async def handler(reader, writer):
            writer.write(b"SSH-2.0-TestServer\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            return port, [r async for r in scan(["127.0.0.1"], [port, port + 1], 1.0, 10, True)]

    port, results = asyncio.run(run())
    assert len(results) == 1
    assert results[0].port == port
    assert "SSH-2.0-TestServer" in results[0].banner


from ghostscan.fingerprint import detect_version, guess_service
from ghostscan.services import port_info


def test_detect_version():
    assert detect_version("SSH-2.0-OpenSSH_9.6p1 Ubuntu") == "OpenSSH 9.6p1"
    assert detect_version("HTTP/1.1 200 OK Server: nginx/1.24.0 Date: x") == "nginx 1.24.0"
    assert detect_version("HTTP/1.0 200 OK Server: SimpleHTTP/0.6 Python/3.12.1") == "Python http.server (Python 3.12.1)"
    assert detect_version("garbage") is None


def test_guess_service():
    assert guess_service("SSH-2.0-OpenSSH_9.6") == "ssh"
    assert guess_service("HTTP/1.0 200 OK") == "http"
    assert guess_service("220 (vsFTPd 3.0.5)") == "ftp"
    assert guess_service("hello") is None


def test_port_info():
    risk, desc = port_info(3389)
    assert risk == "high" and "Remote Desktop" in desc
    assert "Uzak" in port_info(3389, "tr")[1]
    assert port_info(54321)[0] == "info"


def test_scan_corrects_service_from_banner():
    async def run():
        async def handler(reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            return [r async for r in scan(["127.0.0.1"], [port], 1.0, 10, True, "tr")]

    (r,) = asyncio.run(run())
    assert r.service == "ssh" and r.version == "OpenSSH 9.6"
    assert r.risk == "low" and "Uzak" in r.description
