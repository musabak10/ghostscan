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
