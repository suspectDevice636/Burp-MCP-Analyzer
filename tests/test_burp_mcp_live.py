"""Exercise BurpMCP against a real MCP server speaking the protocol (a stand-in for Burp)."""
import socket
import subprocess
import sys
import textwrap
import time

import pytest

from services.burp_mcp import BurpMCP, parse_history_item

SERVER = textwrap.dedent('''
    import json, sys
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("fake-burp", host="127.0.0.1", port=int(sys.argv[1]))

    @mcp.tool()
    def get_proxy_http_history(count: int, offset: int) -> list[str]:
        items = [json.dumps({"request": "GET /n%d HTTP/1.1\\r\\nHost: localhost:3000\\r\\n\\r\\n" % i,
                             "response": "HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n{}",
                             "notes": ""}) for i in range(5)]
        return items[offset: offset + count]

    @mcp.tool()
    def get_proxy_http_history_regex(regex: str, count: int, offset: int) -> list[str]:
        return []

    mcp.run(transport=sys.argv[2])
''')


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(params=[("http", "/mcp"), ("sse", "/sse")])
def server(request, tmp_path):
    transport, path = request.param
    script = tmp_path / "fake_burp.py"
    script.write_text(SERVER)
    port = free_port()
    proc = subprocess.Popen([sys.executable, str(script), str(port),
                             "streamable-http" if transport == "http" else "sse"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("fake MCP server did not start")
    yield BurpMCP(f"http://127.0.0.1:{port}{path}", transport)
    proc.kill()


async def test_health_and_history(server):
    h = await server.health()
    assert h["ok"], h
    texts = await server.history(3, 0)
    assert len(texts) == 3
    assert parse_history_item(texts[0]).request.startswith("GET /n0")
    assert len(await server.history(10, 3)) == 2


async def test_health_when_down():
    h = await BurpMCP("http://127.0.0.1:1/mcp", "http").health()
    assert h["ok"] is False and h["error"]
