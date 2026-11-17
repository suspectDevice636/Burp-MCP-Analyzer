"""Client for PortSwigger's Burp MCP extension.

This service is the MCP *client*; Burp's extension is the server. Each call
opens a short-lived session, so a Burp restart never leaves us holding a dead
connection.

Read-only: only the proxy-history tools are used. Nothing here sends traffic.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass

from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamablehttp_client

from config.config import settings

logger = logging.getLogger(__name__)


@dataclass
class HistoryItem:
    request: str
    response: str
    notes: str = ""


# Burp answers a request past the end of its history with plain text, not an item.
END_MARKERS = {"reached end of items", "end of items", "no more items"}


def is_end_marker(text: str) -> bool:
    return text.strip().strip(".!").lower() in END_MARKERS


def split_history_texts(text: str) -> list[str]:
    """Split one MCP text block into individual history entries.

    Burp may return each item as its own block, or several items joined in one
    block (concatenated JSON objects, a JSON array, or blank-line separated).
    Anything that can't be split is returned whole.
    """
    text = text.strip()
    if not text or is_end_marker(text):
        return []
    try:
        data = json.loads(text, strict=False)
    except ValueError:
        data = None
    if isinstance(data, list):
        return [x if isinstance(x, str) else json.dumps(x) for x in data
                if not (isinstance(x, str) and is_end_marker(x))]
    if isinstance(data, dict):
        return [text]

    decoder = json.JSONDecoder(strict=False)
    items: list[str] = []
    i = 0
    while i < len(text):
        start = text.find("{", i)
        if start == -1:
            break
        try:
            _, end = decoder.raw_decode(text, start)
        except ValueError:
            i = start + 1
            continue
        items.append(text[start:end])
        i = end
    return items or [text]


def parse_history_item(text: str) -> HistoryItem | None:
    """Parse one history entry.

    Burp serializes each item as JSON with request/response/notes. The exact
    shape isn't documented, so this accepts a few variants and returns None
    for anything it can't understand (the caller counts and reports those).
    """
    text = text.strip()
    if not text:
        return None
    try:
        data = json.loads(text, strict=False)
    except ValueError:
        data = None
    if isinstance(data, dict):
        req = data.get("request") or data.get("req")
        resp = data.get("response") or data.get("resp") or ""
        if isinstance(req, dict):  # structured form
            req = req.get("raw") or req.get("content")
        if isinstance(resp, dict):
            resp = resp.get("raw") or resp.get("content") or ""
        if isinstance(req, str):
            return HistoryItem(req, resp if isinstance(resp, str) else "", str(data.get("notes") or ""))
        return None
    # Fallback: raw text that starts with a request line
    first = text.split("\n", 1)[0]
    if first.split(" ")[0].isalpha() and "HTTP/" in first:
        return HistoryItem(text, "")
    return None


class BurpMCP:
    def __init__(self, url: str | None = None, transport: str | None = None):
        self.url = url or settings.burp_mcp_url
        self.transport = transport or settings.burp_mcp_transport

    def _headers(self) -> dict[str, str] | None:
        return {"Host": settings.burp_host_header} if settings.burp_host_header else None

    @asynccontextmanager
    async def _session(self):
        headers = self._headers()
        if self.transport == "sse":
            cm = sse_client(self.url, headers=headers, timeout=settings.burp_timeout)
        else:
            cm = streamablehttp_client(self.url, headers=headers, timeout=settings.burp_timeout)
        async with cm as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                yield session

    async def list_tools(self) -> list[str]:
        async with self._session() as s:
            return [t.name for t in (await s.list_tools()).tools]

    async def health(self) -> dict:
        try:
            tools = await self.list_tools()
            ok = "get_proxy_http_history" in tools
            return {"ok": ok, "tools": len(tools),
                    **({} if ok else {"error": "get_proxy_http_history tool not found"})}
        except BaseException as e:  # anyio raises ExceptionGroups
            return {"ok": False, "error": _short(e)}

    async def history(self, count: int, offset: int = 0, regex: str | None = None) -> list[str]:
        """Return the raw text of each history entry (one string per item)."""
        tool = "get_proxy_http_history_regex" if regex else "get_proxy_http_history"
        args: dict = {"count": count, "offset": offset}
        if regex:
            args["regex"] = regex
        async with self._session() as s:
            result = await s.call_tool(tool, args)
        if result.isError:
            raise RuntimeError(f"Burp MCP tool error: {_content_text(result)[:300]}")
        return [c.text for c in result.content if getattr(c, "type", "") == "text"]


def _content_text(result) -> str:
    return " ".join(getattr(c, "text", "") for c in result.content)


def _short(e: BaseException) -> str:
    subs = getattr(e, "exceptions", None)
    if subs:
        return "; ".join(_short(x) for x in subs)[:300]
    return f"{type(e).__name__}: {e}"[:300]
