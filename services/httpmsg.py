"""Parsing of raw HTTP messages (as Burp serializes them) into usable objects."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit


ID_SEG = re.compile(r"^(\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", re.I)


def path_template(path_only: str) -> tuple[str, list[str]]:
    """'/rest/basket/6/items/2' -> ('/rest/basket/{id}/items/{id}', ['6', '2'])."""
    ids, segs = [], []
    for seg in path_only.split("/"):
        if ID_SEG.match(seg):
            ids.append(seg)
            segs.append("{id}")
        else:
            segs.append(seg)
    return "/".join(segs), ids


@dataclass
class HttpMessage:
    start_line: str
    headers: list[tuple[str, str]]
    body: str

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def headers_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def status(self) -> int | None:
        parts = self.start_line.split(" ", 2)
        if len(parts) >= 2 and parts[0].upper().startswith("HTTP/") and parts[1].isdigit():
            return int(parts[1])
        return None

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";")[0].strip().lower()

    def header_block(self) -> str:
        return "\n".join([self.start_line] + [f"{k}: {v}" for k, v in self.headers])


def parse_message(raw: str) -> HttpMessage:
    raw = raw.replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")
    start = lines[0].strip() if lines else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers.append((k.strip(), v.strip()))
    return HttpMessage(start_line=start, headers=headers, body=body)


@dataclass
class Exchange:
    """One request/response pair."""

    raw_request: str
    raw_response: str
    request: HttpMessage
    response: HttpMessage | None
    method: str
    host: str  # host[:port] exactly as in the Host header
    path: str  # path + query
    scheme: str | None = None  # None when it cannot be determined
    notes: str = ""
    params: dict[str, list[str]] = field(default_factory=dict)

    @property
    def hostname(self) -> str:
        h = self.host
        if h.startswith("["):  # IPv6 literal
            return h[1:].split("]")[0]
        return h.split(":")[0]

    @property
    def url(self) -> str:
        return f"{self.scheme or 'http'}://{self.host}{self.path}"

    @property
    def path_only(self) -> str:
        return urlsplit(self.path).path

    @property
    def endpoint(self) -> str:
        """Method + host + path template + status: exchanges sharing it are near-duplicates."""
        status = self.response.status if self.response else 0
        return f"{self.method} {self.host}{path_template(self.path_only)[0]} {status}"

    @property
    def id(self) -> str:
        h = hashlib.sha256()
        h.update(self.raw_request.encode("utf-8", "replace"))
        h.update(b"\x00")
        h.update(self.raw_response.encode("utf-8", "replace"))
        return h.hexdigest()[:32]


def _collect_params(req: HttpMessage, path: str) -> dict[str, list[str]]:
    params: dict[str, list[str]] = {}

    def add(k: str, v: str) -> None:
        params.setdefault(k, []).append(v)

    for k, v in parse_qsl(urlsplit(path).query, keep_blank_values=True):
        add(k, v)

    ctype = req.content_type
    if ctype == "application/x-www-form-urlencoded":
        for k, v in parse_qsl(req.body, keep_blank_values=True):
            add(k, v)
    elif ctype == "application/json" and req.body.strip():
        try:
            data = json.loads(req.body)
        except ValueError:
            data = None

        def walk(prefix: str, node) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(f"{prefix}.{k}" if prefix else k, v)
            elif isinstance(node, list):
                for v in node[:20]:
                    walk(prefix, v)
            elif isinstance(node, str):
                add(prefix, node)

        walk("", data)
    return params


def build_exchange(raw_request: str, raw_response: str = "", notes: str = "") -> Exchange | None:
    """Build an Exchange from raw messages. Returns None if the request is unparseable."""
    req = parse_message(raw_request)
    parts = req.start_line.split(" ")
    if len(parts) < 2 or not parts[0].isalpha():
        return None
    method, target = parts[0].upper(), parts[1]

    scheme = None
    host = req.header("host") or ""
    path = target
    if target.lower().startswith(("http://", "https://")):
        u = urlsplit(target)
        scheme = u.scheme.lower()
        host = host or u.netloc
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    if not host:
        return None
    if scheme is None and host.endswith(":443"):
        scheme = "https"

    resp = parse_message(raw_response) if raw_response.strip() else None
    if resp is not None and resp.status is None:
        resp = None

    return Exchange(
        raw_request=raw_request,
        raw_response=raw_response,
        request=req,
        response=resp,
        method=method,
        host=host,
        path=path,
        scheme=scheme,
        notes=notes,
        params=_collect_params(req, path),
    )
