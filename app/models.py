from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

ProxyType = Literal[
    "ss",
    "ssr",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "tuic",
    "http",
    "socks5",
]


@dataclass(slots=True)
class ProxyNode:
    name: str
    type: ProxyType
    server: str
    port: int
    params: dict[str, Any] = field(default_factory=dict)
    source_uri: str = ""


@dataclass(slots=True)
class ParseResult:
    nodes: list[ProxyNode]
    warnings: list[str]
