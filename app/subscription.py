from __future__ import annotations

import base64
import json
import re
from ipaddress import ip_address
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse, urlsplit

import httpx
import yaml

from app.models import ParseResult, ProxyNode

_URLSAFE = str.maketrans("-_", "+/")

SUPPORTED_SCHEMES = {
    "ss",
    "ssr",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "hy2",
    "tuic",
    "http",
    "https",
    "socks",
    "socks5",
}


def _decode_base64_urlsafe(data: str) -> bytes:
    cleaned = re.sub(r"\s+", "", data).translate(_URLSAFE)
    if not cleaned:
        raise ValueError("empty base64 payload")
    padding = "=" * ((4 - len(cleaned) % 4) % 4)
    return base64.b64decode(cleaned + padding, validate=False)


def _try_decode_text(data: str) -> str | None:
    try:
        return _decode_base64_urlsafe(data).decode("utf-8")
    except Exception:
        return None


def _to_bool(value: str | None, *, default: bool | None = None) -> bool | None:
    if value is None:
        return default
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return default


def _split_csv(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def _first(qs: dict[str, list[str]], key: str) -> str | None:
    values = qs.get(key)
    if not values:
        return None
    return values[0]


def _int_or_none(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _normalize_name(name: str | None, fallback: str) -> str:
    final_name = (name or "").strip()
    return final_name if final_name else fallback


def _ensure_unique_names(nodes: list[ProxyNode]) -> None:
    seen: dict[str, int] = {}
    for node in nodes:
        base_name = node.name.strip() or f"{node.type}-{node.server}:{node.port}"
        index = seen.get(base_name, 0)
        seen[base_name] = index + 1
        node.name = base_name if index == 0 else f"{base_name}-{index + 1}"


def _any_to_bool(value: Any, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return bool(_to_bool(str(value), default=default))


def _clean_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return _split_csv(str(value))


def _safe_int(value: Any, *, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _first_key(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return None


def _parse_plugin_opts(raw: str | None) -> tuple[str | None, dict[str, str] | None]:
    if not raw:
        return None, None
    items = [part for part in raw.split(";") if part]
    if not items:
        return None, None
    plugin = items[0]
    opts: dict[str, str] = {}
    for item in items[1:]:
        if "=" in item:
            key, value = item.split("=", 1)
            opts[key.strip()] = unquote(value.strip())
    return plugin, opts or None


def _parse_transport_from_query(qs: dict[str, list[str]]) -> dict[str, Any]:
    params: dict[str, Any] = {}
    transport = (_first(qs, "type") or "tcp").lower()
    if transport in {"tcp", "none"}:
        params["network"] = "tcp"
    elif transport in {"ws", "websocket"}:
        params["network"] = "ws"
        ws_opts: dict[str, Any] = {"path": unquote(_first(qs, "path") or "/")}
        host = _first(qs, "host")
        if host:
            ws_opts["headers"] = {"Host": host}
        params["ws_opts"] = ws_opts
    elif transport in {"grpc", "gun"}:
        params["network"] = "grpc"
        grpc_opts: dict[str, Any] = {}
        service_name = _first(qs, "serviceName") or _first(qs, "service_name")
        if service_name:
            grpc_opts["grpc_service_name"] = service_name
        if grpc_opts:
            params["grpc_opts"] = grpc_opts
    elif transport in {"http"}:
        params["network"] = "http"
        http_opts: dict[str, Any] = {}
        host = _first(qs, "host")
        if host:
            http_opts["host"] = _split_csv(host)
        path = _first(qs, "path")
        if path:
            http_opts["path"] = [unquote(path)]
        if http_opts:
            params["http_opts"] = http_opts
    elif transport in {"h2", "http2"}:
        params["network"] = "h2"
        h2_opts: dict[str, Any] = {}
        host = _first(qs, "host")
        if host:
            h2_opts["host"] = _split_csv(host)
        path = _first(qs, "path")
        if path:
            h2_opts["path"] = unquote(path)
        if h2_opts:
            params["h2_opts"] = h2_opts
    else:
        params["network"] = transport
    return params


def _apply_tls_query_params(params: dict[str, Any], qs: dict[str, list[str]], *, force_tls: bool = False) -> None:
    security = (_first(qs, "security") or "").lower()
    tls_flag = force_tls or security in {"tls", "reality"}
    allow_insecure = _to_bool(_first(qs, "insecure"), default=None)
    if allow_insecure is None:
        allow_insecure = _to_bool(_first(qs, "allowInsecure"), default=None)
    params["tls"] = tls_flag
    if allow_insecure is not None:
        params["skip_cert_verify"] = allow_insecure
    sni = _first(qs, "sni") or _first(qs, "servername") or _first(qs, "peer")
    if sni:
        params["sni"] = sni
    alpn = _split_csv(_first(qs, "alpn"))
    if alpn:
        params["alpn"] = alpn
    fp = _first(qs, "fp")
    if fp:
        params["client_fingerprint"] = fp
    pbk = _first(qs, "pbk")
    sid = _first(qs, "sid")
    if pbk:
        params["reality_public_key"] = pbk
    if sid:
        params["reality_short_id"] = sid


def _parse_ss(uri: str) -> ProxyNode:
    parsed = urlsplit(uri)
    qs = parse_qs(parsed.query)
    tag = unquote(parsed.fragment) if parsed.fragment else None

    method: str
    password: str
    server: str
    port: int

    if parsed.username and parsed.password is not None:
        method = unquote(parsed.username)
        password = unquote(parsed.password)
        server = parsed.hostname or ""
        port = parsed.port or 0
    elif parsed.username:
        decoded_user = _try_decode_text(parsed.username)
        if not decoded_user or ":" not in decoded_user:
            raise ValueError("invalid ss base64 userinfo")
        method, password = decoded_user.split(":", 1)
        server = parsed.hostname or ""
        port = parsed.port or 0
    else:
        decoded = _try_decode_text(parsed.netloc)
        if not decoded:
            raise ValueError("invalid ss URI")
        reparsed = urlsplit(f"ss://{decoded}")
        method = unquote(reparsed.username or "")
        password = unquote(reparsed.password or "")
        server = reparsed.hostname or ""
        port = reparsed.port or 0

    if not method or not server or port <= 0:
        raise ValueError("invalid ss endpoint")

    plugin_raw = _first(qs, "plugin")
    plugin, plugin_opts = _parse_plugin_opts(plugin_raw)
    params: dict[str, Any] = {
        "cipher": method,
        "password": password,
        "udp": True,
    }
    if plugin:
        params["plugin"] = plugin
    if plugin_opts:
        params["plugin_opts"] = plugin_opts

    name = _normalize_name(tag, f"ss-{server}:{port}")
    return ProxyNode(name=name, type="ss", server=server, port=port, params=params, source_uri=uri)


def _parse_ssr(uri: str) -> ProxyNode:
    encoded = uri[len("ssr://") :]
    decoded = _try_decode_text(encoded)
    if not decoded:
        raise ValueError("invalid ssr payload")

    main, _, raw_qs = decoded.partition("/?")
    parts = main.split(":")
    if len(parts) < 6:
        raise ValueError("invalid ssr main fields")

    server, port_text, protocol, method, obfs, password_b64 = parts[:6]
    port = int(port_text)
    password = (_try_decode_text(password_b64) or "").strip()
    query = parse_qs(raw_qs)

    def decode_param(key: str) -> str | None:
        value = _first(query, key)
        if not value:
            return None
        decoded_value = _try_decode_text(unquote(value))
        return decoded_value if decoded_value is not None else unquote(value)

    remarks = decode_param("remarks")
    obfs_param = decode_param("obfsparam")
    protocol_param = decode_param("protoparam")

    params: dict[str, Any] = {
        "cipher": method,
        "password": password,
        "protocol": protocol,
        "obfs": obfs,
        "udp": True,
    }
    if obfs_param:
        params["obfs_param"] = obfs_param
    if protocol_param:
        params["protocol_param"] = protocol_param

    name = _normalize_name(remarks, f"ssr-{server}:{port}")
    return ProxyNode(name=name, type="ssr", server=server, port=port, params=params, source_uri=uri)


def _parse_vmess(uri: str) -> ProxyNode:
    encoded = uri[len("vmess://") :]
    payload = _try_decode_text(encoded)
    if not payload:
        raise ValueError("invalid vmess payload")
    data = json.loads(payload)

    server = str(data.get("add", "")).strip()
    port = int(str(data.get("port", "0")).strip() or "0")
    uuid = str(data.get("id", "")).strip()
    if not server or port <= 0 or not uuid:
        raise ValueError("invalid vmess endpoint")

    params: dict[str, Any] = {
        "uuid": uuid,
        "alter_id": int(str(data.get("aid", 0)) or 0),
        "cipher": str(data.get("scy", "auto") or "auto"),
        "udp": True,
    }

    network = str(data.get("net", "tcp") or "tcp").lower()
    params["network"] = network
    host = str(data.get("host", "") or "").strip()
    path = str(data.get("path", "") or "").strip()
    if network in {"ws", "websocket"}:
        ws_opts: dict[str, Any] = {"path": path or "/"}
        if host:
            ws_opts["headers"] = {"Host": host}
        params["network"] = "ws"
        params["ws_opts"] = ws_opts
    elif network in {"grpc", "gun"}:
        params["network"] = "grpc"
        service_name = str(data.get("path", "") or data.get("serviceName", "")).strip()
        if service_name:
            params["grpc_opts"] = {"grpc_service_name": service_name}
    elif network in {"h2", "http2"}:
        params["network"] = "h2"
        h2_opts: dict[str, Any] = {}
        if host:
            h2_opts["host"] = _split_csv(host)
        if path:
            h2_opts["path"] = path
        if h2_opts:
            params["h2_opts"] = h2_opts
    elif network == "http":
        http_opts: dict[str, Any] = {}
        if host:
            http_opts["host"] = _split_csv(host)
        if path:
            http_opts["path"] = [path]
        if http_opts:
            params["http_opts"] = http_opts

    tls_mode = str(data.get("tls", "")).strip().lower()
    if tls_mode in {"tls", "1", "true", "reality"}:
        params["tls"] = True
    if tls_mode in {"none", "0", "false", ""}:
        params["tls"] = False

    sni = str(data.get("sni", "") or "").strip()
    if sni:
        params["sni"] = sni
    alpn = _split_csv(str(data.get("alpn", "") or ""))
    if alpn:
        params["alpn"] = alpn
    fp = str(data.get("fp", "") or "").strip()
    if fp:
        params["client_fingerprint"] = fp

    packet_encoding = str(data.get("packetEncoding", "") or "").strip()
    if packet_encoding:
        params["packet_encoding"] = packet_encoding

    name = _normalize_name(str(data.get("ps", "") or ""), f"vmess-{server}:{port}")
    return ProxyNode(name=name, type="vmess", server=server, port=port, params=params, source_uri=uri)


def _parse_vless(uri: str) -> ProxyNode:
    parsed = urlsplit(uri)
    qs = parse_qs(parsed.query)
    uuid = unquote(parsed.username or "")
    server = parsed.hostname or ""
    port = parsed.port or 0
    if not uuid or not server or port <= 0:
        raise ValueError("invalid vless endpoint")

    params: dict[str, Any] = {
        "uuid": uuid,
        "udp": True,
    }
    flow = _first(qs, "flow")
    if flow:
        params["flow"] = flow
    packet_encoding = _first(qs, "packetEncoding")
    if packet_encoding:
        params["packet_encoding"] = packet_encoding
    transport = _parse_transport_from_query(qs)
    params.update(transport)
    _apply_tls_query_params(params, qs)

    name = _normalize_name(unquote(parsed.fragment) if parsed.fragment else None, f"vless-{server}:{port}")
    return ProxyNode(name=name, type="vless", server=server, port=port, params=params, source_uri=uri)


def _parse_trojan(uri: str) -> ProxyNode:
    parsed = urlsplit(uri)
    qs = parse_qs(parsed.query)
    password = unquote(parsed.username or "")
    server = parsed.hostname or ""
    port = parsed.port or 0
    if not password or not server or port <= 0:
        raise ValueError("invalid trojan endpoint")

    params: dict[str, Any] = {
        "password": password,
        "udp": True,
    }
    transport = _parse_transport_from_query(qs)
    params.update(transport)
    _apply_tls_query_params(params, qs, force_tls=True)

    name = _normalize_name(unquote(parsed.fragment) if parsed.fragment else None, f"trojan-{server}:{port}")
    return ProxyNode(name=name, type="trojan", server=server, port=port, params=params, source_uri=uri)


def _parse_hysteria2(uri: str) -> ProxyNode:
    parsed = urlsplit(uri.replace("hy2://", "hysteria2://", 1))
    qs = parse_qs(parsed.query)
    password = unquote(parsed.username or "")
    if parsed.password:
        password = f"{password}:{unquote(parsed.password)}"
    server = parsed.hostname or ""
    port = parsed.port or 0
    if not password or not server or port <= 0:
        raise ValueError("invalid hysteria2 endpoint")

    params: dict[str, Any] = {
        "password": password,
        "udp": True,
        "tls": True,
    }
    up = _first(qs, "up") or _first(qs, "upmbps")
    down = _first(qs, "down") or _first(qs, "downmbps")
    if up:
        params["up"] = up
    if down:
        params["down"] = down
    obfs = _first(qs, "obfs")
    obfs_password = _first(qs, "obfs-password") or _first(qs, "obfs_password")
    if obfs:
        params["obfs"] = obfs
    if obfs_password:
        params["obfs_password"] = obfs_password
    _apply_tls_query_params(params, qs, force_tls=True)
    if not params.get("sni"):
        sni = _first(qs, "sni") or _first(qs, "peer")
        if sni:
            params["sni"] = sni

    name = _normalize_name(unquote(parsed.fragment) if parsed.fragment else None, f"hy2-{server}:{port}")
    return ProxyNode(name=name, type="hysteria2", server=server, port=port, params=params, source_uri=uri)


def _parse_tuic(uri: str) -> ProxyNode:
    parsed = urlsplit(uri)
    qs = parse_qs(parsed.query)
    user = unquote(parsed.username or "")
    passwd = unquote(parsed.password or "")
    server = parsed.hostname or ""
    port = parsed.port or 0
    if not server or port <= 0 or not user:
        raise ValueError("invalid tuic endpoint")

    params: dict[str, Any] = {
        "udp": True,
        "tls": True,
    }
    if passwd:
        params["uuid"] = user
        params["password"] = passwd
    else:
        params["token"] = user

    if _first(qs, "congestion_control"):
        params["congestion_control"] = _first(qs, "congestion_control")
    if _first(qs, "udp_relay_mode"):
        params["udp_relay_mode"] = _first(qs, "udp_relay_mode")
    if _first(qs, "heartbeat_interval"):
        params["heartbeat_interval"] = _first(qs, "heartbeat_interval")
    _apply_tls_query_params(params, qs, force_tls=True)

    name = _normalize_name(unquote(parsed.fragment) if parsed.fragment else None, f"tuic-{server}:{port}")
    return ProxyNode(name=name, type="tuic", server=server, port=port, params=params, source_uri=uri)


def _parse_http_like(uri: str) -> ProxyNode:
    parsed = urlsplit(uri)
    scheme = parsed.scheme.lower()
    node_type = "http" if scheme in {"http", "https"} else "socks5"
    server = parsed.hostname or ""
    port = parsed.port or 0
    if not server or port <= 0:
        raise ValueError(f"invalid {node_type} endpoint")

    params: dict[str, Any] = {"udp": node_type == "socks5"}
    if parsed.username:
        params["username"] = unquote(parsed.username)
    if parsed.password:
        params["password"] = unquote(parsed.password)
    if scheme == "https":
        params["tls"] = True
    qs = parse_qs(parsed.query)
    _apply_tls_query_params(params, qs, force_tls=scheme == "https")

    name = _normalize_name(unquote(parsed.fragment) if parsed.fragment else None, f"{node_type}-{server}:{port}")
    return ProxyNode(name=name, type=node_type, server=server, port=port, params=params, source_uri=uri)


def _apply_clash_transport(proxy: dict[str, Any], params: dict[str, Any]) -> None:
    network = _first_key(proxy, "network", "net")
    if network:
        params["network"] = str(network).strip().lower()

    ws_opts = _first_key(proxy, "ws-opts", "ws_opts")
    if isinstance(ws_opts, dict):
        out: dict[str, Any] = {}
        if ws_opts.get("path"):
            out["path"] = str(ws_opts["path"])
        headers = ws_opts.get("headers")
        if isinstance(headers, dict) and headers:
            out["headers"] = {str(k): str(v) for k, v in headers.items()}
        if out:
            params["ws_opts"] = out

    grpc_opts = _first_key(proxy, "grpc-opts", "grpc_opts")
    if isinstance(grpc_opts, dict):
        service_name = _first_key(grpc_opts, "grpc-service-name", "grpc_service_name", "serviceName")
        if service_name:
            params["grpc_opts"] = {"grpc_service_name": str(service_name)}

    http_opts = _first_key(proxy, "http-opts", "http_opts")
    if isinstance(http_opts, dict):
        out = {}
        host = _clean_list(http_opts.get("host"))
        if host:
            out["host"] = host
        path = _clean_list(http_opts.get("path"))
        if path:
            out["path"] = path
        if out:
            params["http_opts"] = out

    h2_opts = _first_key(proxy, "h2-opts", "h2_opts")
    if isinstance(h2_opts, dict):
        out = {}
        host = _clean_list(h2_opts.get("host"))
        if host:
            out["host"] = host
        path = _first_key(h2_opts, "path")
        if path:
            out["path"] = str(path)
        if out:
            params["h2_opts"] = out


def _apply_clash_tls(proxy: dict[str, Any], params: dict[str, Any]) -> None:
    if "tls" in proxy:
        params["tls"] = _any_to_bool(proxy.get("tls"), default=False)

    sni = _first_key(proxy, "servername", "serverName", "sni")
    if sni:
        params["sni"] = str(sni)

    skip_verify = _first_key(proxy, "skip-cert-verify", "skip_cert_verify", "allowInsecure")
    if skip_verify is not None:
        params["skip_cert_verify"] = _any_to_bool(skip_verify, default=False)

    alpn = _clean_list(proxy.get("alpn"))
    if alpn:
        params["alpn"] = alpn

    fingerprint = _first_key(proxy, "client-fingerprint", "client_fingerprint", "fp")
    if fingerprint:
        params["client_fingerprint"] = str(fingerprint)

    reality_opts = _first_key(proxy, "reality-opts", "reality_opts")
    if isinstance(reality_opts, dict):
        public_key = _first_key(reality_opts, "public-key", "public_key")
        short_id = _first_key(reality_opts, "short-id", "short_id")
        if public_key:
            params["reality_public_key"] = str(public_key)
        if short_id:
            params["reality_short_id"] = str(short_id)


def _node_from_clash_proxy(proxy: dict[str, Any]) -> ProxyNode:
    ptype = str(proxy.get("type", "")).strip().lower()
    if ptype == "socks":
        ptype = "socks5"
    if ptype == "hysteria-2":
        ptype = "hysteria2"
    if ptype not in SUPPORTED_SCHEMES:
        raise ValueError(f"unsupported clash proxy type: {ptype}")

    server = str(proxy.get("server", "")).strip()
    port = _safe_int(proxy.get("port"), default=0)
    if not server or port <= 0:
        raise ValueError("missing server/port")

    params: dict[str, Any] = {}
    params["udp"] = _any_to_bool(proxy.get("udp"), default=True)
    name = _normalize_name(str(proxy.get("name", "")).strip(), f"{ptype}-{server}:{port}")

    if ptype == "ss":
        params["cipher"] = str(_first_key(proxy, "cipher") or "")
        params["password"] = str(_first_key(proxy, "password") or "")
        plugin = _first_key(proxy, "plugin")
        if plugin:
            params["plugin"] = str(plugin)
        plugin_opts = _first_key(proxy, "plugin-opts", "plugin_opts")
        if isinstance(plugin_opts, dict):
            params["plugin_opts"] = {str(k): str(v) for k, v in plugin_opts.items()}
    elif ptype == "ssr":
        params["cipher"] = str(_first_key(proxy, "cipher") or "")
        params["password"] = str(_first_key(proxy, "password") or "")
        params["obfs"] = str(_first_key(proxy, "obfs") or "")
        params["protocol"] = str(_first_key(proxy, "protocol") or "")
        if _first_key(proxy, "obfs-param", "obfs_param"):
            params["obfs_param"] = str(_first_key(proxy, "obfs-param", "obfs_param"))
        if _first_key(proxy, "protocol-param", "protocol_param"):
            params["protocol_param"] = str(_first_key(proxy, "protocol-param", "protocol_param"))
    elif ptype in {"vmess", "vless"}:
        params["uuid"] = str(_first_key(proxy, "uuid") or "")
        if ptype == "vmess":
            params["alter_id"] = _safe_int(_first_key(proxy, "alterId", "alter-id", "alter_id"), default=0)
            params["cipher"] = str(_first_key(proxy, "cipher", "security") or "auto")
        if ptype == "vless" and _first_key(proxy, "flow"):
            params["flow"] = str(_first_key(proxy, "flow"))
        packet = _first_key(proxy, "packet-encoding", "packet_encoding")
        if packet:
            params["packet_encoding"] = str(packet)
        _apply_clash_transport(proxy, params)
        _apply_clash_tls(proxy, params)
    elif ptype == "trojan":
        params["password"] = str(_first_key(proxy, "password") or "")
        _apply_clash_transport(proxy, params)
        _apply_clash_tls(proxy, params)
        if "tls" not in params:
            params["tls"] = True
    elif ptype in {"hysteria2", "hy2"}:
        ptype = "hysteria2"
        params["password"] = str(_first_key(proxy, "password") or "")
        if _first_key(proxy, "up", "up_mbps"):
            params["up"] = str(_first_key(proxy, "up", "up_mbps"))
        if _first_key(proxy, "down", "down_mbps"):
            params["down"] = str(_first_key(proxy, "down", "down_mbps"))
        if _first_key(proxy, "obfs"):
            params["obfs"] = str(_first_key(proxy, "obfs"))
        if _first_key(proxy, "obfs-password", "obfs_password"):
            params["obfs_password"] = str(_first_key(proxy, "obfs-password", "obfs_password"))
        _apply_clash_tls(proxy, params)
        if "tls" not in params:
            params["tls"] = True
    elif ptype == "tuic":
        if _first_key(proxy, "token"):
            params["token"] = str(_first_key(proxy, "token"))
        else:
            params["uuid"] = str(_first_key(proxy, "uuid") or "")
            params["password"] = str(_first_key(proxy, "password") or "")
        if _first_key(proxy, "congestion-controller", "congestion_control"):
            params["congestion_control"] = str(_first_key(proxy, "congestion-controller", "congestion_control"))
        if _first_key(proxy, "udp-relay-mode", "udp_relay_mode"):
            params["udp_relay_mode"] = str(_first_key(proxy, "udp-relay-mode", "udp_relay_mode"))
        if _first_key(proxy, "heartbeat-interval", "heartbeat_interval"):
            params["heartbeat_interval"] = str(_first_key(proxy, "heartbeat-interval", "heartbeat_interval"))
        _apply_clash_tls(proxy, params)
        if "tls" not in params:
            params["tls"] = True
    elif ptype in {"http", "https"}:
        ptype = "http"
        if _first_key(proxy, "username"):
            params["username"] = str(_first_key(proxy, "username"))
        if _first_key(proxy, "password"):
            params["password"] = str(_first_key(proxy, "password"))
        _apply_clash_tls(proxy, params)
        if str(proxy.get("type", "")).strip().lower() == "https":
            params["tls"] = True
    elif ptype == "socks5":
        if _first_key(proxy, "username"):
            params["username"] = str(_first_key(proxy, "username"))
        if _first_key(proxy, "password"):
            params["password"] = str(_first_key(proxy, "password"))
        _apply_clash_tls(proxy, params)

    return ProxyNode(name=name, type=ptype, server=server, port=port, params=params)


def _node_from_singbox_outbound(outbound: dict[str, Any]) -> ProxyNode | None:
    otype = str(outbound.get("type", "")).strip().lower()
    type_map = {
        "shadowsocks": "ss",
        "vmess": "vmess",
        "vless": "vless",
        "trojan": "trojan",
        "hysteria2": "hysteria2",
        "tuic": "tuic",
        "http": "http",
        "socks": "socks5",
    }
    if otype not in type_map:
        return None
    ptype = type_map[otype]

    server = str(outbound.get("server", "")).strip()
    port = _safe_int(outbound.get("server_port"), default=0)
    if not server or port <= 0:
        return None

    params: dict[str, Any] = {"udp": True}
    name = _normalize_name(str(outbound.get("tag", "")).strip(), f"{ptype}-{server}:{port}")

    if ptype == "ss":
        params["cipher"] = str(_first_key(outbound, "method") or "")
        params["password"] = str(_first_key(outbound, "password") or "")
    elif ptype in {"vmess", "vless"}:
        params["uuid"] = str(_first_key(outbound, "uuid") or "")
        if ptype == "vmess":
            params["alter_id"] = _safe_int(_first_key(outbound, "alter_id"), default=0)
            params["cipher"] = str(_first_key(outbound, "security") or "auto")
        if ptype == "vless" and _first_key(outbound, "flow"):
            params["flow"] = str(_first_key(outbound, "flow"))
        if _first_key(outbound, "packet_encoding"):
            params["packet_encoding"] = str(_first_key(outbound, "packet_encoding"))
    elif ptype == "trojan":
        params["password"] = str(_first_key(outbound, "password") or "")
    elif ptype == "hysteria2":
        params["password"] = str(_first_key(outbound, "password") or "")
        if _first_key(outbound, "up_mbps"):
            params["up"] = str(_first_key(outbound, "up_mbps"))
        if _first_key(outbound, "down_mbps"):
            params["down"] = str(_first_key(outbound, "down_mbps"))
        obfs = outbound.get("obfs")
        if isinstance(obfs, dict):
            if _first_key(obfs, "type"):
                params["obfs"] = str(_first_key(obfs, "type"))
            if _first_key(obfs, "password"):
                params["obfs_password"] = str(_first_key(obfs, "password"))
    elif ptype == "tuic":
        if _first_key(outbound, "token"):
            params["token"] = str(_first_key(outbound, "token"))
        else:
            params["uuid"] = str(_first_key(outbound, "uuid") or "")
            params["password"] = str(_first_key(outbound, "password") or "")
        if _first_key(outbound, "congestion_control"):
            params["congestion_control"] = str(_first_key(outbound, "congestion_control"))
        if _first_key(outbound, "udp_relay_mode"):
            params["udp_relay_mode"] = str(_first_key(outbound, "udp_relay_mode"))
    elif ptype in {"http", "socks5"}:
        if _first_key(outbound, "username"):
            params["username"] = str(_first_key(outbound, "username"))
        if _first_key(outbound, "password"):
            params["password"] = str(_first_key(outbound, "password"))

    transport = outbound.get("transport")
    if isinstance(transport, dict):
        ttype = str(transport.get("type", "")).strip().lower()
        if ttype in {"ws", "grpc", "http"}:
            params["network"] = "h2" if ttype == "http" and ptype in {"vmess", "vless"} else ttype
        if ttype == "ws":
            ws = {}
            if transport.get("path"):
                ws["path"] = str(transport["path"])
            if isinstance(transport.get("headers"), dict) and transport.get("headers"):
                ws["headers"] = {str(k): str(v) for k, v in transport["headers"].items()}
            if ws:
                params["ws_opts"] = ws
        if ttype == "grpc" and transport.get("service_name"):
            params["grpc_opts"] = {"grpc_service_name": str(transport["service_name"])}
        if ttype == "http":
            h2 = {}
            if transport.get("host"):
                h2["host"] = _clean_list(transport["host"])
            if transport.get("path"):
                h2["path"] = str(transport["path"])
            if h2:
                params["h2_opts"] = h2

    tls = outbound.get("tls")
    if isinstance(tls, dict) and tls.get("enabled"):
        params["tls"] = True
        if tls.get("server_name"):
            params["sni"] = str(tls["server_name"])
        if "insecure" in tls:
            params["skip_cert_verify"] = _any_to_bool(tls.get("insecure"), default=False)
        alpn = _clean_list(tls.get("alpn"))
        if alpn:
            params["alpn"] = alpn

    return ProxyNode(name=name, type=ptype, server=server, port=port, params=params)


def _parse_structured_payload(text: str) -> ParseResult:
    stripped = text.strip()
    if not stripped:
        return ParseResult(nodes=[], warnings=[])

    maybe_structured = (
        stripped.startswith("{")
        or stripped.startswith("[")
        or any(marker in stripped for marker in ("proxies:", "outbounds:", "proxy-providers:", "mixed-port:"))
    )
    if not maybe_structured:
        return ParseResult(nodes=[], warnings=[])

    try:
        document = yaml.safe_load(stripped)
    except Exception:
        return ParseResult(nodes=[], warnings=[])

    nodes: list[ProxyNode] = []
    warnings: list[str] = []

    if isinstance(document, dict):
        proxies = document.get("proxies")
        if isinstance(proxies, list):
            for index, proxy in enumerate(proxies, start=1):
                if not isinstance(proxy, dict):
                    warnings.append(f"proxies[{index}]: invalid proxy entry")
                    continue
                try:
                    nodes.append(_node_from_clash_proxy(proxy))
                except Exception as exc:
                    warnings.append(f"proxies[{index}]: {exc}")

        outbounds = document.get("outbounds")
        if isinstance(outbounds, list):
            for index, outbound in enumerate(outbounds, start=1):
                if not isinstance(outbound, dict):
                    continue
                node = _node_from_singbox_outbound(outbound)
                if node:
                    nodes.append(node)

        if not nodes and isinstance(document.get("proxy-providers"), dict):
            warnings.append("detected proxy-providers only; please provide provider content with actual node list")

    elif isinstance(document, list):
        for index, item in enumerate(document, start=1):
            if isinstance(item, dict):
                try:
                    nodes.append(_node_from_clash_proxy(item))
                except Exception as exc:
                    warnings.append(f"item[{index}]: {exc}")
            elif isinstance(item, str):
                try:
                    nodes.append(parse_uri(item.strip()))
                except Exception as exc:
                    warnings.append(f"item[{index}]: {exc}")

    _ensure_unique_names(nodes)
    return ParseResult(nodes=nodes, warnings=warnings)


def _summarize_warnings(warnings: list[str], *, max_items: int = 20) -> list[str]:
    if len(warnings) <= max_items:
        return warnings
    remain = len(warnings) - max_items
    return warnings[:max_items] + [f"... and {remain} more warnings"]


def _extract_uri_candidates_from_line(line: str) -> list[str]:
    stripped = line.strip().strip("\"'")
    if not stripped:
        return []
    if re.match(r"^[\-\s]*url\s*:", stripped, flags=re.IGNORECASE):
        return []
    if re.match(r"^(ss|ssr|vmess|vless|trojan|hysteria2|hy2|tuic|http|https|socks|socks5)://", stripped, flags=re.IGNORECASE):
        return [stripped]
    pattern = re.compile(
        r"(ssr?|vmess|vless|trojan|hysteria2|hy2|tuic|socks5?|https?)://[^\s'\",]+",
        flags=re.IGNORECASE,
    )
    return [match.group(0) for match in pattern.finditer(stripped)]


def parse_uri(line: str) -> ProxyNode:
    if "://" not in line:
        raise ValueError("missing URI scheme")
    scheme = line.split("://", 1)[0].strip().lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError(f"unsupported scheme: {scheme}")

    if scheme == "ss":
        return _parse_ss(line)
    if scheme == "ssr":
        return _parse_ssr(line)
    if scheme == "vmess":
        return _parse_vmess(line)
    if scheme == "vless":
        return _parse_vless(line)
    if scheme == "trojan":
        return _parse_trojan(line)
    if scheme in {"hysteria2", "hy2"}:
        return _parse_hysteria2(line)
    if scheme == "tuic":
        return _parse_tuic(line)
    if scheme in {"http", "https", "socks", "socks5"}:
        return _parse_http_like(line)
    raise ValueError(f"unsupported scheme: {scheme}")


def normalize_subscription_payload(payload: str) -> str:
    raw = payload.strip().lstrip("\ufeff")
    if not raw:
        return ""
    if "://" in raw:
        return raw
    decoded = _try_decode_text(raw)
    if decoded and "://" in decoded:
        return decoded
    compact = re.sub(r"\s+", "", raw)
    decoded_compact = _try_decode_text(compact)
    if decoded_compact and "://" in decoded_compact:
        return decoded_compact
    return raw


def parse_subscription(payload: str) -> ParseResult:
    normalized = normalize_subscription_payload(payload)
    if not normalized:
        return ParseResult(nodes=[], warnings=[])

    structured = _parse_structured_payload(normalized)
    if structured.nodes or structured.warnings:
        return ParseResult(nodes=structured.nodes, warnings=_summarize_warnings(structured.warnings))

    nodes: list[ProxyNode] = []
    warnings: list[str] = []
    skipped_lines = 0

    for line_no, raw_line in enumerate(normalized.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        candidates = _extract_uri_candidates_from_line(line)
        if not candidates and "://" not in line:
            decoded_line = _try_decode_text(line)
            if decoded_line and "://" in decoded_line:
                candidates = []
                for decoded_part in decoded_line.splitlines():
                    candidates.extend(_extract_uri_candidates_from_line(decoded_part))
        if not candidates:
            skipped_lines += 1
            continue

        for candidate in candidates:
            try:
                node = parse_uri(candidate)
                nodes.append(node)
            except Exception as exc:
                warnings.append(f"line {line_no}: {exc}")

    _ensure_unique_names(nodes)
    if skipped_lines and not nodes and not warnings:
        warnings.append("no URI-like nodes found; input may be a full config file instead of subscription nodes")
    return ParseResult(nodes=nodes, warnings=_summarize_warnings(warnings))


def _assert_safe_source_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("source URL must use http or https")
    if not parsed.hostname:
        raise ValueError("source URL has no hostname")
    host = parsed.hostname.lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("localhost source URL is not allowed")
    try:
        ip = ip_address(host)
    except ValueError:
        return
    if ip.is_loopback or ip.is_link_local or ip.is_private:
        raise ValueError("private source URL is not allowed")


async def fetch_subscription(url: str, timeout_sec: float = 15.0) -> str:
    _assert_safe_source_url(url)
    headers = {"User-Agent": "clash-revert/0.1 (+subscription-converter)"}
    async with httpx.AsyncClient(timeout=timeout_sec, follow_redirects=True) as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        content_length = response.headers.get("content-length")
        if content_length and int(content_length) > 5 * 1024 * 1024:
            raise ValueError("subscription payload is too large")
        return response.text
