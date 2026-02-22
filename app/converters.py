from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote

import yaml

from app.models import ProxyNode

SUPPORTED_TARGETS = {"mihomo", "sing-box", "uri"}


def _tls_fields_for_mihomo(node: ProxyNode, output: dict[str, Any]) -> None:
    params = node.params
    if "tls" in params:
        output["tls"] = bool(params["tls"])
    sni = params.get("sni")
    if sni:
        if node.type in {"vmess", "vless"}:
            output["servername"] = sni
        else:
            output["sni"] = sni
    if "skip_cert_verify" in params:
        output["skip-cert-verify"] = bool(params["skip_cert_verify"])
    alpn = params.get("alpn")
    if alpn:
        output["alpn"] = list(alpn)
    client_fingerprint = params.get("client_fingerprint")
    if client_fingerprint:
        output["client-fingerprint"] = client_fingerprint
    reality_public_key = params.get("reality_public_key")
    reality_short_id = params.get("reality_short_id")
    if reality_public_key:
        output["reality-opts"] = {"public-key": reality_public_key}
        if reality_short_id:
            output["reality-opts"]["short-id"] = reality_short_id


def _transport_fields_for_mihomo(node: ProxyNode, output: dict[str, Any]) -> None:
    params = node.params
    network = params.get("network")
    if network:
        output["network"] = network
    if params.get("ws_opts"):
        ws_opts: dict[str, Any] = {}
        path = params["ws_opts"].get("path")
        if path:
            ws_opts["path"] = path
        headers = params["ws_opts"].get("headers")
        if headers:
            ws_opts["headers"] = headers
        if ws_opts:
            output["ws-opts"] = ws_opts
    if params.get("grpc_opts"):
        grpc_opts: dict[str, Any] = {}
        service_name = params["grpc_opts"].get("grpc_service_name")
        if service_name:
            grpc_opts["grpc-service-name"] = service_name
        if grpc_opts:
            output["grpc-opts"] = grpc_opts
    if params.get("http_opts"):
        http_opts: dict[str, Any] = {}
        if params["http_opts"].get("host"):
            http_opts["host"] = list(params["http_opts"]["host"])
        if params["http_opts"].get("path"):
            http_opts["path"] = list(params["http_opts"]["path"])
        if http_opts:
            output["http-opts"] = http_opts
    if params.get("h2_opts"):
        h2_opts: dict[str, Any] = {}
        if params["h2_opts"].get("host"):
            h2_opts["host"] = list(params["h2_opts"]["host"])
        if params["h2_opts"].get("path"):
            h2_opts["path"] = params["h2_opts"]["path"]
        if h2_opts:
            output["h2-opts"] = h2_opts


def node_to_mihomo_proxy(node: ProxyNode) -> dict[str, Any]:
    params = node.params
    out: dict[str, Any] = {
        "name": node.name,
        "type": node.type,
        "server": node.server,
        "port": node.port,
    }
    if "udp" in params:
        out["udp"] = bool(params["udp"])

    if node.type == "ss":
        out["cipher"] = params.get("cipher", "aes-128-gcm")
        out["password"] = params.get("password", "")
        if params.get("plugin"):
            out["plugin"] = params["plugin"]
        if params.get("plugin_opts"):
            out["plugin-opts"] = params["plugin_opts"]
    elif node.type == "ssr":
        out["cipher"] = params.get("cipher", "aes-128-gcm")
        out["password"] = params.get("password", "")
        out["obfs"] = params.get("obfs", "plain")
        out["protocol"] = params.get("protocol", "origin")
        if params.get("obfs_param"):
            out["obfs-param"] = params["obfs_param"]
        if params.get("protocol_param"):
            out["protocol-param"] = params["protocol_param"]
    elif node.type == "vmess":
        out["uuid"] = params.get("uuid", "")
        out["alterId"] = int(params.get("alter_id", 0))
        out["cipher"] = params.get("cipher", "auto")
        if params.get("packet_encoding"):
            out["packet-encoding"] = params["packet_encoding"]
        _transport_fields_for_mihomo(node, out)
        _tls_fields_for_mihomo(node, out)
    elif node.type == "vless":
        out["uuid"] = params.get("uuid", "")
        if params.get("flow"):
            out["flow"] = params["flow"]
        if params.get("packet_encoding"):
            out["packet-encoding"] = params["packet_encoding"]
        _transport_fields_for_mihomo(node, out)
        _tls_fields_for_mihomo(node, out)
    elif node.type == "trojan":
        out["password"] = params.get("password", "")
        _transport_fields_for_mihomo(node, out)
        _tls_fields_for_mihomo(node, out)
    elif node.type == "hysteria2":
        out["password"] = params.get("password", "")
        if params.get("up"):
            out["up"] = params["up"]
        if params.get("down"):
            out["down"] = params["down"]
        if params.get("obfs"):
            out["obfs"] = params["obfs"]
        if params.get("obfs_password"):
            out["obfs-password"] = params["obfs_password"]
        _tls_fields_for_mihomo(node, out)
    elif node.type == "tuic":
        if params.get("token"):
            out["token"] = params["token"]
        else:
            out["uuid"] = params.get("uuid", "")
            out["password"] = params.get("password", "")
        if params.get("congestion_control"):
            out["congestion-controller"] = params["congestion_control"]
        if params.get("udp_relay_mode"):
            out["udp-relay-mode"] = params["udp_relay_mode"]
        if params.get("heartbeat_interval"):
            out["heartbeat-interval"] = params["heartbeat_interval"]
        _tls_fields_for_mihomo(node, out)
    elif node.type == "http":
        if params.get("username"):
            out["username"] = params["username"]
        if params.get("password"):
            out["password"] = params["password"]
        _tls_fields_for_mihomo(node, out)
    elif node.type == "socks5":
        if params.get("username"):
            out["username"] = params["username"]
        if params.get("password"):
            out["password"] = params["password"]
        _tls_fields_for_mihomo(node, out)
    else:
        raise ValueError(f"unsupported node type for mihomo: {node.type}")

    return out


def render_mihomo(nodes: list[ProxyNode]) -> str:
    proxies = [node_to_mihomo_proxy(node) for node in nodes]
    group_proxies = [proxy["name"] for proxy in proxies]
    if not group_proxies:
        group_proxies = ["DIRECT"]
    else:
        group_proxies.append("DIRECT")
    config: dict[str, Any] = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": group_proxies},
        ],
        "rules": ["MATCH,PROXY"],
    }
    return yaml.safe_dump(config, sort_keys=False, allow_unicode=True)


def _build_singbox_tls(params: dict[str, Any], *, force: bool = False) -> dict[str, Any] | None:
    enabled = bool(params.get("tls", False))
    if not enabled and not force:
        return None
    tls: dict[str, Any] = {"enabled": True}
    if params.get("sni"):
        tls["server_name"] = params["sni"]
    if "skip_cert_verify" in params:
        tls["insecure"] = bool(params["skip_cert_verify"])
    if params.get("alpn"):
        tls["alpn"] = list(params["alpn"])
    return tls


def _build_singbox_transport(params: dict[str, Any]) -> dict[str, Any] | None:
    network = params.get("network")
    if network == "ws":
        transport: dict[str, Any] = {"type": "ws"}
        if params.get("ws_opts", {}).get("path"):
            transport["path"] = params["ws_opts"]["path"]
        if params.get("ws_opts", {}).get("headers"):
            transport["headers"] = params["ws_opts"]["headers"]
        return transport
    if network == "grpc":
        transport = {"type": "grpc"}
        if params.get("grpc_opts", {}).get("grpc_service_name"):
            transport["service_name"] = params["grpc_opts"]["grpc_service_name"]
        return transport
    if network == "http":
        transport = {"type": "http"}
        if params.get("http_opts", {}).get("host"):
            transport["host"] = list(params["http_opts"]["host"])
        if params.get("http_opts", {}).get("path"):
            transport["path"] = params["http_opts"]["path"][0]
        return transport
    if network == "h2":
        transport = {"type": "http"}
        if params.get("h2_opts", {}).get("host"):
            transport["host"] = list(params["h2_opts"]["host"])
        if params.get("h2_opts", {}).get("path"):
            transport["path"] = params["h2_opts"]["path"]
        return transport
    return None


def _to_int_mbps(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip().lower().replace("mbps", "").strip()
    try:
        return int(float(text))
    except ValueError:
        return None


def render_sing_box(nodes: list[ProxyNode]) -> tuple[str, list[str]]:
    warnings: list[str] = []
    outbounds: list[dict[str, Any]] = []
    tags: list[str] = []

    for node in nodes:
        params = node.params
        outbound: dict[str, Any]
        if node.type == "ss":
            outbound = {
                "type": "shadowsocks",
                "tag": node.name,
                "server": node.server,
                "server_port": node.port,
                "method": params.get("cipher", "aes-128-gcm"),
                "password": params.get("password", ""),
            }
        elif node.type == "vmess":
            outbound = {
                "type": "vmess",
                "tag": node.name,
                "server": node.server,
                "server_port": node.port,
                "uuid": params.get("uuid", ""),
                "security": params.get("cipher", "auto"),
                "alter_id": int(params.get("alter_id", 0)),
            }
            if params.get("packet_encoding"):
                outbound["packet_encoding"] = params["packet_encoding"]
            transport = _build_singbox_transport(params)
            if transport:
                outbound["transport"] = transport
            tls = _build_singbox_tls(params)
            if tls:
                outbound["tls"] = tls
        elif node.type == "vless":
            outbound = {
                "type": "vless",
                "tag": node.name,
                "server": node.server,
                "server_port": node.port,
                "uuid": params.get("uuid", ""),
            }
            if params.get("flow"):
                outbound["flow"] = params["flow"]
            if params.get("packet_encoding"):
                outbound["packet_encoding"] = params["packet_encoding"]
            transport = _build_singbox_transport(params)
            if transport:
                outbound["transport"] = transport
            tls = _build_singbox_tls(params)
            if tls:
                outbound["tls"] = tls
        elif node.type == "trojan":
            outbound = {
                "type": "trojan",
                "tag": node.name,
                "server": node.server,
                "server_port": node.port,
                "password": params.get("password", ""),
            }
            transport = _build_singbox_transport(params)
            if transport:
                outbound["transport"] = transport
            tls = _build_singbox_tls(params, force=True)
            if tls:
                outbound["tls"] = tls
        elif node.type == "hysteria2":
            outbound = {
                "type": "hysteria2",
                "tag": node.name,
                "server": node.server,
                "server_port": node.port,
                "password": params.get("password", ""),
            }
            up_mbps = _to_int_mbps(params.get("up"))
            down_mbps = _to_int_mbps(params.get("down"))
            if up_mbps is not None:
                outbound["up_mbps"] = up_mbps
            if down_mbps is not None:
                outbound["down_mbps"] = down_mbps
            if params.get("obfs") and params.get("obfs_password"):
                outbound["obfs"] = {"type": params["obfs"], "password": params["obfs_password"]}
            tls = _build_singbox_tls(params, force=True)
            if tls:
                outbound["tls"] = tls
        elif node.type == "tuic":
            if params.get("token"):
                warnings.append(f"{node.name}: sing-box TUIC output requires uuid/password, token-only skipped")
                continue
            outbound = {
                "type": "tuic",
                "tag": node.name,
                "server": node.server,
                "server_port": node.port,
                "uuid": params.get("uuid", ""),
                "password": params.get("password", ""),
            }
            if params.get("congestion_control"):
                outbound["congestion_control"] = params["congestion_control"]
            if params.get("udp_relay_mode"):
                outbound["udp_relay_mode"] = params["udp_relay_mode"]
            tls = _build_singbox_tls(params, force=True)
            if tls:
                outbound["tls"] = tls
        elif node.type == "http":
            outbound = {
                "type": "http",
                "tag": node.name,
                "server": node.server,
                "server_port": node.port,
            }
            if params.get("username"):
                outbound["username"] = params["username"]
            if params.get("password"):
                outbound["password"] = params["password"]
            tls = _build_singbox_tls(params)
            if tls:
                outbound["tls"] = tls
        elif node.type == "socks5":
            outbound = {
                "type": "socks",
                "tag": node.name,
                "server": node.server,
                "server_port": node.port,
            }
            if params.get("username"):
                outbound["username"] = params["username"]
            if params.get("password"):
                outbound["password"] = params["password"]
            tls = _build_singbox_tls(params)
            if tls:
                outbound["tls"] = tls
        else:
            warnings.append(f"{node.name}: {node.type} is not supported in sing-box output")
            continue

        outbounds.append(outbound)
        tags.append(node.name)

    outbounds.extend(
        [
            {"type": "selector", "tag": "select", "outbounds": tags + ["direct"]},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ]
    )

    config = {
        "log": {"level": "info"},
        "outbounds": outbounds,
        "route": {"final": "select", "auto_detect_interface": True},
    }
    return json.dumps(config, ensure_ascii=False, indent=2), warnings


def _node_to_uri(node: ProxyNode) -> str:
    if node.source_uri:
        return node.source_uri

    params = node.params
    if node.type == "ss":
        raw = f"{params.get('cipher', 'aes-128-gcm')}:{params.get('password', '')}"
        user = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
        return f"ss://{user}@{node.server}:{node.port}#{quote(node.name)}"
    if node.type == "vmess":
        vmess = {
            "v": "2",
            "ps": node.name,
            "add": node.server,
            "port": str(node.port),
            "id": params.get("uuid", ""),
            "aid": str(params.get("alter_id", 0)),
            "scy": params.get("cipher", "auto"),
            "net": params.get("network", "tcp"),
            "tls": "tls" if params.get("tls") else "",
        }
        if params.get("sni"):
            vmess["sni"] = params["sni"]
        if params.get("ws_opts", {}).get("path"):
            vmess["path"] = params["ws_opts"]["path"]
        if params.get("ws_opts", {}).get("headers", {}).get("Host"):
            vmess["host"] = params["ws_opts"]["headers"]["Host"]
        encoded = base64.b64encode(json.dumps(vmess, ensure_ascii=False).encode()).decode()
        return f"vmess://{encoded}"
    if node.type == "vless":
        query: list[str] = []
        network = params.get("network")
        if network and network != "tcp":
            query.append(f"type={quote(str(network))}")
        if params.get("tls"):
            query.append("security=tls")
        if params.get("sni"):
            query.append(f"sni={quote(str(params['sni']))}")
        if params.get("flow"):
            query.append(f"flow={quote(str(params['flow']))}")
        if params.get("ws_opts", {}).get("path"):
            query.append(f"path={quote(str(params['ws_opts']['path']))}")
        if params.get("ws_opts", {}).get("headers", {}).get("Host"):
            query.append(f"host={quote(str(params['ws_opts']['headers']['Host']))}")
        query_str = f"?{'&'.join(query)}" if query else ""
        return (
            f"vless://{params.get('uuid', '')}@{node.server}:{node.port}{query_str}"
            f"#{quote(node.name)}"
        )
    if node.type == "trojan":
        query: list[str] = []
        if params.get("network") and params.get("network") != "tcp":
            query.append(f"type={quote(str(params['network']))}")
        if params.get("sni"):
            query.append(f"sni={quote(str(params['sni']))}")
        if params.get("ws_opts", {}).get("path"):
            query.append(f"path={quote(str(params['ws_opts']['path']))}")
        if params.get("ws_opts", {}).get("headers", {}).get("Host"):
            query.append(f"host={quote(str(params['ws_opts']['headers']['Host']))}")
        query_str = f"?{'&'.join(query)}" if query else ""
        return (
            f"trojan://{quote(str(params.get('password', '')))}@{node.server}:{node.port}{query_str}"
            f"#{quote(node.name)}"
        )
    if node.type == "hysteria2":
        query: list[str] = []
        if params.get("sni"):
            query.append(f"sni={quote(str(params['sni']))}")
        if params.get("obfs"):
            query.append(f"obfs={quote(str(params['obfs']))}")
        if params.get("obfs_password"):
            query.append(f"obfs-password={quote(str(params['obfs_password']))}")
        if params.get("up"):
            query.append(f"up={quote(str(params['up']))}")
        if params.get("down"):
            query.append(f"down={quote(str(params['down']))}")
        query_str = f"?{'&'.join(query)}" if query else ""
        return (
            f"hysteria2://{quote(str(params.get('password', '')))}@{node.server}:{node.port}{query_str}"
            f"#{quote(node.name)}"
        )
    if node.type == "tuic":
        auth = params.get("token") or f"{params.get('uuid', '')}:{params.get('password', '')}"
        query: list[str] = []
        if params.get("sni"):
            query.append(f"sni={quote(str(params['sni']))}")
        if params.get("congestion_control"):
            query.append(f"congestion_control={quote(str(params['congestion_control']))}")
        if params.get("udp_relay_mode"):
            query.append(f"udp_relay_mode={quote(str(params['udp_relay_mode']))}")
        query_str = f"?{'&'.join(query)}" if query else ""
        return f"tuic://{quote(str(auth))}@{node.server}:{node.port}{query_str}#{quote(node.name)}"
    if node.type == "http":
        userpass = ""
        if params.get("username"):
            userpass = quote(str(params["username"]))
            if params.get("password"):
                userpass += f":{quote(str(params['password']))}"
            userpass += "@"
        scheme = "https" if params.get("tls") else "http"
        return f"{scheme}://{userpass}{node.server}:{node.port}#{quote(node.name)}"
    if node.type == "socks5":
        userpass = ""
        if params.get("username"):
            userpass = quote(str(params["username"]))
            if params.get("password"):
                userpass += f":{quote(str(params['password']))}"
            userpass += "@"
        return f"socks5://{userpass}{node.server}:{node.port}#{quote(node.name)}"
    return ""


def render_uri_bundle(nodes: list[ProxyNode], *, as_base64: bool = False) -> str:
    lines = [line for line in (_node_to_uri(node) for node in nodes) if line]
    output = "\n".join(lines)
    if as_base64:
        return base64.b64encode(output.encode("utf-8")).decode("utf-8")
    return output


def convert_nodes(
    nodes: list[ProxyNode],
    target: str,
    *,
    uri_as_base64: bool = False,
) -> tuple[str, list[str], str]:
    if target not in SUPPORTED_TARGETS:
        raise ValueError(f"unsupported target: {target}")

    if target == "mihomo":
        return render_mihomo(nodes), [], "text/yaml; charset=utf-8"
    if target == "sing-box":
        output, warnings = render_sing_box(nodes)
        return output, warnings, "application/json; charset=utf-8"
    if target == "uri":
        return render_uri_bundle(nodes, as_base64=uri_as_base64), [], "text/plain; charset=utf-8"
    raise ValueError(f"unsupported target: {target}")
