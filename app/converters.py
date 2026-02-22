from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import yaml

from app.models import ProxyNode

SUPPORTED_TARGETS = {"mihomo", "sing-box", "uri"}

RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "SRC-IP-CIDR",
    "GEOIP",
    "GEOSITE",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "DST-PORT",
    "SRC-PORT",
    "NETWORK",
    "IN-TYPE",
    "IN-PORT",
    "IN-USER",
    "RULE-SET",
    "MATCH",
}

ALLOWED_BUILTIN_TARGETS = {"DIRECT", "REJECT", "REJECT-DROP", "GLOBAL", "PASS", "PROXY"}


@dataclass(slots=True)
class AclPolicy:
    proxy_groups: list[dict[str, Any]] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    rule_providers: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


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


def _default_mihomo_groups(nodes: list[ProxyNode]) -> list[dict[str, Any]]:
    names = [node.name for node in nodes]
    if not names:
        names = ["DIRECT"]
    elif "DIRECT" not in names:
        names.append("DIRECT")
    return [{"name": "PROXY", "type": "select", "proxies": names}]


def _default_mihomo_rules() -> list[str]:
    return ["MATCH,PROXY"]


def _sanitize_rule_provider_name(url: str) -> str:
    digest = hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]
    return f"acl_{digest}"


def _is_rule_like(line: str) -> bool:
    upper = line.split(",", 1)[0].strip().upper()
    return upper in RULE_TYPES


def _normalize_rule_line(line: str, fallback_group: str = "PROXY") -> str | None:
    value = line.strip()
    if not value:
        return None
    if value.startswith("#") or value.startswith(";") or value.startswith("//"):
        return None
    if value.startswith("[") and value.endswith("]"):
        return None
    if not _is_rule_like(value):
        return None
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if not parts:
        return None
    rule_type = parts[0].upper()
    if rule_type == "MATCH":
        return f"MATCH,{fallback_group}" if len(parts) == 1 else f"MATCH,{parts[1]}"
    if len(parts) == 1:
        return f"{rule_type},{fallback_group}"
    if len(parts) == 2:
        return f"{rule_type},{parts[1]},{fallback_group}"
    return ",".join(parts)


def _parse_custom_proxy_group(expr: str, node_names: list[str]) -> tuple[dict[str, Any] | None, str | None]:
    parts = [part.strip() for part in expr.split("`")]
    if len(parts) < 2:
        return None, f"invalid custom_proxy_group: {expr[:80]}"
    name = parts[0] or "PROXY"
    group_type = (parts[1] or "select").lower()
    rest = [item for item in parts[2:] if item]

    def add_unique(target: list[str], items: list[str]) -> None:
        for item in items:
            if item and item not in target:
                target.append(item)

    proxies: list[str] = []
    regex_filters: list[str] = []
    test_url: str | None = None
    interval = 300
    for item in rest:
        if item.startswith("[]"):
            add_unique(proxies, [item[2:].strip()])
            continue
        if item.startswith("http://") or item.startswith("https://"):
            test_url = item
            continue
        match = re.search(r"\d+", item)
        if match:
            interval = int(match.group(0))
            continue
        regex_filters.append(item)

    for pattern in regex_filters:
        try:
            matched = [name for name in node_names if re.search(pattern, name)]
        except re.error:
            continue
        add_unique(proxies, matched)

    if not proxies:
        proxies = list(node_names)
        if "DIRECT" not in proxies:
            proxies.append("DIRECT")
    group: dict[str, Any] = {"name": name, "type": group_type}
    if group_type in {"select", "relay", "fallback", "url-test", "load-balance"}:
        group["proxies"] = proxies
    else:
        # Unknown group type fallback to select to avoid invalid output.
        group["type"] = "select"
        group["proxies"] = proxies
    if group["type"] in {"fallback", "url-test", "load-balance"}:
        group["url"] = test_url or "http://www.gstatic.com/generate_204"
        group["interval"] = interval
        if group["type"] == "load-balance":
            group["strategy"] = "consistent-hashing"
    return group, None


def _ruleset_expr_to_rule(
    group: str,
    expr: str,
    providers: dict[str, Any],
) -> str | None:
    item = expr.strip()
    if not item:
        return None
    if item.startswith("[]"):
        inline = item[2:].strip()
        inline_upper = inline.upper()
        if inline_upper in {"FINAL", "MATCH"}:
            return f"MATCH,{group}"
        if "," in inline:
            normalized = _normalize_rule_line(inline, fallback_group=group)
            return normalized
        return f"DOMAIN-SUFFIX,{inline},{group}"
    if item.startswith("http://") or item.startswith("https://"):
        provider_name = _sanitize_rule_provider_name(item)
        providers[provider_name] = {
            "type": "http",
            "behavior": "classical",
            "url": item,
            "path": f"./ruleset/{provider_name}.yaml",
            "interval": 86400,
        }
        return f"RULE-SET,{provider_name},{group}"
    normalized = _normalize_rule_line(item, fallback_group=group)
    return normalized


def parse_acl_text(acl_text: str, nodes: list[ProxyNode]) -> AclPolicy:
    policy = AclPolicy()
    raw = (acl_text or "").strip()
    if not raw:
        return policy

    def _extract_from_clash_template(raw_text: str) -> AclPolicy | None:
        try:
            doc = yaml.safe_load(raw_text)
        except Exception:
            return None
        if not isinstance(doc, dict):
            return None

        raw_groups = doc.get("proxy-groups")
        raw_rules = doc.get("rules")
        raw_rule_providers = doc.get("rule-providers")
        has_groups = isinstance(raw_groups, list)
        has_rules = isinstance(raw_rules, list)
        has_rule_providers = isinstance(raw_rule_providers, dict)
        if not has_groups and not has_rules and not has_rule_providers:
            return None

        parsed = AclPolicy()
        node_names = [node.name for node in nodes]
        group_names = [
            str(group.get("name")).strip()
            for group in (raw_groups or [])
            if isinstance(group, dict) and str(group.get("name", "")).strip()
        ]
        group_name_set = set(group_names)
        group_types_with_proxies = {"select", "relay", "fallback", "url-test", "load-balance"}

        def sanitize_group(group: dict[str, Any]) -> dict[str, Any] | None:
            name = str(group.get("name", "")).strip()
            if not name:
                return None
            out: dict[str, Any] = {
                "name": name,
                "type": str(group.get("type", "select")).strip().lower() or "select",
            }
            for key in (
                "url",
                "interval",
                "strategy",
                "tolerance",
                "lazy",
                "expected-status",
                "max-failed-times",
                "disable-udp",
                "hidden",
                "icon",
            ):
                if key in group:
                    out[key] = group[key]

            raw_proxies = group.get("proxies")
            need_proxies = out["type"] in group_types_with_proxies
            if isinstance(raw_proxies, list):
                template_proxies: list[str] = []
                for item in raw_proxies:
                    proxy = str(item).strip()
                    if not proxy:
                        continue
                    if (
                        proxy in node_names
                        or proxy in group_name_set
                        or proxy in ALLOWED_BUILTIN_TARGETS
                    ):
                        if proxy not in template_proxies:
                            template_proxies.append(proxy)
                if need_proxies:
                    # Keep user's original node order first, then append template-only items.
                    proxies: list[str] = list(node_names)
                    for proxy in template_proxies:
                        if proxy not in proxies:
                            proxies.append(proxy)
                else:
                    proxies = template_proxies
                if need_proxies and not proxies:
                    proxies = ["DIRECT"]
                if proxies:
                    out["proxies"] = proxies
            elif need_proxies:
                out["proxies"] = list(dict.fromkeys(node_names + ["DIRECT"]))
            return out

        rename_group_map: dict[str, str] = {}

        if has_groups:
            for group in raw_groups:
                if not isinstance(group, dict):
                    continue
                sanitized = sanitize_group(group)
                if sanitized:
                    parsed.proxy_groups.append(sanitized)

        # Normalize MESL-like template entry group:
        # 1) first group name MESL -> Select
        # 2) move Auto/Fallback to the top in first group
        if parsed.proxy_groups:
            first_group = parsed.proxy_groups[0]
            first_name = str(first_group.get("name", "")).strip()
            if first_name.lower() == "mesl":
                first_group["name"] = "Select"
                rename_group_map[first_name] = "Select"
            if isinstance(first_group.get("proxies"), list):
                proxies = [str(item).strip() for item in first_group["proxies"] if str(item).strip()]
                top: list[str] = []
                for preferred in ("Auto", "Fallback"):
                    for item in proxies:
                        if item.lower() == preferred.lower() and item not in top:
                            top.append(item)
                rest = [item for item in proxies if item not in top]
                first_group["proxies"] = top + rest

        if rename_group_map:
            for group in parsed.proxy_groups:
                if isinstance(group.get("proxies"), list):
                    group["proxies"] = [rename_group_map.get(item, item) for item in group["proxies"]]

        if not parsed.proxy_groups:
            parsed.proxy_groups = _default_mihomo_groups(nodes)
        default_rule_target = parsed.proxy_groups[0]["name"] if parsed.proxy_groups else "PROXY"

        valid_targets = {
            *(group["name"] for group in parsed.proxy_groups if isinstance(group, dict) and group.get("name")),
            *ALLOWED_BUILTIN_TARGETS,
        }

        def normalize_rule_target(rule: str) -> str | None:
            parts = [part.strip() for part in rule.split(",")]
            if not parts:
                return None
            rtype = parts[0].upper()
            target_index = 1 if rtype == "MATCH" else 2
            if len(parts) <= target_index:
                return None
            parts[target_index] = rename_group_map.get(parts[target_index], parts[target_index])
            if parts[target_index] not in valid_targets:
                parts[target_index] = default_rule_target
            return ",".join(parts)

        if has_rules:
            for item in raw_rules:
                if not isinstance(item, str):
                    continue
                normalized = normalize_rule_target(item.strip())
                if normalized:
                    parsed.rules.append(normalized)

        if has_rule_providers:
            parsed.rule_providers = dict(raw_rule_providers)
        return parsed

    extracted = _extract_from_clash_template(raw)
    if extracted:
        return extracted

    lines = [line.strip() for line in raw.replace("\ufeff", "").splitlines()]
    node_names = [node.name for node in nodes]

    is_acl4ssr = any(line.startswith("ruleset=") or line.startswith("custom_proxy_group=") for line in lines)
    if is_acl4ssr:
        for line in lines:
            if not line or line.startswith(("#", ";", "//")):
                continue
            if line.startswith("[") and line.endswith("]"):
                continue
            if line.startswith("custom_proxy_group="):
                expr = line.split("=", 1)[1].strip()
                group, warning = _parse_custom_proxy_group(expr, node_names)
                if warning:
                    policy.warnings.append(warning)
                    continue
                if group:
                    policy.proxy_groups.append(group)
                continue
            if line.startswith("ruleset="):
                body = line.split("=", 1)[1].strip()
                if "," not in body:
                    policy.warnings.append(f"invalid ruleset line: {line[:80]}")
                    continue
                group, expr = body.split(",", 1)
                rule = _ruleset_expr_to_rule(group.strip(), expr.strip(), policy.rule_providers)
                if rule:
                    policy.rules.append(rule)
                continue
        return policy

    for line in lines:
        normalized = _normalize_rule_line(line)
        if normalized:
            policy.rules.append(normalized)
    return policy


def _build_mihomo_acl(nodes: list[ProxyNode], acl_text: str | None) -> tuple[list[dict[str, Any]], list[str], dict[str, Any], list[str]]:
    groups = _default_mihomo_groups(nodes)
    rules = _default_mihomo_rules()
    providers: dict[str, Any] = {}
    warnings: list[str] = []
    if not acl_text or not acl_text.strip():
        return groups, rules, providers, warnings

    parsed = parse_acl_text(acl_text, nodes)
    if parsed.proxy_groups:
        groups = parsed.proxy_groups
    if parsed.rules:
        rules = parsed.rules
    if parsed.rule_providers:
        providers = parsed.rule_providers
    warnings.extend(parsed.warnings)
    return groups, rules, providers, warnings


def render_mihomo(nodes: list[ProxyNode], *, acl_text: str | None = None) -> tuple[str, list[str]]:
    proxies = [node_to_mihomo_proxy(node) for node in nodes]
    proxy_groups, rules, rule_providers, acl_warnings = _build_mihomo_acl(nodes, acl_text)
    config: dict[str, Any] = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": rules,
    }
    if rule_providers:
        config["rule-providers"] = rule_providers
    return yaml.safe_dump(config, sort_keys=False, allow_unicode=True), acl_warnings


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
    acl_text: str | None = None,
) -> tuple[str, list[str], str]:
    if target not in SUPPORTED_TARGETS:
        raise ValueError(f"unsupported target: {target}")

    if target == "mihomo":
        output, warnings = render_mihomo(nodes, acl_text=acl_text)
        return output, warnings, "text/yaml; charset=utf-8"
    if target == "sing-box":
        output, warnings = render_sing_box(nodes)
        if acl_text and acl_text.strip():
            warnings.append("ACL rules are currently applied only to Mihomo output.")
        return output, warnings, "application/json; charset=utf-8"
    if target == "uri":
        warnings: list[str] = []
        if acl_text and acl_text.strip():
            warnings.append("ACL rules are ignored for URI output.")
        return render_uri_bundle(nodes, as_base64=uri_as_base64), warnings, "text/plain; charset=utf-8"
    raise ValueError(f"unsupported target: {target}")
