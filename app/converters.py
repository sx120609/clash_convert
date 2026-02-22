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

SUPPORTED_TARGETS = {"mihomo", "sing-box", "surge", "uri"}

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
MESL_SELECT_NAME = "🎯 Select"


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
        is_mesl_template = False

        if has_groups:
            for group in raw_groups:
                if not isinstance(group, dict):
                    continue
                sanitized = sanitize_group(group)
                if sanitized:
                    parsed.proxy_groups.append(sanitized)

        # Normalize MESL-like template entry group:
        # 1) first group name MESL -> 🎯 Select
        # 2) move Auto/Fallback to the top in first group
        if parsed.proxy_groups:
            first_group = parsed.proxy_groups[0]
            first_name = str(first_group.get("name", "")).strip()
            if first_name.lower() == "mesl":
                is_mesl_template = True
                first_group["name"] = MESL_SELECT_NAME
                rename_group_map[first_name] = MESL_SELECT_NAME
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

        # For MESL template groups in mainland usage:
        # - Apple/Bilibili/Microsoft/Steam groups default to DIRECT
        # - other groups default to 🎯 Select
        # - every business select group must include both 🎯 Select and DIRECT
        #   and pin them to first/second position.
        if is_mesl_template:
            direct_default_keywords = {"apple", "bilibili", "microsoft", "steam"}
            loop_guard_group_names = {"select", MESL_SELECT_NAME.lower(), "auto", "fallback"}

            def _is_direct_default_group(name: str) -> bool:
                lower = name.lower()
                return any(keyword in lower for keyword in direct_default_keywords)

            for group in parsed.proxy_groups:
                group_name = str(group.get("name", "")).strip()
                group_type = str(group.get("type", "select")).strip().lower()
                # Avoid introducing cyclic references in scheduler groups such as Auto/Fallback.
                if group_name.lower() in loop_guard_group_names:
                    continue
                if group_type != "select":
                    continue
                raw_proxies = group.get("proxies")
                if not isinstance(raw_proxies, list):
                    continue
                proxies: list[str] = []
                for item in raw_proxies:
                    proxy = str(item).strip()
                    if proxy and proxy not in proxies:
                        proxies.append(proxy)
                if not proxies:
                    proxies = []

                select_item = next(
                    (item for item in proxies if item.lower() in {"select", MESL_SELECT_NAME.lower()}),
                    None,
                ) or MESL_SELECT_NAME
                direct_item = next((item for item in proxies if item.upper() == "DIRECT"), None) or "DIRECT"
                rest = [item for item in proxies if item not in {select_item, direct_item}]

                if _is_direct_default_group(group_name):
                    group["proxies"] = [direct_item, select_item, *rest]
                else:
                    group["proxies"] = [select_item, direct_item, *rest]

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


def _quote_surge_value(value: Any) -> str:
    text = str(value)
    if any(ch in text for ch in [",", " ", "\t", '"']):
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return text


def _surge_safe_name(name: str, used: set[str]) -> str:
    base = re.sub(r"[\r\n]", " ", name).strip()
    if not base:
        base = "proxy"
    base = base.replace(",", "_").replace("=", "_")
    final = base
    index = 2
    while final in used:
        final = f"{base}-{index}"
        index += 1
    used.add(final)
    return final


def _surge_resolve_builtin_target(target: str, default_policy: str) -> str | None:
    upper = target.upper()
    if upper == "DIRECT":
        return "DIRECT"
    if upper in {"REJECT", "REJECT-DROP"}:
        return "REJECT"
    if upper == "PASS":
        return "DIRECT"
    if upper in {"PROXY", "GLOBAL"}:
        return default_policy
    return None


def _surge_resolve_policy_target(
    target: str,
    *,
    proxy_name_map: dict[str, str],
    group_name_map: dict[str, str],
    default_policy: str,
) -> str:
    value = (target or "").strip()
    if not value:
        return default_policy
    if value in proxy_name_map:
        return proxy_name_map[value]
    if value in group_name_map:
        return group_name_map[value]
    builtin = _surge_resolve_builtin_target(value, default_policy)
    if builtin:
        return builtin
    return default_policy


def _surge_convert_rule(
    rule: str,
    *,
    providers: dict[str, Any],
    proxy_name_map: dict[str, str],
    group_name_map: dict[str, str],
    default_policy: str,
) -> tuple[str | None, str | None]:
    parts = [part.strip() for part in rule.split(",")]
    if not parts or not parts[0]:
        return None, "invalid empty rule line"

    rule_type = parts[0].upper()
    if rule_type == "MATCH":
        target = parts[1] if len(parts) > 1 else default_policy
        resolved = _surge_resolve_policy_target(
            target,
            proxy_name_map=proxy_name_map,
            group_name_map=group_name_map,
            default_policy=default_policy,
        )
        return f"FINAL,{resolved}", None

    if len(parts) < 3:
        return None, f"invalid rule missing target: {rule}"

    value = parts[1]
    target = _surge_resolve_policy_target(
        parts[2],
        proxy_name_map=proxy_name_map,
        group_name_map=group_name_map,
        default_policy=default_policy,
    )
    extras = [item for item in parts[3:] if item]

    supported = {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "IP-CIDR",
        "IP-CIDR6",
        "GEOIP",
        "PROCESS-NAME",
        "DST-PORT",
        "SRC-PORT",
    }
    if rule_type in supported:
        out = f"{rule_type},{value},{target}"
        if extras:
            out += f",{','.join(extras)}"
        return out, None

    if rule_type == "RULE-SET":
        rule_set_url = value
        if not (rule_set_url.startswith("http://") or rule_set_url.startswith("https://")):
            provider = providers.get(value)
            if isinstance(provider, dict):
                candidate = str(provider.get("url", "")).strip()
                if candidate.startswith("http://") or candidate.startswith("https://"):
                    rule_set_url = candidate
        if not (rule_set_url.startswith("http://") or rule_set_url.startswith("https://")):
            return None, f"RULE-SET provider/url not found for surge: {value}"
        out = f"RULE-SET,{rule_set_url},{target}"
        if extras:
            out += f",{','.join(extras)}"
        return out, None

    return None, f"rule type '{rule_type}' is not supported in surge output"


def _surge_ws_opts(params: dict[str, Any]) -> tuple[list[str], str | None]:
    network = str(params.get("network") or "tcp").lower()
    if network in {"tcp", "none", ""}:
        return [], None
    if network != "ws":
        return [], f"transport '{network}' is not supported by surge"

    opts = ["ws=true"]
    path = params.get("ws_opts", {}).get("path")
    if path:
        opts.append(f"ws-path={_quote_surge_value(path)}")
    host = params.get("ws_opts", {}).get("headers", {}).get("Host")
    if host:
        opts.append(f"ws-headers={_quote_surge_value(f'Host:{host}')}")
    return opts, None


def _build_surge_proxy_entry(node: ProxyNode, surge_name: str) -> tuple[str | None, str | None]:
    params = node.params
    opts: list[str]

    if node.type == "ss":
        opts = [
            f"encrypt-method={_quote_surge_value(params.get('cipher', 'aes-128-gcm'))}",
            f"password={_quote_surge_value(params.get('password', ''))}",
            "udp-relay=true",
        ]
        return f"{surge_name} = ss, {node.server}, {node.port}, {', '.join(opts)}", None
    if node.type == "vmess":
        ws_opts, ws_warning = _surge_ws_opts(params)
        if ws_warning:
            return None, f"{node.name}: {ws_warning}"
        opts = [f"username={_quote_surge_value(params.get('uuid', ''))}"]
        ignore_alter_id = int(params.get("alter_id", 0)) != 0
        if params.get("tls"):
            opts.append("tls=true")
        if params.get("sni"):
            opts.append(f"sni={_quote_surge_value(params['sni'])}")
        if "skip_cert_verify" in params:
            opts.append(f"skip-cert-verify={str(bool(params['skip_cert_verify'])).lower()}")
        opts.extend(ws_opts)
        warning = f"{node.name}: surge vmess ignores alter_id" if ignore_alter_id else None
        return f"{surge_name} = vmess, {node.server}, {node.port}, {', '.join(opts)}", warning
    if node.type == "trojan":
        ws_opts, ws_warning = _surge_ws_opts(params)
        if ws_warning:
            return None, f"{node.name}: {ws_warning}"
        opts = [f"password={_quote_surge_value(params.get('password', ''))}"]
        if params.get("sni"):
            opts.append(f"sni={_quote_surge_value(params['sni'])}")
        if "skip_cert_verify" in params:
            opts.append(f"skip-cert-verify={str(bool(params['skip_cert_verify'])).lower()}")
        opts.extend(ws_opts)
        return f"{surge_name} = trojan, {node.server}, {node.port}, {', '.join(opts)}", None
    if node.type == "http":
        opts = []
        if params.get("username"):
            opts.append(f"username={_quote_surge_value(params['username'])}")
        if params.get("password"):
            opts.append(f"password={_quote_surge_value(params['password'])}")
        if params.get("tls"):
            opts.append("tls=true")
        if "skip_cert_verify" in params:
            opts.append(f"skip-cert-verify={str(bool(params['skip_cert_verify'])).lower()}")
        line = f"{surge_name} = http, {node.server}, {node.port}"
        if opts:
            line += f", {', '.join(opts)}"
        return line, None
    if node.type == "socks5":
        opts = []
        if params.get("username"):
            opts.append(f"username={_quote_surge_value(params['username'])}")
        if params.get("password"):
            opts.append(f"password={_quote_surge_value(params['password'])}")
        if params.get("tls"):
            opts.append("tls=true")
        if "skip_cert_verify" in params:
            opts.append(f"skip-cert-verify={str(bool(params['skip_cert_verify'])).lower()}")
        line = f"{surge_name} = socks5, {node.server}, {node.port}"
        if opts:
            line += f", {', '.join(opts)}"
        return line, None
    return None, f"{node.name}: {node.type} is not supported in surge output"


def render_surge(nodes: list[ProxyNode], *, acl_text: str | None = None) -> tuple[str, list[str]]:
    warnings: list[str] = []
    used_names: set[str] = set()
    proxy_lines: list[str] = []
    proxy_name_map: dict[str, str] = {}
    proxy_names: list[str] = []

    for node in nodes:
        surge_name = _surge_safe_name(node.name, used_names)
        line, warning = _build_surge_proxy_entry(node, surge_name)
        if warning:
            warnings.append(warning)
        if not line:
            continue

        proxy_lines.append(line)
        proxy_name_map[node.name] = surge_name
        proxy_names.append(surge_name)

    parsed_acl = parse_acl_text(acl_text or "", nodes) if acl_text and acl_text.strip() else AclPolicy()
    warnings.extend(parsed_acl.warnings)

    group_lines: list[str] = []
    group_name_map: dict[str, str] = {}
    raw_groups: list[dict[str, Any]] = []

    if parsed_acl.proxy_groups:
        for group in parsed_acl.proxy_groups:
            if not isinstance(group, dict):
                continue
            raw_name = str(group.get("name", "")).strip()
            if not raw_name:
                continue
            safe_group_name = _surge_safe_name(raw_name, used_names)
            group_name_map[raw_name] = safe_group_name
            raw_groups.append(group)

    if not group_name_map:
        group_name_map["PROXY"] = _surge_safe_name("PROXY", used_names)
        raw_groups = [{"name": "PROXY", "type": "select", "proxies": proxy_names + ["DIRECT"]}]

    default_policy = group_name_map.get("PROXY") or next(iter(group_name_map.values()))

    for group in raw_groups:
        raw_name = str(group.get("name", "")).strip()
        if not raw_name or raw_name not in group_name_map:
            continue
        safe_group_name = group_name_map[raw_name]
        group_type = str(group.get("type", "select")).strip().lower()
        if group_type != "select":
            warnings.append(f"{raw_name}: surge proxy-group type '{group_type}' downgraded to select")
        raw_members = group.get("proxies")
        members: list[str] = []
        if isinstance(raw_members, list):
            for member in raw_members:
                resolved = _surge_resolve_policy_target(
                    str(member),
                    proxy_name_map=proxy_name_map,
                    group_name_map=group_name_map,
                    default_policy=default_policy,
                )
                if resolved and resolved not in members:
                    members.append(resolved)
        if not members:
            for member in proxy_names + ["DIRECT"]:
                if member not in members:
                    members.append(member)
        group_lines.append(f"{safe_group_name} = select, {', '.join(members)}")

    if not group_lines:
        fallback_members = list(dict.fromkeys(proxy_names + ["DIRECT"]))
        group_lines.append(f"{default_policy} = select, {', '.join(fallback_members)}")

    rule_lines: list[str] = []
    if parsed_acl.rules:
        for rule in parsed_acl.rules:
            converted, warning = _surge_convert_rule(
                rule,
                providers=parsed_acl.rule_providers,
                proxy_name_map=proxy_name_map,
                group_name_map=group_name_map,
                default_policy=default_policy,
            )
            if warning:
                warnings.append(warning)
            if converted:
                rule_lines.append(converted)
    if not rule_lines:
        rule_lines = [f"FINAL,{default_policy}"]
    elif not any(line.upper().startswith("FINAL,") for line in rule_lines):
        rule_lines.append(f"FINAL,{default_policy}")

    sections = [
        "[Proxy]",
        *proxy_lines,
        "",
        "[Proxy Group]",
        *group_lines,
        "",
        "[Rule]",
        *rule_lines,
        "",
    ]
    return "\n".join(sections), warnings


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
    if target == "surge":
        output, warnings = render_surge(nodes, acl_text=acl_text)
        return output, warnings, "text/plain; charset=utf-8"
    if target == "uri":
        warnings: list[str] = []
        if acl_text and acl_text.strip():
            warnings.append("ACL rules are ignored for URI output.")
        return render_uri_bundle(nodes, as_base64=uri_as_base64), warnings, "text/plain; charset=utf-8"
    raise ValueError(f"unsupported target: {target}")
