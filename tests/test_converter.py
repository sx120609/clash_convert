from __future__ import annotations

import base64
import json

import yaml

from app.converters import convert_nodes
from app.subscription import parse_subscription


def _make_vmess_uri() -> str:
    payload = {
        "v": "2",
        "ps": "vmess-node",
        "add": "vm.example.com",
        "port": "443",
        "id": "11111111-1111-1111-1111-111111111111",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "host": "cdn.example.com",
        "path": "/ws",
        "tls": "tls",
        "sni": "vm.example.com",
    }
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    return f"vmess://{encoded}"


def _make_ss_uri() -> str:
    user = base64.urlsafe_b64encode(b"aes-128-gcm:secret").decode("utf-8").rstrip("=")
    return f"ss://{user}@ss.example.com:8388#ss-node"


def _make_ssr_uri() -> str:
    pwd = base64.urlsafe_b64encode(b"secret").decode("utf-8").rstrip("=")
    remarks = base64.urlsafe_b64encode("ssr-node".encode("utf-8")).decode("utf-8").rstrip("=")
    body = f"ssr.example.com:1443:auth_sha1_v4:aes-128-cfb:tls1.2_ticket_auth:{pwd}/?remarks={remarks}"
    encoded = base64.urlsafe_b64encode(body.encode("utf-8")).decode("utf-8").rstrip("=")
    return f"ssr://{encoded}"


def test_parse_mixed_subscription() -> None:
    text = "\n".join(
        [
            _make_ss_uri(),
            _make_vmess_uri(),
            "vless://22222222-2222-2222-2222-222222222222@vl.example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fvless&sni=vl.example.com#vless-node",
            "trojan://p@tr.example.com:443?type=grpc&serviceName=grpc-service&sni=tr.example.com#trojan-node",
            "hysteria2://hy-pass@hy.example.com:8443?sni=hy.example.com&obfs=salamander&obfs-password=obfs123#hy2-node",
            "tuic://33333333-3333-3333-3333-333333333333:pass@tuic.example.com:443?sni=tuic.example.com#tuic-node",
            "socks5://user:pwd@socks.example.com:1080#socks-node",
            "https://u:p@proxy.example.com:8443#http-node",
        ]
    )
    result = parse_subscription(text)
    assert len(result.nodes) == 8
    assert result.warnings == []
    assert {node.type for node in result.nodes} == {
        "ss",
        "vmess",
        "vless",
        "trojan",
        "hysteria2",
        "tuic",
        "socks5",
        "http",
    }


def test_parse_base64_subscription_payload() -> None:
    raw = "\n".join([_make_ss_uri(), _make_vmess_uri()])
    encoded = base64.b64encode(raw.encode("utf-8")).decode("utf-8")
    result = parse_subscription(encoded)
    assert len(result.nodes) == 2
    assert not result.warnings


def test_render_mihomo_yaml() -> None:
    text = "\n".join([_make_ss_uri(), _make_vmess_uri()])
    parsed = parse_subscription(text)
    output, warnings, mime = convert_nodes(parsed.nodes, "mihomo")
    assert warnings == []
    assert mime.startswith("text/yaml")
    doc = yaml.safe_load(output)
    assert "proxies" in doc
    assert len(doc["proxies"]) == 2
    assert doc["proxy-groups"][0]["name"] == "PROXY"


def test_render_sing_box_json_with_ssr_warning() -> None:
    text = "\n".join([_make_ss_uri(), _make_ssr_uri()])
    parsed = parse_subscription(text)
    output, warnings, mime = convert_nodes(parsed.nodes, "sing-box")
    assert mime.startswith("application/json")
    parsed_json = json.loads(output)
    assert "outbounds" in parsed_json
    assert any("ssr" in warning for warning in warnings)


def test_render_uri_base64() -> None:
    text = "\n".join([_make_ss_uri(), _make_vmess_uri()])
    parsed = parse_subscription(text)
    output, warnings, _ = convert_nodes(parsed.nodes, "uri", uri_as_base64=True)
    assert warnings == []
    decoded = base64.b64decode(output).decode("utf-8")
    assert "ss://" in decoded
    assert "vmess://" in decoded


def test_parse_clash_yaml_proxies() -> None:
    yaml_text = """
mixed-port: 7890
proxies:
  - name: ss-node
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-128-gcm
    password: pass
  - name: vmess-node
    type: vmess
    server: vm.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /ws
"""
    result = parse_subscription(yaml_text)
    assert len(result.nodes) == 2
    assert {node.type for node in result.nodes} == {"ss", "vmess"}


def test_proxy_providers_only_gives_single_warning() -> None:
    yaml_text = """
proxy-providers:
  p1:
    type: http
    url: http://example.com/sub
"""
    result = parse_subscription(yaml_text)
    assert len(result.nodes) == 0
    assert len(result.warnings) == 1
    assert "proxy-providers only" in result.warnings[0]
