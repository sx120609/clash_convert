from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from app.main import app


def _make_ss_uri() -> str:
    user = base64.urlsafe_b64encode(b"aes-128-gcm:secret").decode("utf-8").rstrip("=")
    return f"ss://{user}@ss.example.com:8388#ss-node"


def test_convert_returns_share_link_for_text_source() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/convert",
        json={
            "source": _make_ss_uri(),
            "source_type": "text",
            "target": "mihomo",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["result_url"].startswith("http://testserver/r/")

    result_response = client.get(payload["result_url"])
    assert result_response.status_code == 200
    assert "proxies:" in result_response.text


def test_convert_returns_dynamic_link_for_url_source(monkeypatch) -> None:
    async def fake_fetch_subscription(url: str, timeout_sec: float = 15.0) -> str:  # noqa: ARG001
        if "ACL4SSR_Online.ini" in url:
            return "MATCH,PROXY"
        return _make_ss_uri()

    monkeypatch.setattr("app.main.fetch_subscription", fake_fetch_subscription)
    client = TestClient(app)
    response = client.post(
        "/api/convert",
        json={
            "source": "https://example.com/sub",
            "source_type": "url",
            "target": "mihomo",
            "acl_text": "MATCH,PROXY",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["result_url"].startswith("http://testserver/r/")

    result_response = client.get(payload["result_url"])
    assert result_response.status_code == 200
    assert "MATCH,PROXY" in result_response.text


def test_acl_presets_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/api/acl-presets")
    assert response.status_code == 200
    payload = response.json()
    assert "items" in payload
    assert len(payload["items"]) > 0
    assert payload["items"][0]["id"]


def test_convert_supports_acl_preset(monkeypatch) -> None:
    async def fake_fetch_subscription(url: str, timeout_sec: float = 15.0) -> str:  # noqa: ARG001
        if "ACL4SSR_Online.ini" in url:
            return "MATCH,PROXY"
        return _make_ss_uri()

    monkeypatch.setattr("app.main.fetch_subscription", fake_fetch_subscription)
    client = TestClient(app)
    response = client.post(
        "/api/convert",
        json={
            "source": _make_ss_uri(),
            "source_type": "text",
            "target": "mihomo",
            "acl_preset": "acl4ssr_online_default",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    resolved = client.get(payload["result_url"])
    assert resolved.status_code == 200
    assert "MATCH,PROXY" in resolved.text
