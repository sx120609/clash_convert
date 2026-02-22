from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.acl_presets import ACL_PRESETS, ACL_PRESET_MAP
from app.converters import SUPPORTED_TARGETS, convert_nodes
from app.models import ProxyNode
from app.share_links import LinkStore
from app.subscription import fetch_subscription, parse_subscription

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
LINK_STORE = LinkStore(default_ttl_sec=6 * 3600, max_items=4000)

app = FastAPI(
    title="Subscription Converter",
    version="0.1.0",
    description="Convert subscription links between Mihomo/Clash, sing-box and URI bundle outputs.",
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class ConvertRequest(BaseModel):
    source: str = Field(..., min_length=1)
    source_type: Literal["text", "url"] = "text"
    target: Literal["mihomo", "sing-box", "uri"] = "mihomo"
    uri_as_base64: bool = False
    acl_preset: str | None = None
    acl_text: str | None = None
    acl_url: str | None = None


class ConvertResponse(BaseModel):
    target: str
    node_count: int
    warnings: list[str]
    result_url: str
    expires_at: int


def _split_source_urls(raw: str) -> list[str]:
    lines = re.split(r"[\n|]+", raw.replace("\r", "\n"))
    urls: list[str] = []
    seen: set[str] = set()
    for part in lines:
        item = part.strip()
        if not item:
            continue
        if item not in seen:
            seen.add(item)
            urls.append(item)
    return urls


async def _load_source_urls(raw: str) -> tuple[list[str], list[str], list[str]]:
    urls = _split_source_urls(raw)
    if not urls:
        raise HTTPException(status_code=400, detail="source URL is empty")
    if len(urls) > 50:
        raise HTTPException(status_code=400, detail="too many source URLs, max is 50")

    results = await asyncio.gather(*(fetch_subscription(url) for url in urls), return_exceptions=True)
    payloads: list[str] = []
    warnings: list[str] = []
    ok_urls: list[str] = []

    for url, result in zip(urls, results):
        if isinstance(result, Exception):
            warnings.append(f"failed to fetch {url}: {result}")
            continue
        payloads.append(result)
        ok_urls.append(url)

    if not payloads:
        head = warnings[:5]
        suffix = [f"... and {len(warnings) - 5} more fetch errors"] if len(warnings) > 5 else []
        raise HTTPException(status_code=400, detail={"warnings": head + suffix})

    if len(warnings) > 10:
        warnings = warnings[:10] + [f"... and {len(warnings) - 10} more fetch errors"]
    return payloads, warnings, ok_urls


async def _load_source(req: ConvertRequest) -> tuple[list[str], list[str], str | None]:
    source = req.source.strip()
    if req.source_type == "text":
        return [source], [], None
    payloads, warnings, urls = await _load_source_urls(source)
    return payloads, warnings, "|".join(urls)


async def _load_acl_text(req: ConvertRequest) -> str:
    if req.acl_preset and req.acl_preset.strip():
        preset = ACL_PRESET_MAP.get(req.acl_preset.strip())
        if not preset:
            raise HTTPException(status_code=400, detail=f"unsupported acl preset: {req.acl_preset}")
        try:
            return (await fetch_subscription(preset.url)).strip()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"failed to fetch acl preset: {exc}") from exc
    if req.acl_text and req.acl_text.strip():
        return req.acl_text.strip()
    if req.acl_url and req.acl_url.strip():
        try:
            return (await fetch_subscription(req.acl_url.strip())).strip()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"failed to fetch acl URL: {exc}") from exc
    return ""


def _build_link_url(request: Request, token: str) -> str:
    path = str(request.app.url_path_for("resolve_link", token=token))

    origin = request.headers.get("origin", "").strip()
    if origin:
        parsed = urlparse(origin)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}{path}"

    referer = request.headers.get("referer", "").strip()
    if referer:
        parsed = urlparse(referer)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}{path}"

    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    forwarded_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
    host = forwarded_host or request.headers.get("host", "").split(",")[0].strip()

    if forwarded_proto and host:
        return f"{forwarded_proto}://{host}{path}"

    if host:
        host_without_port = host.split(":", 1)[0].strip().lower()
        local_hosts = {"127.0.0.1", "localhost", "::1", "testserver"}
        scheme = "http" if host_without_port in local_hosts else "https"
        return f"{scheme}://{host}{path}"

    return str(request.url_for("resolve_link", token=token))


def _ensure_unique_names(nodes: list[ProxyNode]) -> None:
    seen: dict[str, int] = {}
    for node in nodes:
        base_name = node.name.strip() or f"{node.type}-{node.server}:{node.port}"
        index = seen.get(base_name, 0)
        seen[base_name] = index + 1
        node.name = base_name if index == 0 else f"{base_name}-{index + 1}"


def _parse_payloads(payloads: list[str]) -> tuple[list[ProxyNode], list[str]]:
    nodes: list[ProxyNode] = []
    warnings: list[str] = []
    for index, payload in enumerate(payloads, start=1):
        parsed = parse_subscription(payload)
        nodes.extend(parsed.nodes)
        warnings.extend([f"source#{index}: {item}" for item in parsed.warnings])
    _ensure_unique_names(nodes)
    return nodes, warnings


def _convert_payloads(
    payloads: list[str],
    *,
    target: str,
    uri_as_base64: bool,
    acl_text: str,
) -> tuple[str, list[str], str, int]:
    nodes, parse_warnings = _parse_payloads(payloads)
    if not nodes:
        all_warnings = parse_warnings or ["no valid nodes found in source payload"]
        raise HTTPException(status_code=400, detail={"warnings": all_warnings})
    try:
        output, target_warnings, mime = convert_nodes(
            nodes,
            target,
            uri_as_base64=uri_as_base64,
            acl_text=acl_text,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    warnings = parse_warnings + target_warnings
    return output, warnings, mime, len(nodes)


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/supported")
async def supported() -> dict[str, object]:
    return {
        "targets": sorted(SUPPORTED_TARGETS),
        "protocols": ["ss", "ssr", "vmess", "vless", "trojan", "hysteria2", "tuic", "socks5", "http"],
        "note": "Some targets may support only a subset of protocols.",
        "acl": {
            "format": "clash rule lines or ACL4SSR custom syntax",
            "available_in_targets": ["mihomo"],
            "preset_count": len(ACL_PRESETS),
        },
    }


@app.get("/api/acl-presets")
async def acl_presets() -> dict[str, object]:
    return {
        "source": "ACL4SSR-sub style presets",
        "items": [{"id": item.id, "label": item.label, "url": item.url} for item in ACL_PRESETS],
    }


@app.post("/api/convert", response_model=ConvertResponse)
async def convert(req: ConvertRequest, request: Request) -> ConvertResponse:
    source_payloads, source_warnings, source_spec = await _load_source(req)
    acl_text = await _load_acl_text(req)
    output, warnings, mime, node_count = _convert_payloads(
        source_payloads,
        target=req.target,
        uri_as_base64=req.uri_as_base64,
        acl_text=acl_text,
    )
    warnings = source_warnings + warnings
    if req.source_type == "url":
        token, record = LINK_STORE.create_dynamic(
            source_url=source_spec or req.source.strip(),
            target=req.target,
            uri_as_base64=req.uri_as_base64,
            acl_text=acl_text,
        )
    else:
        token, record = LINK_STORE.create_static(
            content=output,
            mime=mime,
            target=req.target,
            uri_as_base64=req.uri_as_base64,
            acl_text=acl_text,
        )

    return ConvertResponse(
        target=req.target,
        node_count=node_count,
        warnings=warnings,
        result_url=_build_link_url(request, token),
        expires_at=int(record.expires_at),
    )


@app.get("/r/{token}", name="resolve_link")
async def resolve_link(token: str) -> PlainTextResponse:
    record = LINK_STORE.get(token)
    if not record:
        raise HTTPException(status_code=404, detail="link not found or expired")

    if record.kind == "static":
        assert record.content is not None
        assert record.mime is not None
        return PlainTextResponse(content=record.content, media_type=record.mime)

    if not record.source_url:
        raise HTTPException(status_code=500, detail="invalid link record")
    try:
        source_payloads, _, _ = await _load_source_urls(record.source_url)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"failed to fetch source URL: {exc}") from exc

    try:
        output, _, mime, _ = _convert_payloads(
            source_payloads,
            target=record.target,
            uri_as_base64=record.uri_as_base64,
            acl_text=record.acl_text,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"failed to render output: {exc}") from exc
    return PlainTextResponse(content=output, media_type=mime)


@app.get("/sub")
async def convert_subscription(
    url: str = Query(..., min_length=4, description="subscription URL"),
    target: str = Query("mihomo", description="target format"),
    uri_as_base64: bool = Query(False, description="for target=uri"),
    acl_preset: str = Query("", description="acl preset id"),
    acl: str = Query("", description="acl text"),
    acl_url: str = Query("", description="acl URL"),
) -> PlainTextResponse:
    if target not in SUPPORTED_TARGETS:
        raise HTTPException(status_code=400, detail=f"unsupported target: {target}")

    try:
        source_payloads, _, _ = await _load_source_urls(url)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"failed to fetch source URL: {exc}") from exc

    acl_text = acl.strip()
    if not acl_text and acl_preset.strip():
        preset = ACL_PRESET_MAP.get(acl_preset.strip())
        if not preset:
            raise HTTPException(status_code=400, detail=f"unsupported acl preset: {acl_preset}")
        try:
            acl_text = (await fetch_subscription(preset.url)).strip()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"failed to fetch acl preset: {exc}") from exc

    if not acl_text and acl_url.strip():
        try:
            acl_text = (await fetch_subscription(acl_url.strip())).strip()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"failed to fetch acl URL: {exc}") from exc

    output, _, mime, _ = _convert_payloads(
        source_payloads,
        target=target,
        uri_as_base64=uri_as_base64,
        acl_text=acl_text,
    )
    return PlainTextResponse(content=output, media_type=mime)
