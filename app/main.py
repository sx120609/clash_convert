from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.acl_presets import ACL_PRESETS, ACL_PRESET_MAP
from app.converters import SUPPORTED_TARGETS, convert_nodes
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


async def _load_source(req: ConvertRequest) -> str:
    source = req.source.strip()
    if req.source_type == "text":
        return source
    try:
        return await fetch_subscription(source)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"failed to fetch source URL: {exc}") from exc


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
    return str(request.url_for("resolve_link", token=token))


def _convert_payload(
    payload: str,
    *,
    target: str,
    uri_as_base64: bool,
    acl_text: str,
) -> tuple[str, list[str], str, int]:
    parsed = parse_subscription(payload)
    if not parsed.nodes:
        all_warnings = parsed.warnings or ["no valid nodes found in source payload"]
        raise HTTPException(status_code=400, detail={"warnings": all_warnings})
    try:
        output, target_warnings, mime = convert_nodes(
            parsed.nodes,
            target,
            uri_as_base64=uri_as_base64,
            acl_text=acl_text,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    warnings = parsed.warnings + target_warnings
    return output, warnings, mime, len(parsed.nodes)


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
    source_payload = await _load_source(req)
    acl_text = await _load_acl_text(req)
    output, warnings, mime, node_count = _convert_payload(
        source_payload,
        target=req.target,
        uri_as_base64=req.uri_as_base64,
        acl_text=acl_text,
    )
    if req.source_type == "url":
        token, record = LINK_STORE.create_dynamic(
            source_url=req.source.strip(),
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
        source_payload = await fetch_subscription(record.source_url)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"failed to fetch source URL: {exc}") from exc

    try:
        output, _, mime, _ = _convert_payload(
            source_payload,
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
        source_payload = await fetch_subscription(url)
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

    output, _, mime, _ = _convert_payload(
        source_payload,
        target=target,
        uri_as_base64=uri_as_base64,
        acl_text=acl_text,
    )
    return PlainTextResponse(content=output, media_type=mime)
