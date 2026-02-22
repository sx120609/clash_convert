from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.converters import SUPPORTED_TARGETS, convert_nodes
from app.subscription import fetch_subscription, parse_subscription

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

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


class ConvertResponse(BaseModel):
    target: str
    node_count: int
    warnings: list[str]
    output: str


async def _load_source(req: ConvertRequest) -> str:
    source = req.source.strip()
    if req.source_type == "text":
        return source
    try:
        return await fetch_subscription(source)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"failed to fetch source URL: {exc}") from exc


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
    }


@app.post("/api/convert", response_model=ConvertResponse)
async def convert(req: ConvertRequest) -> ConvertResponse:
    source_payload = await _load_source(req)
    parsed = parse_subscription(source_payload)
    if not parsed.nodes:
        all_warnings = parsed.warnings or ["no valid nodes found in source payload"]
        raise HTTPException(status_code=400, detail={"warnings": all_warnings})
    try:
        output, target_warnings, _ = convert_nodes(
            parsed.nodes,
            req.target,
            uri_as_base64=req.uri_as_base64,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return ConvertResponse(
        target=req.target,
        node_count=len(parsed.nodes),
        warnings=parsed.warnings + target_warnings,
        output=output,
    )


@app.get("/sub")
async def convert_subscription(
    url: str = Query(..., min_length=4, description="subscription URL"),
    target: str = Query("mihomo", description="target format"),
    uri_as_base64: bool = Query(False, description="for target=uri"),
) -> PlainTextResponse:
    if target not in SUPPORTED_TARGETS:
        raise HTTPException(status_code=400, detail=f"unsupported target: {target}")

    try:
        source_payload = await fetch_subscription(url)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"failed to fetch source URL: {exc}") from exc

    parsed = parse_subscription(source_payload)
    if not parsed.nodes:
        warnings = "; ".join(parsed.warnings) if parsed.warnings else "no valid nodes found"
        raise HTTPException(status_code=400, detail=warnings)

    output, _, mime = convert_nodes(parsed.nodes, target, uri_as_base64=uri_as_base64)
    return PlainTextResponse(content=output, media_type=mime)
