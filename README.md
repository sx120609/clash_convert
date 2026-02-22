# Subscription Converter (Mihomo / Sing-box)

一个可直接运行的订阅转换 Web 应用，支持主流代理协议解析并转换到不同客户端格式。

## 支持范围

- 输入协议: `ss` `ssr` `vmess` `vless` `trojan` `hysteria2/hy2` `tuic` `socks5` `http(s)`
- 输入形态:
  - URL 订阅内容
  - 纯文本 URI 列表
  - 整段 Base64 订阅文本
- 输出目标:
  - `mihomo` (`Clash` 系 YAML)
  - `sing-box` (JSON)
  - `uri` (URI 列表，可选 Base64)

## 快速启动

```powershell
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
pip install -e .[dev]
uvicorn app.main:app --reload --port 8000
```

打开 `http://127.0.0.1:8000/`。

## API

- `POST /api/convert`
  - `source`: 订阅 URL 或文本
  - `source_type`: `url` 或 `text`
  - `target`: `mihomo` / `sing-box` / `uri`
  - `uri_as_base64`: 仅对 `uri` 生效
- `GET /sub?url=...&target=mihomo`
  - 方便作为“转换后订阅链接”直接给客户端订阅

## 测试

```powershell
pytest
```
