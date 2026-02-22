# Subscription Converter (Mihomo / Sing-box / Surge)

一个可直接运行的订阅转换 Web 应用，支持主流代理协议解析并转换到不同客户端格式。

## 支持范围

- 输入协议: `ss` `ssr` `vmess` `vless` `trojan` `hysteria2/hy2` `tuic` `socks5` `http(s)`
- 输入形态:
  - URL 订阅内容（支持多个 URL，换行或 `|` 分隔）
  - 纯文本 URI 列表
  - 整段 Base64 订阅文本
- 输出目标:
  - `mihomo` (`Clash` 系 YAML)
  - `sing-box` (JSON)
  - `surge` (Surge `.conf`)
  - `uri` (URI 列表，可选 Base64)
- ACL:
  - 支持直接选择 ACL 预设（ACL4SSR-sub 风格）
  - 内置 `MESL规则` 预设（从指定 Clash 配置提取规则/分组）
  - 支持 Clash 规则行（如 `DOMAIN-SUFFIX,google.com,PROXY`）
  - 支持 ACL4SSR 常见 `custom_proxy_group=` / `ruleset=` 语法（用于 Mihomo/Surge 输出）

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
  - `target`: `mihomo` / `sing-box` / `surge` / `uri`
  - `uri_as_base64`: 仅对 `uri` 生效
  - `source_type=url` 时，`source` 支持多个 URL（换行或 `|` 分隔）
  - `acl_preset`: ACL 预设 ID（可用值见 `GET /api/acl-presets`）
  - `acl_text` / `acl_url`: ACL 规则（对 `mihomo` / `surge` 生效）
  - 返回 `result_url`：可直接打开获取转换结果内容
  - 返回的链接默认有效期约 6 小时
- `GET /api/acl-presets`
  - 获取 ACL 预设列表（用于前端下拉框）
- `GET /r/{token}`
  - 打开后直接返回转换后的订阅内容
- `GET /sub?url=...&target=mihomo`
  - 方便作为“转换后订阅链接”直接给客户端订阅
  - `url` 支持多个 URL（换行或 `|` 分隔）
  - 支持 `acl_preset`、`acl`、`acl_url` 参数

## 测试

```powershell
pytest
```
