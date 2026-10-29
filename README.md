# mailwatch-ews

一个实时 EWS 邮箱采集、归档与轻量网页工作台。

专为那些服务器上 **IMAP / POP3 / SMTP 被封禁**、但 **EWS（Exchange Web Services）over HTTPS** 依然开放的企业邮箱设计——Exchange 2013/2016/2019 常见的封锁策略。本服务通过 EWS 连接邮箱，保持 *streaming subscription*（流式订阅）以获得推送级别的实时更新，并叠加周期性增量兜底同步，把看到的每一封邮件都存下来，同时提供一个精简的 HTTP API 和单页 Web 工作台（登录、搜索、阅读、附件下载、撰写/回复）。

> 这是通用化后的开源打包版本。内部运营面板、值班看板、面板同步等 **不属于本仓库的内容**——这里只有邮箱服务本体（采集 / 存储 / 查看 / 发送）。

## 功能特性

- **EWS 实时采集** — 流式订阅推送通知，自动重订阅，20 分钟流周期
- **增量兜底同步** — 每 5 分钟（可配置）基于 sync state 增量拉取，扛短时故障
- **首启回填** — 第一次运行即把收件箱已有内容全部入库
- **内容寻址归档** — 原始 MIME 存为 `.eml.gz`，全部附件按 SHA-256 存储，跨邮件去重
- **PostgreSQL 存储** — 元数据、正文全文、同步状态与日志，`pg_trgm` 模糊搜索（主题/正文/发件人）
- **存储配额** — 超限自动从最旧开始清理（默认 100 GiB 逻辑配额，清理至 95 GiB），孤儿文件清扫、去重 blob 引用计数删除
- **Web UI** — 单文件 `index.html`，零 CDN / 零外部资源：登录、摘要栏、分页邮件列表与搜索、HTML 正文沙箱 iframe 渲染、附件下载、内联图片预览、撰写 / 回复 / 试运行发送
- **Web 设置向导** — 部署完成后在「设置」里登录自己的企业邮箱（服务器/NTLM 用户名/密码/邮箱地址），保存即生效，采集线程无停机热切换；换邮箱自动对新邮箱整箱回填
- **界面可选存档容量** — 设置页一键选择存档上限（5/10/50/100/200/500 GiB 或自定义，如 `30G`），实时显示当前用量进度条，超限自动从最旧开始清理
- **API 鉴权** — token 或用户名/密码两种方式（`X-Panel-Token` 请求头）；整个界面为中文单文件，无任何外部资源

## 协议要求

整套设计针对经典的"企业邮件封锁"场景：

| 协议 | 端口 | 目标环境状态 |
|---|---|---|
| OWA / EWS / ActiveSync / Autodiscover | 443 | **可用 — 唯一取数通道** |
| IMAP / POP3 / SMTP submission | 143/993/110/995/465/587 | 通常被上游封禁 |
| SMTP 入站（MX） | 25 | 开放（收信路径） |
| SMTP AUTH 发信 | 25 | 常被邮件网关拒绝 |

如果你的邮箱提供干净的 IMAP，大概率不需要本服务；如果没有，这就是你的阅读工具。

## 架构

```text
┌──────────────── mailwatch-ews（单 Python 进程）────────────────┐
│  exchangelib ─► EWS :443 (NTLM)                                │
│   ├── streaming subscription        （推送写入 event_log）      │
│   └── 每 N 秒增量同步               （兜底 + 回填）             │
│  存储                                                           │
│   ├── PostgreSQL   messages / attachments / meta / ingest_log / │
│   │                event_log                                    │
│   └── ../data/archive                                           │
│        ├── mime/YYYY/MM/<sha256>.eml.gz                         │
│        └── attachments/<sha2>/<sha256>  （去重）                 │
│  HTTP API  :18661  JSON + 静态 index.html                       │
│  清理器     每 60 秒执行配额检查与最旧消息删除                   │
└─────────────────────────────────────────────────────────────────┘
```

## 快速开始（Docker Compose 一条命令）

```bash
git clone https://github.com/wwu-unique/mailwatch-ews.git
cd mailwatch-ews
cp .env.example .env
$EDITOR .env    # 至少填 UI 登录账号(db/UI 密码)；邮箱账号可以不填
docker compose up -d --build
```

然后打开 `http://localhost:18661/`（`MAIL_PORT`），用 `PANEL_USER` / `PANEL_PASSWORD` 登录。

**两种入门路径：**

- **网页配置（推荐，默认路径）**：`.env` 里只填 UI 密码与数据库密码，邮箱账号留空。首次打开界面会自动弹出「设置」，在界面里填写企业的 Exchange 服务器、NTLM 用户名、密码、邮箱地址，选一个存档容量上限，保存并生效——服务会先真实验证凭据、随后自动回填收件箱并实时采集，无需重启容器。
- **环境变量 / config.json（脚本化部署）**：像过去一样在 `.env` 中预置邮箱账号，服务启动后直接采集。

Compose 启动两个容器：

- `mail` — 本服务（暴露配置端口）
- `db` — PostgreSQL 18，自带数据卷

所有邮件元数据存在 `mailwatch` 数据库；原始 MIME 与附件在 `./data/archive`（宿主机 `./data` bind 挂载）。

## 配置说明

配置由一个可选 JSON 文件 + 环境变量覆盖组成（后者优先）：

```json5
// /app/config.json（用 MAILWATCH_CONFIG=/path/to/config.json 可换路径）
{
  "server":   "mail.example.com",     // EWS 主机，仅 https
  "username": "DOMAIN\\user",         // NTLM 登录
  "password": "…",
  "mailbox":  "user@example.com"      // 主 SMTP 地址
}
```

以上字段也都可以不写文件，直接用环境变量：

| 变量 | 含义 |
|---|---|
| `MAILWATCH_EWS_SERVER` | 提供 EWS 的 Exchange 主机 |
| `MAILWATCH_EWS_USERNAME` | NTLM 用户，`域名\用户` |
| `MAILWATCH_EWS_PASSWORD` | NTLM 密码 |
| `MAILWATCH_EWS_MAILBOX` | 主 SMTP 邮箱地址 |
| `MAILWATCH_EWS_BUILD` | 可选服务器版本号提示，如 `15.2.2562`（Exchange 2019） |
| `MAILWATCH_EWS_API_PORT` | HTTP API 端口，默认 `18661` |
| `MAILWATCH_EWS_API_HOST` | 监听地址，默认 `127.0.0.1`（Compose 设 `0.0.0.0`） |
| `MAILWATCH_EWS_DIR` | 工作目录，默认 `/app` |
| `MAILWATCH_CONFIG` | 配置 JSON 路径，默认 `/app/config.json` |
| `MAILWATCH_PG_DSN` | PostgreSQL 连接串（或代码同目录 `pg.env` 文件） |
| `MAILWATCH_EWS_SYNC_INTERVAL` | 兜底同步周期秒数，默认 `300` |
| `MAILWATCH_EWS_STREAM_TIMEOUT` | 流式订阅分钟数，默认 `20` |
| `MAILWATCH_EWS_BACKFILL` | 数字 `1` = 首次启动回填收件箱 |
| `MAILWATCH_EWS_LOG_LEVEL` | 日志级别，默认 `INFO` |
| `MAILWATCH_MIN_KEEP_MESSAGES` | 清理器必须保留的最少消息数，默认 `1` |
| `MAILWATCH_CLEANUP_BATCH` | 每批清理删除的最大行数 |
| `MAILWATCH_PANEL_USER` / `MAILWATCH_PANEL_PASSWORD` | Web UI / API 登录 |
| `MAILWATCH_PANEL_TOKEN` | 静态 token 鉴权（与账号二选一） |
| `MAILWATCH_PANEL_SESSION_TTL` | 会话有效期秒数，默认 12 小时 |
| `MAILWATCH_MAX_STORAGE_BYTES` | 逻辑内容配额，默认 `100G`（设置页保存后以设置页为准） |
| `/api/settings`（Web 设置，数据存在 PG meta 表） | 界面保存的账号与配额，优先级高于文件与环境变量；`GET /api/settings` 查看，`POST {action: test/save}` 修改 |
| `MAILWATCH_STORAGE_TARGET_BYTES` | 清理后的目标用量，默认 `95G` |
| `MAILWATCH_CLEANUP_INTERVAL` | 清理器周期秒数，默认 `60` |

### 首次启动

全新部署时流程如下：

1. 连接 EWS，把现有收件箱全部回填（约每封 1–2 秒，视附件而定）；
2. 执行 *同步状态锚定*（`prime_sync_state`），把文件夹重放一遍拿到 EWS 变更水位——大邮箱（数百封起）耗时与回填同一量级（数百次往返）；
3. 完成后才启动流式订阅、增量同步兜底与存储清理器（配额统计在此之前保持初始值）。

后续三阶段与参考生产部署共用同一套代码路径，没有任何针对特定环境的东西。

### 存储配额语义

用量（磁盘 + 数据库）达到 `MAILWATCH_MAX_STORAGE_BYTES` 后，清理器按批删除最旧的邮件，直到用量回落至 `MAILWATCH_STORAGE_TARGET_BYTES`，避免反复触发抖动。先删数据库行；内容寻址 blob 只有在不再被任何消息或附件引用时才删除（保留去重共享）。清理在启动时和每 `MAILWATCH_CLEANUP_INTERVAL` 秒各跑一次，结果通过 `/api/summary` 的 `storage_*` / `last_cleanup*` 字段暴露。

## HTTP API

除特别说明外，所有端点返回 JSON。配置鉴权后，请求必须带 `X-Panel-Token: <session-or-token>` 或 `?token=`。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | `{username, password}` → `{ok, token, expires_in}` |
| POST | `/api/logout` | 销毁当前会话 |
| GET | `/` `/health` `/api/health` | 摘要 + 同步/流式/存储状态 |
| GET | `/api/summary` | 邮件总数、未读数、最新一封、配额用量 |
| GET | `/api/mails?limit&offset&q` | 分页列表，`q` = 全文搜索 |
| GET | `/api/mail/<key>` | 完整邮件：头、正文、附件列表 |
| GET | `/api/att/<key>/<attid>` | 下载附件 |
| GET | `/api/img/<key>/<attid>` | 内联图片（Disposition 友好） |
| GET | `/api/mime/<key>` | 归档的原始 `.eml.gz` 内容 |
| GET | `/api/tags` | 已见的邮件分类去重列表 |
| GET | `/api/log?limit` | 采集日志尾部 |
| POST | `/api/mail/<key>/read` | `{read: true|false}` 单封标记已读/未读 |
| POST | `/api/mails/read` | 全部标记已读 |
| POST | `/api/send` | 新邮件 / 回复 / 全部回复，支持 `dry_run` 试运行 |
| GET | `/api/settings` | 当前邮箱配置、配额与用量（不含明文密码） |
| POST | `/api/settings` | `{action:"test"\|"save", server, username, password, mailbox, max_storage?}` 测试/保存账号与存档容量 |

## 安全说明

- Docker 镜像在容器内以 root 运行，因为归档路径与 DSN 文件依赖 `0600/0700` 文件位作为首要防线（上游托管部署保留了这个行为）。请把 `/app/data` 挂到宿主机权限收紧的路径上。
- Web UI 把 HTML 正文放进**沙箱 iframe**（`sandbox=""`）渲染，邮件正文里的脚本无法触达应用源。
- 任何对外可达的部署务必配置 `PANEL_USER`/`PANEL_PASSWORD`（或 `PANEL_TOKEN`）；两者都没配时 API 是开放的。
- 密钥只从环境变量、`pg.env`/`config.json` 文件或设置页读取，绝不写日志、不上 API 回显（`GET` 返回脱敏信息）、不进源码。
- 设置页保存的邮箱密码存放在本机 PostgreSQL 的 `meta` 表中；请以适用的精细权限保护数据库（Volume 归属宿主机本地盘）。

## 本地开发

```bash
python -m venv ./.venv && source ./.venv/bin/activate
pip install -r requirements.txt
# MAILWATCH_PG_DSN 指向本机 PostgreSQL
MAILWATCH_EWS_DIR=/app MAILWATCH_EWS_API_HOST=127.0.0.1 MAILWATCH_EWS_API_PORT=18661 \
  MAILWATCH_EWS_SERVER=… MAILWATCH_EWS_USERNAME=… MAILWATCH_EWS_PASSWORD=… \
  MAILWATCH_EWS_MAILBOX=… python ews_worker.py
```

## 许可证

MIT — 见 `LICENSE`。
