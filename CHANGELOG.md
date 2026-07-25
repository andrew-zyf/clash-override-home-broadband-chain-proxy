# Changelog

版本号对应脚本头部的 `@version`。

---

## v14.33 (2026-07-25)

**家宽出口统一 SOCKS5 与命名**
- 官方中转与静态IP 均注入为 SOCKS5（共用 `buildResidentialSocksProxy`）。
- 节点名统一为 `家宽出口（官方中转）` / `家宽出口（静态IP）`；升级时清理旧名 `家宽出口（家庭静态 IP）`。

- `@version` 14.32 → 14.33。

## v14.32 (2026-07-25)

**家宽凭证共用认证**
- `RESIDENTIAL_CREDENTIALS` 改为顶层 `username`/`password`，`transit` / `homeStatic` 只保留 `server`/`port`。
- 官方中转必填共用认证；家庭 SOCKS5 认证可选（无用户名密码亦可注入）。
- README / 测试同步新结构。

- `@version` 14.31 → 14.32。

## v14.30 (2026-07-25)

**AI 浏览器清单**
- 仅管控 Comet / Dia / Atlas 三个 AI 浏览器进程。

- `@version` 14.29 → 14.30。

## v14.29 (2026-07-25)

**Gemini + Antigravity 合并管控**
- 域名合并为 `gemini_antigravity`（Gemini Web/API + Antigravity / IDE 后端）。
- 进程补齐：Gemini App/Helper、`gemini.exe`、`antigravity.exe`；与 Antigravity App/IDE/`agy` CLI 同一防封策略。

- `@version` 14.28 → 14.29。

## v14.28 (2026-07-25)

**不再管控 Cursor**
- 去掉 Cursor 桌面进程与 Helper；域名此前已不进严管，整体落到 GFW/MATCH。

- `@version` 14.27 → 14.28。

## v14.27 (2026-07-25)

**严管清单再收窄**
- AI 域名：去掉 OpenRouter / Mistral / HF / Cursor；保留并强调 Meta AI（`meta.ai`）；去掉 `crixet`、DeepMind/Labs 边缘域。
- 进程：去掉 SunBrowser；Cursor 桌面仍进程进防封（无域名清单）。
- 其他调度：去掉 `yt.be`、`nflximg.com` 冗余后缀。

- `@version` 14.26 → 14.27。

## v14.26 (2026-07-25)

**测试套件重设计**
- `tests/test.js` 重构为 16 单元 + 30 集成；按防封/解锁调度、清单收窄与凭证降级分组。
- 失败时打印用例名与堆栈；数量用断言锁死。

**严管 / 其他调度清单收窄**
- 严管 AI：去掉图像/语音/低敏创作与编码站（Midjourney、Cohere、Windsurf 等），保留核心账号服务。
- 支撑：去掉 GitLab/Atlassian、crates/RubyGems/Docker、整树部署平台；CDN 去掉 Akamai/Fastly。
- 进程：去掉 Quotio；桌面/CLI 与核心 AI 对齐。
- 其他调度：去掉 SoundCloud、LinkedIn、Slack、Signal 及 Telegram 附属域。

- `@version` 14.25 → 14.26。

## v14.25 (2026-07-25)

**防封调度策略**
- 组名：`🎯 统一出口` → 严管 `🏠 防封出口` / 其他 `🌏 解锁出口`。
- 有家宽时，防封出口**只挂**家宽实体 + 家宽组，不再挂地区测速，避免 UI 误切机房。
- 无家宽降级时，防封出口只挂家宽组（组内为地区/DIRECT）。
- 防封 / 解锁总闸写入订阅默认代理组，便于直达切换。

- `@version` 14.24 → 14.25。

## v14.24 (2026-07-25)

**聚焦防封号：严管默认家宽**
- `严管.🎯 统一出口` 候选序改回：家宽实体 → 家宽组 → 🇺🇸 → 🇯🇵 → 🇸🇬 → 🇭🇰。
- `其他.🎯 统一出口` 仍美区优先，媒体解锁与 AI 防封解耦。

- `@version` 14.23 → 14.24。

## v14.23 (2026-07-25)

**调度网址去冗余 / 提速**
- AI：去掉被 `CDN.cloud` / Statsig 父域遮蔽的 OpenAI 单租户主机与 Sentry 项目域；去掉 `clau.de` / MakerSuite / 共享 `host.livekit.cloud`。
- CDN：去掉 jsDelivr / Bunny / Cloudinary 等过宽 SaaS CDN。
- 支撑 / 集成：去掉 `docker.com`、JetBrains、Intercom、PostHog。
- 其他调度：去掉 Hulu / Peacock / Paramount / Bandcamp / Medium 等长尾显式规则（落到 GFW/MATCH）。

- `@version` 14.22 → 14.23。

## v14.22 (2026-07-25)

**统一出口默认美区**
- 严管 / 其他两套 `🎯 统一出口` 候选序统一为：🇺🇸 → 🇯🇵 → 🇸🇬 → 🇭🇰 → 家宽。
- 防封号需在严管统一出口手动切到家宽节点或家宽组。

- `@version` 14.21 → 14.22。
