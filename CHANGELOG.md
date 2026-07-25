# Changelog

版本号对应脚本头部的 `@version`。

---

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
