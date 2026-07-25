# Changelog

版本号对应脚本头部的 `@version`。

---

## v14.44 (2026-07-25)

**Google OAuth 旁路再收窄 + 文档取舍**
- 严管去掉 `www.googleapis.com` / `apis.google.com`；保留 accounts / consent / oauth2 / gstatic / googleusercontent。
- README 写明进程兜底与 AI 浏览器整进程进防封的取舍。

- `@version` 14.43 → 14.44。

## v14.43 (2026-07-25)

**严管 CDN 收窄**
- 去掉 `CDN.cloud` 整后缀（amazonaws / cloudfront / azureedge / cdn.cloudflare 等）进防封。
- OpenAI 确用静态/挑战域仍在 AI 桶；通用云流量落到 GFW/MATCH。

- `@version` 14.42 → 14.43。

## v14.42 (2026-07-25)

**命名与总闸优选**
- 总闸优选：🇺🇸美国 → 🏠家宽 → 🇸🇬新加坡 → 🇯🇵日本 → 🇰🇷韩国 → 🌸台湾 → 🇭🇰香港
- 家宽组：`az.其他测速.🏠 家宽`；台湾分区：`az.分区测速.🌸 台湾节点组`
- 去掉代码中的 🇹🇼

- `@version` 14.41 → 14.42。
