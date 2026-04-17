// Clash 家宽IP-链式代理覆写脚本
//
// 把 AI 整条链路（会话本体 + 登录反机器人 + 订阅支付 + 特性开关上报）锁进家宽 IP 链式出口；
// 流媒体 / 社交 / IM 走独立 mediaRegion；域内业务直连；其余按订阅默认。
// DNS / Sniffer / 分流规则三层共用一份 POLICY 分类，规则与解析永远同步。
//
// 数据流（自上而下）：
//
//   USER_OPTIONS     用户可调参数（地区 + 浏览器开关）
//   BASE             运行期常量（地区表、节点名、组名后缀、DoH、规则前缀）
//   SOURCE_*         按路由意图分桶的 `+.domain` 字面量
//                      SOURCE_CHAIN / SOURCE_MEDIA / SOURCE_GLOBAL_DEFAULT /
//                      SOURCE_CN_DIRECT / SOURCE_OVERSEAS_DIRECT /
//                      SOURCE_LOCAL_DIRECT / SOURCE_NETWORK_DIRECT
//   POLICY           单一权威表：每条 entry 写明
//                      route / dnsZone / sniffer / fakeIpBypass / fallbackFilter
//                    新增分类只改 POLICY 一处，下游全部自动同步。
//   DERIVED          从 POLICY 投影出的下游视图：patterns / processNames / networkRules
//   EXPECTED_ROUTES  端到端路由样本（toChain / toMedia），加载期 + 测试期共用
//   main(config)     装配顺序：容器 → DNS/Sniffer → MiyaIP 节点 →
//                    地区目标解析 → 规则注入 → 收尾校验
//
// 函数前缀约定：build*=纯产出  resolve*=读+幂等写  write*=改 config  assert*=运行期断言
//
// 依赖：先跑 `MiyaIP 凭证.js` 把凭证写到 `config._miya`，再跑本脚本。
// 兼容性：Clash Party 的 JavaScriptCore；只用 ES5 语法。
//
// @version 9.2

// ---------------------------------------------------------------------------
// 用户可调参数
// ---------------------------------------------------------------------------

var USER_OPTIONS = {
  chainRegion: "SG", // AI 家宽出口前一跳地区，可选 US / JP / HK / SG
  mediaRegion: "US", // 媒体默认地区，可选 US / JP / HK / SG
  routeBrowserToChain: true // 是否让 AI 向浏览器按应用名继续强制走 chainRegion
};

// ---------------------------------------------------------------------------
// 基础常量
// ---------------------------------------------------------------------------

// 所有运行期稳定常量的单一来源：地区、节点名、组名后缀、DoH 服务器、规则前缀。
var BASE = {
  regions: {
    US: { regex: /🇺🇸|美国|^US[|丨\- ]/i, label: "美国", flag: "🇺🇸" },
    JP: { regex: /🇯🇵|日本|^JP[|丨\- ]/i, label: "日本", flag: "🇯🇵" },
    HK: { regex: /🇭🇰|香港|^HK[|丨\- ]/i, label: "香港", flag: "🇭🇰" },
    SG: { regex: /🇸🇬|新加坡|^SG[|丨\- ]/i, label: "新加坡", flag: "🇸🇬" },
    TW: { regex: /🇹🇼|台湾|^TW[|丨\- ]/i, label: "台湾", flag: "🇹🇼" },
    KR: { regex: /🇰🇷|韩国|^KR[|丨\- ]/i, label: "韩国", flag: "🇰🇷" }
  },
  nodeNames: {
    relay: "自选节点 + 家宽IP",
    transit: "MiyaIP（官方中转）"
  },
  groupNames: {
    nodeSelection: "节点选择" // 订阅里托管的全局选择组
  },
  ruleTargets: {
    direct: "DIRECT"
  },
  rulePrefixes: {
    match: "MATCH," // Clash 兜底规则固定前缀
  },
  urlTestProbeUrl: "http://www.gstatic.com/generate_204",
  miyaProxyNameKeyword: "MiyaIP",
  groupNameSuffixes: {
    relay: "-AI|链式代理.跳板",
    chain: "-AI|链式代理.家宽出口",
    media: "-媒体"
  },
  regionFallbackOrder: {
    chain: ["SG", "TW", "JP", "KR", "US"], // 家宽出口优先低时延亚洲地区，最后再回退到美国
    media: ["US", "JP", "HK"]              // 媒体优先美区常见流媒体，其次回退到日 / 港
  },
  dns: {
    overseas: [
      "https://dns.google/dns-query",
      "https://cloudflare-dns.com/dns-query"
    ],
    domestic: [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ],
    openaiGeosite: "geosite:openai" // nameserver-policy 专用 geosite 键
  }
};

// `fallback` 依赖已定义的 `overseas`，单独成行可避免重复写同一组域外 DoH。
BASE.dns.fallback = BASE.dns.overseas.concat(["https://dns.quad9.net/dns-query"]);

// ---------------------------------------------------------------------------
// 模式字面量（SOURCE_*）
// ---------------------------------------------------------------------------

// 这里只列"哪些域名属于哪个业务桶"，路由/DNS/sniffer 行为统一在下面的 POLICY 注入。
// 模式形如 `+.domain`，转成规则时由 `toSuffix` 去掉 `+.` 前缀。

// ---------- Chain · 链式代理 ----------
var SOURCE_CHAIN = {
  support: {
    google_core: [
      "+.google.com",
      "+.googleapis.com",
      "+.googleusercontent.com"
    ],
    google_static: [
      "+.gstatic.com",
      "+.ggpht.com",
      "+.gvt1.com",
      "+.gvt2.com"
    ],
    google_workspace: ["+.withgoogle.com"], // `googleworkspace.com` 证据不足，先不默认注入
    google_cloud: [
      "+.cloud.google.com"
    ],
    microsoft_core: [
      "+.microsoft.com",
      "+.live.com",
      "+.windows.net"
    ], // `windows.net` 作为 Microsoft 官方基础设施宽域名保留
    microsoft_productivity: [
      "+.office.com",
      "+.office.net",
      "+.office365.com",
      "+.m365.cloud.microsoft",
      "+.sharepoint.com",
      "+.onenote.com",
      "+.onedrive.com"
    ],
    microsoft_auth: [
      "+.microsoftonline.com",
      "+.msftauth.net",
      "+.msauth.net",
      "+.msecnd.net"
    ],
    microsoft_developer: [
      "+.visualstudio.com",
      "+.vsassets.io",
      "+.vsmarketplacebadges.dev"
    ], // Microsoft 开发者与 VS Code 生态基础设施
    developer_git_hosts: [
      "+.github.com",
      "+.githubusercontent.com", // raw.githubusercontent.com 等，GFW 下常被 DNS 污染
      "+.gitlab.com",
      "+.gitlab-static.net",
      "+.bitbucket.org",
      "+.atlassian.com",         // Jira / Confluence / Bitbucket 官网
      "+.atlassian.net"          // 客户工作区子域
    ],
    developer_package_registries: [
      "+.npmjs.org",             // npm registry（Claude Code 自更新 + JS 项目依赖）
      "+.npmjs.com",
      "+.pypi.org",              // Python
      "+.pythonhosted.org",      // PyPI 包文件 CDN
      "+.crates.io",             // Rust
      "+.rubygems.org",          // Ruby
      "+.docker.com",            // Docker Hub
      "+.docker.io"
    ],
    developer_deployment: [
      "+.vercel.com",
      "+.vercel.app",
      "+.vercel-storage.com",
      "+.netlify.com",
      "+.netlify.app",
      "+.supabase.com",
      "+.supabase.co",
      "+.fly.io",
      "+.fly.dev",
      "+.render.com",
      "+.onrender.com",
      "+.railway.app"
    ],
    developer_tools: [
      "+.jetbrains.com",
      "+.jetbrains.space"
    ],
    developer_docs_and_qa: [
      "+.stackoverflow.com",
      "+.sstatic.net",           // Stack Exchange 静态资源
      "+.mozilla.org",           // 含 developer.mozilla.org / MDN
      "+.readthedocs.io",
      "+.readthedocs.org",
      "+.gitbook.io",
      "+.gitbook.com"
    ]
  },
  ai: {
    anthropic: [
      "+.claude.ai",
      "+.claude.com",
      "+.anthropic.com",
      "+.claudeusercontent.com",
      "+.clau.de" // Anthropic 官方场景使用过的短链
    ],
    openai: [
      "+.openai.com",
      "+.chatgpt.com",
      "+.sora.com",
      "+.oaiusercontent.com", // OpenAI 官方静态资源与内容分发基础设施
      "+.oaistatic.com"
    ],
    google_ai: [
      "+.gemini.google.com",
      "+.aistudio.google.com",
      "+.ai.google.dev",
      "+.generativelanguage.googleapis.com",
      "+.ai.google",
      "+.notebooklm.google",
      "+.makersuite.google.com", // 历史兼容入口，Google 已迁移到 AI Studio
      "+.deepmind.google",
      "+.labs.google"
    ],
    google_antigravity: [
      "+.antigravity.google",
      "+.antigravity-ide.com" // Antigravity IDE 的非 google 子域资源站
    ],
    perplexity: [
      "+.perplexity.ai",
      "+.perplexitycdn.com" // Perplexity 资源分发域名
    ],
    router_and_tools: [
      "+.openrouter.ai"
    ],
    meta: [
      "+.meta.ai"
    ],
    xai: [
      "+.x.ai",
      "+.grok.com"
    ],
    cursor: [
      "+.cursor.sh",
      "+.cursor.com"
    ], // Cursor 后端与鉴权域名；PROCESS-NAME 仅覆盖进程，域名层仍需显式入链
    mistral: [
      "+.mistral.ai"        // 含 api / console / codestral 全部子域
    ],
    huggingface: [
      "+.huggingface.co",
      "+.hf.co",            // 短链
      "+.hf.space"          // Spaces 应用托管
    ],
    replicate: [
      "+.replicate.com",
      "+.replicate.delivery" // 模型输出 CDN
    ],
    groq: [
      "+.groq.com"
    ],
    together: [
      "+.together.ai",
      "+.together.xyz"
    ],
    elevenlabs: [
      "+.elevenlabs.io"      // 语音合成
    ],
    midjourney: [
      "+.midjourney.com"
    ],
    runway: [
      "+.runwayml.com"       // Runway 视频生成
    ],
    stability: [
      "+.stability.ai"
    ],
    ideogram: [
      "+.ideogram.ai"
    ],
    civitai: [
      "+.civitai.com"        // SD 模型与社区
    ],
    ai_search: [
      "+.you.com",           // You.com / YouChat
      "+.phind.com",         // Phind 编程搜索
      "+.kagi.com"           // Kagi 付费搜索
    ],
    character_and_companion: [
      "+.character.ai",
      "+.pi.ai"              // Inflection / Pi
    ]
  },
  // AI 会话共享的第三方集成：登录反机器人、第三方鉴权、订阅结算、特性开关与错误上报。
  // 这些域名由多家 AI 厂商共用，统一随主会话走家宽链路，避免 IP 不一致触发的风控与指纹漂移。
  // Cloudflare Turnstile (challenges.cloudflare.com) 已被 chain.cloudflare 的 +.cloudflare.com 覆盖。
  integrations: {
    antibot: [
      "+.arkoselabs.com",  // ChatGPT 登录的 Arkose FunCaptcha（token 绑定客户端 IP）
      "+.funcaptcha.com",
      "+.recaptcha.net",   // reCAPTCHA 独立域，并不走 google.com
      "+.hcaptcha.com"     // hCaptcha（Discord / 部分 AI 注册）
    ],
    auth_providers: [
      "+.auth0.com",       // ChatGPT Team 等使用 Auth0
      "+.auth0cdn.com",
      "+.clerk.com",       // OpenRouter / 多家 AI 创业用 Clerk
      "+.clerk.dev",
      "+.clerk.accounts.dev",
      "+.okta.com"         // 企业 SSO（含 Anthropic Console 团队席位）
    ],
    payments: [
      "+.stripe.com",      // Claude Pro / ChatGPT Plus / Perplexity Pro 主要结算入口
      "+.stripe.network",
      "+.paypal.com",      // PayPal
      "+.paypalobjects.com", // PayPal CDN
      "+.paddle.com",      // Paddle（Apple 友好的订阅平台）
      "+.lemonsqueezy.com" // 独立 AI 应用常用
    ],
    telemetry: [
      "+.statsig.com",     // Claude Code / Claude.ai / ChatGPT 的 feature flag
      "+.statsigapi.net",
      "+.featuregates.org",
      "+.featureassets.org",
      "+.sentry.io",       // Sentry 错误上报
      "+.sentry-cdn.com",
      "+.posthog.com",     // PostHog（Claude.ai 等）
      "+.segment.com",     // Segment / Twilio Segment
      "+.segment.io",
      "+.segmentapis.com",
      "+.mixpanel.com",
      "+.amplitude.com",
      "+.datadoghq.com",   // Datadog RUM 浏览器端
      "+.browser-intake-datadoghq.com"
    ]
  },
  force: {
    cloudflare: [
      "+.cloudflare.com"
    ]
  },
  apps: {
    ai: {
      apps: [
        "Claude",
        "ChatGPT",
        "Perplexity",
        "Cursor"
      ],
      helperSuffixes: [
        "Helper"
      ],
      exact: [
        "ChatGPTHelper",
        "Claude Helper (Renderer)",
        "Claude Helper (GPU)",
        "Claude Helper (Plugin)",
        // macOS PROCESS-NAME 匹配 Bundle 可执行名，不含 `.app` 后缀。
        // 未列入此处的应用：
        //   - Claude Code / URL Handler 都以 `claude` 运行，统一通过 ai.cli 命中。
        //   - Antigravity 的 Bundle 可执行名是 `Electron`，无法按进程名精确匹配，改走域名规则。
        "Quotio"
      ],
      cli: ["claude", "gemini", "codex"]
    },
    browser: {
      apps: [
        "Dia",
        "Atlas",
        "SunBrowser"
      ],
      helperSuffixes: [
        "Helper",
        "Helper (Renderer)",
        "Helper (GPU)",
        "Helper (Plugin)",
        "Helper (Alerts)"
      ]
    }
  }
};

// ---------- Global Default · 域外默认代理 ----------
var SOURCE_GLOBAL_DEFAULT = {
  cloud: {
    cloudflare: [
      "+.cloudflare-dns.com",
      "+.cdn.cloudflare.net",
      "+.workers.dev",
      "+.pages.dev"
    ],
    aws: [
      "+.amazonaws.com",
      "+.awsstatic.com",
      "+.cloudfront.net"
    ],
    fastly: [
      "+.fastly.com",
      "+.fastly.net",
      "+.fastlylb.net"
    ],
    akamai: [
      "+.akamai.net",
      "+.akamaiedge.net",
      "+.akamaihd.net",
      "+.akamaized.net",
      "+.edgekey.net",
      "+.edgesuite.net"
    ],
    azure_cdn: [
      "+.azureedge.net",
      "+.azurefd.net"
    ],
    jsdelivr: [
      "+.jsdelivr.net"
    ],
    bunny: [
      "+.bunnycdn.com",
      "+.b-cdn.net"        // BunnyCDN 客户加速域
    ],
    cloudinary: [
      "+.cloudinary.com"   // 图片 / 视频 SaaS CDN
    ]
  }
};

// ---------- Media（独立地区组，不走家宽链路） ----------
// 分四类：视频流媒体 / 音乐流媒体 / 社交 / 即时通讯。
// 这一桶里的所有域名都路由到 `mediaRegion`（默认 US），与家宽 chain 解耦，
// 也借此跨越对这些站点不友好的网络环境（GFW、地区封锁等）。
var SOURCE_MEDIA = {
  // ---- 视频流媒体 ----
  youtube: [
    "+.youtube.com",
    "+.googlevideo.com",
    "+.ytimg.com",
    "+.youtube-nocookie.com",
    "+.yt.be"
  ],
  netflix: [
    "+.netflix.com",
    "+.netflix.net",
    "+.nflxvideo.net",
    "+.nflxso.net",
    "+.nflximg.net",
    "+.nflximg.com",
    "+.nflxext.com"
  ],
  disney_plus: [
    "+.disneyplus.com",
    "+.disney-plus.net",
    "+.dssott.com",   // Disney+ 流媒体 CDN
    "+.bamgrid.com"   // BAMTech（Disney 流媒体后端）
  ],
  hbo_max: [
    "+.max.com",
    "+.hbomax.com",
    "+.hbomaxcdn.com",
    "+.hbonow.com",
    "+.maxgo.com"
  ],
  peacock: [
    "+.peacocktv.com"      // NBCUniversal Peacock
  ],
  paramount_plus: [
    "+.paramountplus.com",
    "+.cbsivideo.com",     // 旧 CBS All Access 残留 CDN
    "+.paramount.com"
  ],
  crunchyroll: [
    "+.crunchyroll.com",   // 动漫流媒体
    "+.cr-bundles.com"
  ],
  vimeo: [
    "+.vimeo.com",
    "+.vimeocdn.com"
  ],
  dailymotion: [
    "+.dailymotion.com",
    "+.dmcdn.net"
  ],
  hulu: [
    "+.hulu.com",
    "+.hulustream.com",
    "+.huluim.com"
  ],
  prime_video: [
    "+.primevideo.com",
    "+.aiv-cdn.net",     // Prime Video CDN（不会牵连 amazon.com 主站和 AWS）
    "+.aiv-delivery.net"
  ],
  twitch: [
    "+.twitch.tv",
    "+.ttvnw.net",
    "+.jtvnw.net"
  ],

  // ---- 音乐流媒体 ----
  spotify: [
    "+.spotify.com",
    "+.scdn.co",         // Spotify 静态资源
    "+.spotifycdn.com"
  ],
  soundcloud: [
    "+.soundcloud.com",
    "+.sndcdn.com"       // SoundCloud CDN
  ],
  bandcamp: [
    "+.bandcamp.com"
  ],

  // ---- 社交 ----
  twitter: [
    "+.twitter.com",
    "+.x.com",
    "+.twimg.com",
    "+.t.co"
  ],
  meta: [
    "+.facebook.com",
    "+.fbcdn.net",
    "+.fb.com",
    "+.facebook.net",
    "+.instagram.com",
    "+.cdninstagram.com",
    "+.threads.net"      // Meta 旗下 Threads
  ],
  reddit: [
    "+.reddit.com",
    "+.redditmedia.com",
    "+.redditstatic.com"
  ],
  tiktok: [              // TikTok 海外版（与抖音 douyin.com 无关，不会触发境内分流）
    "+.tiktok.com",
    "+.tiktokcdn.com",
    "+.tiktokv.com",
    "+.ibyteimg.com"
  ],
  snapchat: [
    "+.snapchat.com",
    "+.snap.com",
    "+.sc-cdn.net"
  ],
  pinterest: [
    "+.pinterest.com",
    "+.pinimg.com"
  ],
  bluesky: [
    "+.bsky.app",
    "+.bsky.social"
  ],
  tumblr: [
    "+.tumblr.com",
    "+.tumblr.media"
  ],
  long_form_writing: [
    "+.medium.com",
    "+.substack.com",
    "+.patreon.com"
  ],
  niche_communities: [
    "+.goodreads.com",     // 读书
    "+.letterboxd.com"     // 电影日记
  ],

  // ---- 即时通讯 ----
  telegram: [
    "+.telegram.org",
    "+.t.me",
    "+.telegra.ph",
    "+.telesco.pe"
  ],
  discord: [
    "+.discord.com",
    "+.discord.gg",
    "+.discordapp.com",
    "+.discordapp.net",
    "+.discord.media"
  ],
  line: [                // LINE（日 / 韩 / 台主流 IM）
    "+.line.me",
    "+.line-apps.com",
    "+.line-scdn.net",
    "+.line-cdn.net"
  ],
  whatsapp: [            // WhatsApp（Meta 旗下，但放 IM 桶更直观）
    "+.whatsapp.com",
    "+.whatsapp.net"
  ],
  signal: [
    "+.signal.org"
  ]
};

// ---------- CN Direct · 境内直连 ----------
var SOURCE_CN_DIRECT = {
  ai: {
    tongyi: [
      "+.tongyi.aliyun.com",
      "+.qianwen.aliyun.com",
      "+.dashscope.aliyuncs.com"
    ],
    moonshot: [
      "+.moonshot.cn"
    ],
    zhipu: [
      "+.chatglm.cn",
      "+.zhipuai.cn",
      "+.bigmodel.cn"
    ],
    siliconflow: [
      "+.siliconflow.cn"
    ],
    deepseek: [
      "+.deepseek.com"      // api / platform / chat 全部子域
    ],
    doubao: [
      "+.doubao.com",       // 字节豆包
      "+.volcengineapi.com" // 火山方舟（豆包模型 API）
    ],
    minimax: [
      "+.minimaxi.com",     // MiniMax 域内域名
      "+.hailuoai.com"      // 海螺 AI
    ],
    baichuan: [
      "+.baichuan-ai.com"
    ],
    stepfun: [
      "+.stepfun.com"       // 阶跃星辰
    ]
  },
  office: {
    tencent_messaging_and_collab: [
      "+.qq.com",
      "+.qqmail.com",
      "+.exmail.qq.com",
      "+.weixin.qq.com",
      "+.work.weixin.qq.com",
      "+.docs.qq.com",
      "+.meeting.tencent.com"
    ],
    alibaba_productivity: [
      "+.dingtalk.com",
      "+.dingtalkapps.com",
      "+.aliyundrive.com",
      "+.quark.cn",
      "+.teambition.com"
    ],
    bytedance_productivity: [
      "+.feishu.cn",
      "+.feishu.net",
      "+.feishucdn.com",
      "+.larksuite.com",
      "+.larkoffice.com"
    ],
    wps_productivity: [
      "+.wps.cn",
      "+.wps.com",
      "+.kdocs.cn",
      "+.kdocs.com"
    ]
  },
  cloud: {
    alibaba_cloud: [
      "+.aliyun.com",
      "+.aliyuncs.com",
      "+.alibabacloud.com"
    ],
    tencent_cloud: [
      "+.tencentcloud.com",
      "+.cloud.tencent.com",
      "+.qcloud.com"
    ],
    bytedance_cloud: [
      "+.volcengine.com",
      "+.volces.com"
    ],
    huawei_cloud: [
      "+.myhuaweicloud.com",
      "+.huaweicloud.com",
      "+.huaweicloud.cn"
    ],
    baidu_cloud_and_cdn: [
      "+.baidubce.com",
      "+.bcebos.com",
      "+.bdstatic.com"
    ],
    jd_cloud: [
      "+.jdcloud.com",
      "+.jcloudcs.com"
    ],
    qiniu_cdn: [
      "+.qiniu.com",
      "+.qbox.me",
      "+.qiniucdn.com"
    ],
    upyun: [
      "+.upyun.com",
      "+.upaiyun.com"
    ],
    wangsu_cdn: [
      "+.wangsu.com",
      "+.wscdns.com",
      "+.wscloudcdn.com"
    ],
    ctyun: [
      "+.ctyun.cn"
    ],
    ksyun: [
      "+.ksyun.com"
    ]
  },
  // 域内消费类高频站点；放 DIRECT 既走最近 CN CDN，也避免占用代理带宽。
  consumer: {
    baidu: [
      "+.baidu.com",         // 搜索 / 网盘 / 地图统一入口
      "+.bdimg.com"          // 百度图片站静态资源
    ],
    bilibili: [
      "+.bilibili.com",
      "+.hdslb.com",         // B 站全站静态 / 图片 CDN
      "+.biliapi.net",
      "+.biliapi.com",
      "+.bilivideo.com",     // 视频流分发
      "+.bilicdn1.com",
      "+.biligame.com"
    ],
    weibo_and_sina: [
      "+.weibo.com",
      "+.weibo.cn",
      "+.weibocdn.com",
      "+.sinaimg.cn",        // Weibo 图片 / 视频 CDN
      "+.sina.com.cn"
    ],
    zhihu: [
      "+.zhihu.com",
      "+.zhimg.com"          // 知乎静态资源
    ],
    xiaohongshu: [
      "+.xiaohongshu.com",
      "+.xhscdn.com"
    ],
    douyin_and_kuaishou: [
      "+.douyin.com",        // 抖音（与海外 TikTok 不冲突）
      "+.douyinpic.com",
      "+.douyincdn.com",
      "+.kuaishou.com",
      "+.gifshow.com",       // 快手早期域 / 静态资源
      "+.yximgs.com"         // 快手图片 CDN
    ],
    netease: [
      "+.163.com",           // 含网易邮箱 / 网易云音乐 / 新闻
      "+.126.com",
      "+.netease.com"
    ],
    video_streaming: [
      "+.iqiyi.com",
      "+.iqiyipic.com",
      "+.youku.com",
      "+.mgtv.com",
      "+.sohu.com"
    ],
    e_commerce: [
      "+.taobao.com",
      "+.tbcdn.cn",
      "+.taobaocdn.com",
      "+.tmall.com",
      "+.jd.com",
      "+.360buyimg.com",     // 京东图片 CDN
      "+.pinduoduo.com",
      "+.yangkeduo.com"      // 拼多多前端域
    ],
    local_services: [
      "+.meituan.com",
      "+.meituan.net",
      "+.dianping.com"
    ],
    gaming: [
      "+.mihoyo.com"         // 米哈游国服（原神 / 星穹铁道）；hoyoverse.com 走默认
    ]
  }
};

// ---------- Local Direct · 本地与推送直连 ----------
var SOURCE_LOCAL_DIRECT = {
  local_and_push: [
    "+.push.apple.com",
    "+.lan",
    "+.local",
    "+.localhost",
    "+.home.arpa"          // RFC 8375 家庭网络保留域
  ]
};

// ---------- Overseas Direct · 域外 DoH + 直连 ----------
var SOURCE_OVERSEAS_DIRECT = {
  special: {
    apple: {
      core: [
        "+.apple.com",
        "+.icloud.com"
      ],
      content: [
        "+.icloud-content.com",
        "+.mzstatic.com",
        "+.cdn-apple.com",
        "+.aaplimg.com"
      ],
      services: ["+.apple-cloudkit.com"]
    },
    egressCheck: {
      core: [
        "+.ping0.cc",
        "+.ipinfo.io",
        "+.ifconfig.me",     // 常用 curl 出口检测
        "+.ip.sb"            // NextDNS 提供的快速出口查询
      ]
    }
  },
  global: {
    cnApps: {
      immersive_translate: [
        "+.immersivetranslate.com"
      ],
      mineru: [
        "+.mineru.org.cn",
        "+.openxlab.org.cn"
      ]
    },
    apps: {
      tailscale: [
        "+.tailscale.com",
        "+.tailscale.io",
        "+.ts.net"
      ],
      zerotier: [
        "+.zerotier.com"     // ZeroTier P2P，定位与 Tailscale 类似
      ],
      plex: [
        "+.plex.tv",
        "+.plex.direct"      // Plex 客户端直连家用服务器走 plex.direct 通配子域
      ],
      synology: [
        "+.synology.com",
        "+.quickconnect.to"  // Synology QuickConnect 中继
      ],
      typeless: [
        "+.typeless.com"
      ]
    }
  }
};

// ---------- Network Direct · 网络地址直连 ----------
// 私有 / 链路本地 / CGNAT / Tailscale ULA 都走 DIRECT，避免被无意中走代理。
var SOURCE_NETWORK_DIRECT = {
  direct: [
    // RFC 1918 私有网络
    { type: "IP-CIDR", value: "10.0.0.0/8", target: BASE.ruleTargets.direct },
    { type: "IP-CIDR", value: "172.16.0.0/12", target: BASE.ruleTargets.direct },
    { type: "IP-CIDR", value: "192.168.0.0/16", target: BASE.ruleTargets.direct },
    // 链路本地
    { type: "IP-CIDR", value: "169.254.0.0/16", target: BASE.ruleTargets.direct },
    // CGNAT (RFC 6598) + Tailscale magic IP
    { type: "IP-CIDR", value: "100.64.0.0/10", target: BASE.ruleTargets.direct },
    { type: "IP-CIDR", value: "100.100.100.100/32", target: BASE.ruleTargets.direct },
    // IPv6 ULA + 链路本地 + Tailscale ULA
    { type: "IP-CIDR6", value: "fc00::/7", target: BASE.ruleTargets.direct },
    { type: "IP-CIDR6", value: "fe80::/10", target: BASE.ruleTargets.direct },
    { type: "IP-CIDR6", value: "fd7a:115c:a1e0::/48", target: BASE.ruleTargets.direct }
  ]
};

// 端到端样本：声明"这些域名 / 进程必须落到这个出口"。
//   - 加载期 assertExpectedRoutesCoverage：样本必须能在 SOURCE_* 中匹配。
//   - 运行期 validateManagedRouting：每条样本规则的 target 必须正确。
//   - tests/validate.js：直接读 sandbox.EXPECTED_ROUTES 当端到端期望。
// 字段：
//   domains       裸域名（DOMAIN-SUFFIX 命中）
//   processNames  受管桌面 App 进程名
//   cliNames      AI CLI 可执行名（固定走 chainRegion）
var EXPECTED_ROUTES = {
  toChain: {
    domains: [
      "claude.ai",
      "chatgpt.com",
      "gemini.google.com",
      "perplexity.ai",
      "google.com",
      "cursor.sh",             // Cursor 后端
      "arkoselabs.com",        // Arkose 登录反机器人（integrations.antibot）
      "stripe.com",            // AI 订阅支付（integrations.payments）
      "statsig.com",           // feature flag（integrations.telemetry）
      "githubusercontent.com", // GitHub 原始内容，GFW 下易污染
      "npmjs.org"              // npm 官方 registry
    ],
    processNames: ["Claude"],
    cliNames: ["claude", "codex"]
  },
  toMedia: {
    domains: [
      "youtube.com",     // 视频流媒体
      "x.com",           // 社交
      "twitch.tv",       // 直播
      "spotify.com",     // 音乐
      "line.me",         // IM
      "whatsapp.com"     // IM
    ]
  }
};

// ---------------------------------------------------------------------------
// 通用数据处理工具
// ---------------------------------------------------------------------------

// 对字符串列表做稳定去重，保留首次出现的顺序。
function uniqueStrings(values) {
  var uniqueValues = [];
  var seen = {};
  for (var i = 0; i < values.length; i++) {
    var value = values[i];
    if (seen[value]) continue;
    seen[value] = true;
    uniqueValues.push(value);
  }
  return uniqueValues;
}

// 合并多组字符串列表并保持稳定去重。
function mergeStringGroups(groups) {
  var mergedValues = [];
  for (var i = 0; i < groups.length; i++) {
    mergedValues.push.apply(mergedValues, groups[i]);
  }
  return uniqueStrings(mergedValues);
}

// 为应用展开主进程、显式 helper，以及精确进程名。
function expandProcessNamesWithHelpers(appNames, helperSuffixes, exactProcessNames) {
  var processNames = [];
  var i;
  var j;
  var exactNames = exactProcessNames || [];

  for (i = 0; i < appNames.length; i++) {
    processNames.push(appNames[i]);
    for (j = 0; j < helperSuffixes.length; j++) {
      processNames.push(appNames[i] + " " + helperSuffixes[j]);
    }
  }

  processNames.push.apply(processNames, exactNames);
  return uniqueStrings(processNames);
}

// 为字符串数组构建便于查询的哈希表。
function buildStringLookup(values) {
  var lookup = {};
  for (var i = 0; i < values.length; i++) {
    lookup[values[i]] = true;
  }
  return lookup;
}

// 从字符串数组中排除另一组字符串，保留原顺序。
function excludeStrings(values, excludedValues) {
  var filteredValues = [];
  var excludedLookup = buildStringLookup(excludedValues);
  for (var i = 0; i < values.length; i++) {
    if (excludedLookup[values[i]]) continue;
    filteredValues.push(values[i]);
  }
  return uniqueStrings(filteredValues);
}

// 约束：`+.` 前缀 + 一或多个标签（字母/数字/连字符，不以 `-` 起止），标签间用单个 `.` 分隔，
// 禁止 `*`、连续点、首尾点等通配或畸形写法。单标签（如 +.lan）允许。
var PATTERN_SHAPE = /^\+\.[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;

// 断言所有模式符合 `+.domain` 形状，拦截漏写前缀或通配符滥用。
function assertPatternsHavePlusPrefix(patterns) {
  for (var i = 0; i < patterns.length; i++) {
    if (!PATTERN_SHAPE.test(patterns[i])) {
      throw createUserError("pattern 形状非法（应为 +.domain）: " + patterns[i]);
    }
  }
}

// 把带通配前缀的域名模式转换成规则使用的裸域名后缀。
function toSuffix(domainPattern) {
  return domainPattern.indexOf("+.") === 0
    ? domainPattern.substring(2)
    : domainPattern;
}

// ES5 安全的 `endsWith`：判断 str 是否以 suffix 结尾。
function endsWithString(str, suffix) {
  if (suffix.length > str.length) return false;
  return str.lastIndexOf(suffix) === str.length - suffix.length;
}

// 把按类别分组的域名模式对象展平成单个数组并去重。
function flattenGroupedPatterns(groupedPatterns) {
  var flattenedPatterns = [];
  Object.keys(groupedPatterns).forEach(function (groupName) {
    flattenedPatterns.push.apply(flattenedPatterns, groupedPatterns[groupName]);
  });
  return uniqueStrings(flattenedPatterns);
}

function createUserError(message) {
  return new Error(message);
}

// 是否让受管 AI 浏览器继续按应用名强制走 chainRegion。
function shouldRouteBrowserToChain() {
  return USER_OPTIONS.routeBrowserToChain !== false;
}

// ---------------------------------------------------------------------------
// 策略表（POLICY）与派生分类
// ---------------------------------------------------------------------------

// POLICY 是所有域名模式的**单一权威来源**：每条 entry 同时声明
// 路由 / DNS 分区 / sniffer / fake-ip 绕过 / fallback-filter。
// 下游 DNS、sniffer、规则、断言都只从 POLICY 投影，没有第二份决策。
//
// 字段：
//   key            稳定标识（仅用于调试与报错）
//   patterns       `+.domain` 模式数组（已去重）
//   route          "chain" | "media" | "direct"，省略 = 不生成路由规则
//   dnsZone        "overseas" | "domestic"，省略 = 不进 nameserver-policy
//   sniffer        "force" | "skip"，省略 = 不参与 sniffer 配置
//   fakeIpBypass   true = 进入 fake-ip-filter（解析真实 IP）
//   fallbackFilter true = 进入 DNS fallback-filter.domain
//
// 冲突解决：同一 pattern 既出现在 direct 又出现在 chain/media 时，direct 胜出
// （chain/media 派生时 excludeStrings(direct)）。
function buildPolicy() {
  return [
    // ---- chain · 走家宽出口 ----
    {
      key: "chain.support", patterns: flattenGroupedPatterns(SOURCE_CHAIN.support),
      route: "chain", dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },
    {
      key: "chain.ai", patterns: flattenGroupedPatterns(SOURCE_CHAIN.ai),
      route: "chain", dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },
    {
      key: "chain.integrations", patterns: flattenGroupedPatterns(SOURCE_CHAIN.integrations),
      route: "chain", dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },
    {
      key: "chain.cloudflare", patterns: flattenGroupedPatterns(SOURCE_CHAIN.force),
      route: "chain", dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },

    // ---- media · 走媒体地区组 ----
    {
      key: "media", patterns: flattenGroupedPatterns(SOURCE_MEDIA),
      route: "media", dnsZone: "overseas", fallbackFilter: true
    },

    // ---- 默认代理（不写 route，仅做 DNS / fallback-filter）----
    {
      key: "default.overseasCloudCdn", patterns: flattenGroupedPatterns(SOURCE_GLOBAL_DEFAULT.cloud),
      dnsZone: "overseas", fallbackFilter: true
    },

    // ---- direct · 直连 ----
    {
      key: "direct.apple", patterns: flattenGroupedPatterns(SOURCE_OVERSEAS_DIRECT.special.apple),
      route: "direct", dnsZone: "overseas", fakeIpBypass: true
    },
    {
      key: "direct.egressCheck", patterns: flattenGroupedPatterns(SOURCE_OVERSEAS_DIRECT.special.egressCheck),
      route: "direct", dnsZone: "overseas", fallbackFilter: true
    },
    {
      key: "direct.overseasApps", patterns: flattenGroupedPatterns(SOURCE_OVERSEAS_DIRECT.global.apps),
      route: "direct", dnsZone: "overseas", sniffer: "skip", fallbackFilter: true
    },
    {
      key: "direct.cnAppsOverseasDoh", patterns: flattenGroupedPatterns(SOURCE_OVERSEAS_DIRECT.global.cnApps),
      route: "direct", dnsZone: "overseas", sniffer: "skip", fallbackFilter: true
    },
    {
      key: "direct.cn.ai", patterns: flattenGroupedPatterns(SOURCE_CN_DIRECT.ai),
      route: "direct", dnsZone: "domestic"
    },
    {
      key: "direct.cn.office", patterns: flattenGroupedPatterns(SOURCE_CN_DIRECT.office),
      route: "direct", dnsZone: "domestic"
    },
    {
      key: "direct.cn.cloud", patterns: flattenGroupedPatterns(SOURCE_CN_DIRECT.cloud),
      route: "direct", dnsZone: "domestic"
    },
    {
      key: "direct.cn.consumer", patterns: flattenGroupedPatterns(SOURCE_CN_DIRECT.consumer),
      route: "direct", dnsZone: "domestic"
    },
    {
      key: "direct.localAndPush", patterns: flattenGroupedPatterns(SOURCE_LOCAL_DIRECT),
      route: "direct", dnsZone: "domestic", sniffer: "skip"
    }
  ];
}

var POLICY = buildPolicy();

// 加载期断言：每条 POLICY 条目的 patterns 都符合 `+.domain` 形状。
(function () {
  for (var i = 0; i < POLICY.length; i++) {
    assertPatternsHavePlusPrefix(POLICY[i].patterns);
  }
})();

// 投影工具：对每条 POLICY 跑断言函数，把命中的 patterns 合并去重返回。
function projectPolicyPatterns(predicate) {
  var result = [];
  for (var i = 0; i < POLICY.length; i++) {
    if (predicate(POLICY[i])) result.push.apply(result, POLICY[i].patterns);
  }
  return uniqueStrings(result);
}

// POLICY 谓词工厂。
function matchRoute(route) {
  return function (entry) { return entry.route === route; };
}
function matchSniffer(mode) {
  return function (entry) { return entry.sniffer === mode; };
}
function matchFakeIpBypass(entry) { return entry.fakeIpBypass === true; }
function matchFallbackFilter(entry) { return entry.fallbackFilter === true; }

// 从 POLICY 投影出下游真正消费的三类域名集合：
//   chain    → 进家宽出口（排除被 direct 抢占的模式）
//   media    → 媒体地区组
//   direct   → 全量 DIRECT 模式，用于生成直连规则与 fake-ip/sniffer 判断
//   sniffer  → force / skip 两侧的嗅探决策
//   fakeIpBypass → 需要返回真实 IP 的域名（Apple 等）
function buildDerivedPatterns() {
  var direct = projectPolicyPatterns(matchRoute("direct"));
  var chain = excludeStrings(projectPolicyPatterns(matchRoute("chain")), direct);
  var media = excludeStrings(projectPolicyPatterns(matchRoute("media")), direct);
  return {
    chain: chain,
    media: media,
    direct: direct,
    fakeIpBypass: projectPolicyPatterns(matchFakeIpBypass),
    sniffer: {
      // chain 条目默认强制嗅探；额外合入所有 sniffer=force 的条目以覆盖不走 chain 的纯嗅探项。
      force: mergeStringGroups([chain, projectPolicyPatterns(matchSniffer("force"))]),
      skip: projectPolicyPatterns(matchSniffer("skip"))
    }
  };
}

// 从 SOURCE_CHAIN.apps 展开出三类进程入口：
//   aiApps  → 受管 AI 桌面 App + 显式 helper（始终走 chainRegion）
//   aiCli   → AI 命令行（始终走 chainRegion）
//   browser → AI 浏览器 + 全部 helper（按 USER_OPTIONS.routeBrowserToChain 决定是否走 chainRegion）
function buildDerivedProcessNames() {
  return {
    aiApps: expandProcessNamesWithHelpers(
      SOURCE_CHAIN.apps.ai.apps,
      SOURCE_CHAIN.apps.ai.helperSuffixes,
      SOURCE_CHAIN.apps.ai.exact
    ),
    aiCli: uniqueStrings(SOURCE_CHAIN.apps.ai.cli.slice()),
    browser: expandProcessNamesWithHelpers(
      SOURCE_CHAIN.apps.browser.apps,
      SOURCE_CHAIN.apps.browser.helperSuffixes
    )
  };
}

// DERIVED 是后续执行函数唯一应直接消费的派生入口。
var DERIVED = {
  patterns: buildDerivedPatterns(),
  processNames: buildDerivedProcessNames(),
  networkRules: {
    direct: SOURCE_NETWORK_DIRECT.direct.slice()
  }
};

// 判断裸域是否被一组 `+.xxx` 模式覆盖（等值或作为子域）。
function isDomainCoveredBySuffixPatterns(domain, suffixPatterns) {
  for (var i = 0; i < suffixPatterns.length; i++) {
    var suffix = toSuffix(suffixPatterns[i]);
    if (domain === suffix) return true;
    if (endsWithString(domain, "." + suffix)) return true;
  }
  return false;
}

// 断言每个样本域名 / 进程都能在对应的 DERIVED 源集合中找到覆盖，防止样本与源头漂移。
function assertExpectedRoutesCoverage() {
  var i;
  var sample;

  for (i = 0; i < EXPECTED_ROUTES.toChain.domains.length; i++) {
    sample = EXPECTED_ROUTES.toChain.domains[i];
    if (!isDomainCoveredBySuffixPatterns(sample, DERIVED.patterns.chain)) {
      throw createUserError("toChain 样本未被 chain 源覆盖: " + sample);
    }
  }

  for (i = 0; i < EXPECTED_ROUTES.toMedia.domains.length; i++) {
    sample = EXPECTED_ROUTES.toMedia.domains[i];
    if (!isDomainCoveredBySuffixPatterns(sample, DERIVED.patterns.media)) {
      throw createUserError("toMedia 样本未被 media 源覆盖: " + sample);
    }
  }

  var procLookup = buildStringLookup(
    DERIVED.processNames.aiApps.concat(DERIVED.processNames.aiCli)
  );
  var procSamples = EXPECTED_ROUTES.toChain.processNames
    .concat(EXPECTED_ROUTES.toChain.cliNames);
  for (i = 0; i < procSamples.length; i++) {
    if (!procLookup[procSamples[i]]) {
      throw createUserError("toChain 样本进程未在 SOURCE_CHAIN.apps 中: " + procSamples[i]);
    }
  }
}

assertExpectedRoutesCoverage();

// 把字符串数组映射为 { type, value } 规则目标列表。
function buildValidationTargets(ruleType, values) {
  var targets = [];
  for (var i = 0; i < values.length; i++) {
    targets.push({ type: ruleType, value: values[i] });
  }
  return targets;
}

// 校验目标从 `EXPECTED_ROUTES.toChain` 派生，避免校验与源数据脱钩。
function buildStrictValidationTargets() {
  var samples = EXPECTED_ROUTES.toChain;
  return buildValidationTargets("DOMAIN-SUFFIX", samples.domains)
    .concat(buildValidationTargets("PROCESS-NAME", samples.processNames))
    .concat(buildValidationTargets("PROCESS-NAME", samples.cliNames));
}

// 校验媒体域名是否命中独立媒体组选区。
function buildMediaValidationTargets() {
  return buildValidationTargets("DOMAIN-SUFFIX", EXPECTED_ROUTES.toMedia.domains);
}

// 校验受管浏览器进程是否继续命中链式代理出口，每个受管 App 都校验主进程名。
function buildBrowserValidationTargets() {
  if (!shouldRouteBrowserToChain()) return [];
  var targets = [];
  var apps = SOURCE_CHAIN.apps.browser.apps;
  for (var i = 0; i < apps.length; i++) {
    targets.push({ type: "PROCESS-NAME", value: apps[i] });
  }
  return targets;
}

// ---------------------------------------------------------------------------
// DNS + Sniffer
// ---------------------------------------------------------------------------

// 把脚本生成的 DNS 和域名嗅探配置写入主配置。
function writeDnsAndSniffer(config, derived) {
  config.dns = buildDnsConfig(derived);
  config.sniffer = buildSnifferConfig(derived);
}

// 遍历 POLICY，按 `dnsZone` 把每条 entry 的模式绑到对应 DoH。
// 新增类别时只需在 POLICY 里给新条目加 `dnsZone` 字段，这里无需改动。
function buildNameserverPolicy() {
  var dohByZone = { overseas: BASE.dns.overseas, domestic: BASE.dns.domestic };
  var policy = {};
  policy[BASE.dns.openaiGeosite] = dohByZone.overseas;

  for (var i = 0; i < POLICY.length; i++) {
    var entry = POLICY[i];
    if (!entry.dnsZone) continue;
    var dohServers = dohByZone[entry.dnsZone];
    if (!dohServers) throw createUserError("nameserver-policy 未知 zone: " + entry.dnsZone);
    for (var j = 0; j < entry.patterns.length; j++) {
      policy[entry.patterns[j]] = dohServers;
    }
  }

  return policy;
}

// 构建需要绕过 `fake-ip` 的域名白名单。
// 风格约定：能用 `+.` 前缀的统一用 `+.`（匹配域名本身与全部子域）；
// 仅中部通配（如 `time.*.com`、`xbox.*.microsoft.com`、`stun.*.*`）才保留 glob，
// 因为 `+.` 不支持中段通配。
function buildDnsFakeIpFilter(derived) {
  var localNetworkDomains = [
    "+.push.apple.com",
    "+.lan",
    "+.local",
    "+.localhost",
    "localhost.ptlogin2.qq.com"
  ];
  var timeSyncDomains = [
    "time.*.com", // 中部通配：保留 glob
    "time.*.gov",
    "time.*.edu.cn",
    "time.*.apple.com",
    "time-ios.apple.com",
    "time-macos.apple.com",
    "ntp.*.com",
    "ntp1.aliyun.com",
    "pool.ntp.org",
    "+.pool.ntp.org"
  ];
  var connectivityTestDomains = [
    "+.msftconnecttest.com", // 覆盖裸域与所有子域（含 www.）
    "+.msftncsi.com"
  ];
  var gamingRealtimeDomains = [
    "+.srv.nintendo.net",
    "+.stun.playstation.net",
    "xbox.*.microsoft.com", // 中部通配：保留 glob
    "+.xboxlive.com",
    "+.battlenet.com.cn",
    "+.blzstatic.cn"
  ]; // 游戏主机和游戏平台入口通常依赖真实 IP
  var stunRealtimeDomains = [
    "stun.*.*", // 中部通配：保留 glob
    "stun.*.*.*"
  ]; // 通用 STUN 常见于 WebRTC、语音和点对点连接
  var homeRouterDomains = [
    "+.router.asus.com",
    "+.linksys.com",
    "+.tplinkwifi.net",
    "+.xiaoqiang.net"
  ]; // 本地路由器和家庭网络设备入口应返回真实 IP

  return localNetworkDomains
    .concat(timeSyncDomains)
    .concat(connectivityTestDomains)
    .concat(derived.patterns.fakeIpBypass)
    .concat(gamingRealtimeDomains)
    .concat(stunRealtimeDomains)
    .concat(homeRouterDomains);
}

// 所有标记 fallbackFilter 的 POLICY 模式都进 fallback-filter.domain；
// 配 `geoip-code: CN`，让境内 IP 走 nameserver、其余走 fallback DoH。
function buildDnsFallbackFilter() {
  return {
    geoip: true,
    "geoip-code": "CN",
    geosite: ["gfw"],
    ipcidr: ["240.0.0.0/4", "0.0.0.0/32"],
    domain: projectPolicyPatterns(matchFallbackFilter)
  };
}

// 构建不含动态列表项的基础 DNS 配置。
function buildDnsBaseConfig() {
  return {
    enable: true,
    listen: "0.0.0.0:1053",
    ipv6: true,
    "respect-rules": false,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    nameserver: BASE.dns.domestic,
    "proxy-server-nameserver": BASE.dns.domestic,
    "direct-nameserver": BASE.dns.domestic.slice(),
    "direct-nameserver-follow-policy": true,
    fallback: BASE.dns.fallback
  };
}

// 组装完整的 DNS 配置。
function buildDnsConfig(derived) {
  var dnsConfig = buildDnsBaseConfig();
  dnsConfig["fake-ip-filter"] = buildDnsFakeIpFilter(derived);
  dnsConfig["fallback-filter"] = buildDnsFallbackFilter();
  dnsConfig["nameserver-policy"] = buildNameserverPolicy();
  return dnsConfig;
}

// 构建域名嗅探配置，继续复用 AI 严格分类与直连跳过项。
function buildSnifferConfig(derived) {
  return {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    sniff: {
      TLS: { ports: [443, 8443] },
      HTTP: { ports: [80, 8080, 8880], "override-destination": true },
      QUIC: { ports: [443] }
    },
    "force-domain": derived.patterns.sniffer.force,
    "skip-domain": derived.patterns.sniffer.skip
  };
}

// ---------------------------------------------------------------------------
// MiyaIP 代理链路与地区组选区
// ---------------------------------------------------------------------------

// 确保主配置里存在代理、代理组和规则三个容器。
function writeContainers(config) {
  if (!config.proxies) config.proxies = [];
  if (!config["proxy-groups"]) config["proxy-groups"] = [];
  if (!config.rules) config.rules = [];
}

// 把地区输入统一转成大写字符串键；非字符串或空串直接拒绝，便于尽早暴露配置错误。
function normalizeRegionKey(region) {
  if (typeof region !== "string" || region === "") {
    throw createUserError("chainRegion / mediaRegion 必须是非空字符串，实际: " + region);
  }
  return region.toUpperCase();
}

// 根据地区键解析地区元数据，并按需提供兜底标签。
function resolveRegionMeta(region, allowFallbackRegionLabel) {
  var regionKey = normalizeRegionKey(region);
  if (BASE.regions[regionKey]) return BASE.regions[regionKey];
  if (!allowFallbackRegionLabel) return null;
  return { label: region, flag: "🌐" };
}

// 按旗帜、地区标签和后缀拼出代理组名称。
function buildRegionGroupName(regionMeta, groupNameSuffix) {
  return regionMeta.flag + regionMeta.label + groupNameSuffix;
}

// 根据凭证和端点信息生成一个 MiyaIP HTTP 代理节点。
function buildMiyaProxy(miyaCredentials, proxyName, endpoint) {
  return {
    name: proxyName,
    type: "http",
    server: endpoint.server,
    port: endpoint.port,
    username: miyaCredentials.username,
    password: miyaCredentials.password,
    udp: true
  };
}

// 在按 `name` 命名的数组项中查找条目下标；未命中返回 -1。
function findNamedItemIndex(items, targetName) {
  for (var i = 0; i < items.length; i++) {
    if (items[i].name === targetName) return i;
  }
  return -1;
}

// 在按 `name` 命名的数组项中查找单个条目，复用下标查找避免重复遍历。
function findNamedItem(items, targetName) {
  var index = findNamedItemIndex(items, targetName);
  return index >= 0 ? items[index] : null;
}

// 按名称更新或插入一个完整条目，避免沿用同名旧对象。
function upsertNamedItem(items, itemDefinition) {
  var itemIndex = findNamedItemIndex(items, itemDefinition.name);
  if (itemIndex >= 0) items[itemIndex] = itemDefinition;
  else items.push(itemDefinition);
  return itemDefinition;
}

// 按名称查找单个代理节点。
function findProxyByName(proxies, proxyName) {
  return findNamedItem(proxies, proxyName);
}

// 按名称查找单个代理组。
function findProxyGroupByName(proxyGroups, groupName) {
  return findNamedItem(proxyGroups, groupName);
}

// 判断给定名称是否在节点或代理组中存在。
function hasProxyOrGroup(config, targetName) {
  return !!(
    findProxyByName(config.proxies || [], targetName) ||
    findProxyGroupByName(config["proxy-groups"] || [], targetName)
  );
}

// 收集匹配地区特征且非 MiyaIP 的节点名称列表。
function collectRegionNodeNames(proxies, regionRegex) {
  var regionNodeNames = [];
  for (var i = 0; i < proxies.length; i++) {
    var proxy = proxies[i];
    if (
      regionRegex.test(proxy.name) &&
      proxy.name.indexOf(BASE.miyaProxyNameKeyword) < 0
    ) {
      regionNodeNames.push(proxy.name);
    }
  }
  return regionNodeNames;
}

// 把地区节点列表包装成一个 `url-test` 代理组，并覆盖同名旧组。
function upsertRegionUrlTestGroup(proxyGroups, groupName, regionNodeNames) {
  upsertNamedItem(proxyGroups, {
    name: groupName,
    type: "url-test",
    proxies: regionNodeNames,
    url: BASE.urlTestProbeUrl,
    interval: 300,
    tolerance: 50
  });
}

// 把脚本生成的地区组写入 `节点选择`，同时剔除带相同后缀的旧地区组（防止地区切换后残留）。
function writeManagedGroupIntoNodeSelection(config, managedGroupName, managedGroupSuffix) {
  var nodeSelectionGroup = findProxyGroupByName(config["proxy-groups"], BASE.groupNames.nodeSelection);
  if (!nodeSelectionGroup || !nodeSelectionGroup.proxies) return;

  var nextProxyNames = [];
  for (var i = 0; i < nodeSelectionGroup.proxies.length; i++) {
    var name = nodeSelectionGroup.proxies[i];
    if (name === managedGroupName) continue;
    if (endsWithString(name, managedGroupSuffix)) continue;
    nextProxyNames.push(name);
  }
  nextProxyNames.push(managedGroupName);
  nodeSelectionGroup.proxies = uniqueStrings(nextProxyNames);
}

// 向主配置注入家宽出口和官方中转两个 MiyaIP 节点。
function writeMiyaProxies(config, miyaCredentials) {
  var miyaProxies = [
    buildMiyaProxy(miyaCredentials, BASE.nodeNames.relay, miyaCredentials.relay),
    buildMiyaProxy(
      miyaCredentials,
      BASE.nodeNames.transit,
      miyaCredentials.transit
    )
  ];

  for (var i = 0; i < miyaProxies.length; i++) {
    upsertNamedItem(config.proxies, miyaProxies[i]);
  }
}

// 仅根据订阅节点创建或修正指定地区的 `url-test` 代理组。
// 当前既用于链式跳板，也用于媒体组选区。
function writeRegionGroup(config, region, groupNameSuffix) {
  var regionMeta = resolveRegionMeta(region, false);
  if (!regionMeta) return null;

  var regionRegex = regionMeta.regex;
  var groupName = buildRegionGroupName(regionMeta, groupNameSuffix);
  var proxyGroups = config["proxy-groups"];

  var regionNodeNames = collectRegionNodeNames(config.proxies, regionRegex);
  if (regionNodeNames.length === 0) return null;

  upsertRegionUrlTestGroup(proxyGroups, groupName, regionNodeNames); // 用订阅地区节点创建或修正目标组

  return groupName;
}

// 按"首选地区 + fallback 顺序"生成实际尝试列表，首位永远保留用户首选。
function buildRegionResolutionOrder(primaryRegion, fallbackRegions) {
  var orderedRegions = [normalizeRegionKey(primaryRegion)];
  var i;
  var regionKey;
  for (i = 0; i < fallbackRegions.length; i++) {
    regionKey = normalizeRegionKey(fallbackRegions[i]);
    if (orderedRegions.indexOf(regionKey) >= 0) continue;
    orderedRegions.push(regionKey);
  }
  return orderedRegions;
}

// 按顺序尝试地区组，命中后返回实际地区与组名。
function resolveRegionGroupTarget(config, primaryRegion, fallbackRegions, groupNameSuffix, targetLabel) {
  var resolutionOrder = buildRegionResolutionOrder(primaryRegion, fallbackRegions);
  var i;
  var regionKey;
  var groupName;

  for (i = 0; i < resolutionOrder.length; i++) {
    regionKey = resolutionOrder[i];
    groupName = writeRegionGroup(config, regionKey, groupNameSuffix);
    if (groupName) {
      return { region: regionKey, target: groupName };
    }
  }

  throw createUserError(
    "未找到可用的 " +
    targetLabel +
    "，已按顺序尝试 " +
    resolutionOrder.join(" / ") +
    "，请检查订阅地区节点与命名"
  );
}

// 解析家宽链式代理前一跳应使用的脚本跳板组；首选缺失时自动按 fallback 顺序回退。
function resolveRelayTarget(config, region) {
  return resolveRegionGroupTarget(
    config,
    region,
    BASE.regionFallbackOrder.chain,
    BASE.groupNameSuffixes.relay,
    "chainRegion 节点"
  );
}

// 解析媒体应使用的普通地区组；首选缺失时自动按 fallback 顺序回退。
function resolveMediaTarget(config, region) {
  return resolveRegionGroupTarget(
    config,
    region,
    BASE.regionFallbackOrder.media,
    BASE.groupNameSuffixes.media,
    "mediaRegion 媒体节点"
  );
}

// 给家宽出口节点绑定拨号前置代理，并清理官方中转节点的拨号代理。
function writeDialerProxy(config, relayTarget) {
  var relayProxy = findProxyByName(config.proxies, BASE.nodeNames.relay);
  if (relayProxy) {
    if (relayTarget) relayProxy["dialer-proxy"] = relayTarget;
    else delete relayProxy["dialer-proxy"];
  }

  var transitProxy = findProxyByName(config.proxies, BASE.nodeNames.transit);
  if (transitProxy) delete transitProxy["dialer-proxy"]; // 官方中转节点不挂 dialer-proxy
}

// 确保存在一个承载 MiyaIP 官方中转与家宽出口的 AI 家宽出口组。
function writeChainGroup(config, region) {
  var regionMeta = resolveRegionMeta(region, true);
  var chainGroupName = buildRegionGroupName(
    regionMeta,
    BASE.groupNameSuffixes.chain
  );

  upsertNamedItem(config["proxy-groups"], {
    name: chainGroupName,
    type: "select",
    proxies: [BASE.nodeNames.transit, BASE.nodeNames.relay]
  });

  return chainGroupName;
}

// 统一解析本轮注入所需的关键目标，减少主流程里的状态分散。
// 这里会同时收敛链式跳板、AI 家宽出口和媒体组选区。
function resolveRoutingTargets(config, chainRegion, mediaRegion) {
  var relayResolution = resolveRelayTarget(config, chainRegion);
  writeManagedGroupIntoNodeSelection(config, relayResolution.target, BASE.groupNameSuffixes.relay);
  var chainGroupName = writeChainGroup(config, relayResolution.region);
  var mediaResolution = resolveMediaTarget(config, mediaRegion);
  writeManagedGroupIntoNodeSelection(config, mediaResolution.target, BASE.groupNameSuffixes.media);
  return {
    relayTarget: relayResolution.target,
    relayRegion: relayResolution.region,
    chainGroupName: chainGroupName,
    strictAiTarget: chainGroupName,
    mediaTarget: mediaResolution.target,
    mediaRegion: mediaResolution.region
  };
}

// 把拨号代理绑定和受管规则注入收口到一个装配步骤。
function writeManagedRouting(config, routingTargets, derived) {
  writeDialerProxy(config, routingTargets.relayTarget);
  writeManagedRules(
    config,
    routingTargets.strictAiTarget,
    routingTargets.mediaTarget,
    derived
  );
}

// ---------------------------------------------------------------------------
// 规则注入（去重 + 置顶）
// ---------------------------------------------------------------------------

// 提取规则的 `"TYPE,value"` 标识。
function getRuleIdentity(ruleLine) {
  var firstCommaIndex = ruleLine.indexOf(",");
  if (firstCommaIndex < 0) return null;

  var secondCommaIndex = ruleLine.indexOf(",", firstCommaIndex + 1);
  if (secondCommaIndex < 0) return null;

  return ruleLine.substring(0, secondCommaIndex);
}

// 按规则标识（TYPE,value）首次出现即保留，丢弃后续同标识行，解决跨段重复。
function dedupeRulesByIdentity(ruleLines) {
  var deduped = [];
  var seen = {};
  for (var i = 0; i < ruleLines.length; i++) {
    var identity = getRuleIdentity(ruleLines[i]);
    if (identity === null) {
      deduped.push(ruleLines[i]);
      continue;
    }
    if (seen[identity]) continue;
    seen[identity] = true;
    deduped.push(ruleLines[i]);
  }
  return deduped;
}

// 按固定优先级拼出严格 AI 规则、媒体组选区、直连保留项和链式浏览器规则。
// 浏览器进程规则刻意放在媒体 / 直连域名规则之后，避免受管浏览器压过这些更具体的匹配。
// 段内各自去重，段间顺序即优先级——首次出现的目标胜出。
function buildManagedRules(strictAiTarget, mediaTarget, derived) {
  var concatenated = buildStrictChainRules(strictAiTarget, derived)
    .concat(buildMediaRules(mediaTarget, derived))
    .concat(buildDirectRules(derived))
    .concat(buildBrowserChainRules(strictAiTarget, derived));
  return dedupeRulesByIdentity(concatenated);
}

// 把规则数组转换成便于查询的规则标识表。
function buildRuleIdentityLookup(ruleLines) {
  var ruleIdentityLookup = {};
  for (var i = 0; i < ruleLines.length; i++) {
    var ruleIdentity = getRuleIdentity(ruleLines[i]);
    if (ruleIdentity) ruleIdentityLookup[ruleIdentity] = true;
  }
  return ruleIdentityLookup;
}

// 过滤掉与管理规则命中同一标识的原始订阅规则。
function filterConflictingRules(ruleLines, blockedRuleIdentities) {
  var filteredRules = [];
  for (var i = 0; i < ruleLines.length; i++) {
    var ruleIdentity = getRuleIdentity(ruleLines[i]);
    if (ruleIdentity === null || !blockedRuleIdentities[ruleIdentity]) {
      filteredRules.push(ruleLines[i]);
    }
  }
  return filteredRules;
}

// 将原始规则拆成"非 MATCH 兜底"与"MATCH 兜底"两段，保留后者在末尾以不破坏 Clash 兜底语义。
function splitMatchFallback(ruleLines) {
  var nonMatch = [];
  var matchTail = [];
  for (var i = 0; i < ruleLines.length; i++) {
    var line = ruleLines[i];
    if (line.indexOf(BASE.rulePrefixes.match) === 0) {
      matchTail.push(line);
    } else {
      nonMatch.push(line);
    }
  }
  return { nonMatch: nonMatch, matchTail: matchTail };
}

// 注入管理规则并整体置顶，同时保证 MATCH 兜底始终在末尾。
function writeManagedRules(
  config,
  strictAiTarget,
  mediaTarget,
  derived
) {
  var managedRules = buildManagedRules(strictAiTarget, mediaTarget, derived);
  var managedRuleIdentities = buildRuleIdentityLookup(managedRules);
  var remainingRules = filterConflictingRules(config.rules, managedRuleIdentities);
  var split = splitMatchFallback(remainingRules);

  // 管理规则置顶 → 剩余非兜底规则 → MATCH 兜底永远在最后。
  config.rules = managedRules.concat(split.nonMatch).concat(split.matchTail);
}

// 批量追加指定类型规则。
function appendTypedRules(ruleLines, values, ruleType, target) {
  for (var i = 0; i < values.length; i++) {
    ruleLines.push(ruleType + "," + values[i] + "," + target);
  }
}

// 批量追加 `DOMAIN-SUFFIX` 规则。
function appendSuffixRules(ruleLines, domains, target) {
  var suffixes = [];
  for (var i = 0; i < domains.length; i++) {
    suffixes.push(toSuffix(domains[i]));
  }
  appendTypedRules(ruleLines, suffixes, "DOMAIN-SUFFIX", target);
}

// 批量追加 `PROCESS-NAME` 规则。
function appendProcessRules(ruleLines, processNames, target) {
  appendTypedRules(ruleLines, processNames, "PROCESS-NAME", target);
}

// 返回应纳入严格 AI 路由的进程分组；AI CLI 固定走 chainRegion。
function buildStrictProcessGroups(derived) {
  return [derived.processNames.aiApps, derived.processNames.aiCli];
}

// 按当前用户选项返回应纳入链式代理的浏览器进程分组。
function buildBrowserChainProcessGroups(derived) {
  if (!shouldRouteBrowserToChain()) return [];
  return [derived.processNames.browser];
}

// 生成进家宽出口的所有规则：受管 AI 进程 + AI CLI + 全部 chain 域名。
// 段内不去重——跨段去重由 `buildManagedRules` 末端统一完成。
function buildStrictChainRules(strictAiTarget, derived) {
  var ruleLines = [];
  var processGroups = buildStrictProcessGroups(derived);
  for (var i = 0; i < processGroups.length; i++) {
    appendProcessRules(ruleLines, processGroups[i], strictAiTarget);
  }
  appendSuffixRules(ruleLines, derived.patterns.chain, strictAiTarget);
  return ruleLines;
}

// 生成链式浏览器规则，承载按应用名强制分流的 AI 浏览器进程。
function buildBrowserChainRules(browserTarget, derived) {
  var ruleLines = [];
  var processGroups = buildBrowserChainProcessGroups(derived);
  for (var i = 0; i < processGroups.length; i++) {
    appendProcessRules(ruleLines, processGroups[i], browserTarget);
  }
  return ruleLines;
}

// 生成媒体组选区规则，只承载媒体域名。
function buildMediaRules(mediaTarget, derived) {
  var ruleLines = [];
  appendSuffixRules(ruleLines, derived.patterns.media, mediaTarget);
  return ruleLines;
}

// 生成所有 DIRECT 规则：固定 IP-CIDR 网段（带 `no-resolve`）+ 全部 direct 模式。
function buildDirectRules(derived) {
  var ruleLines = [];
  for (var i = 0; i < derived.networkRules.direct.length; i++) {
    var r = derived.networkRules.direct[i];
    ruleLines.push(r.type + "," + r.value + "," + r.target + ",no-resolve");
  }
  appendSuffixRules(ruleLines, derived.patterns.direct, BASE.ruleTargets.direct);
  return ruleLines;
}

// 基于预构建的规则行查找表 O(1) 断言管理规则是否命中预期目标。
function assertManagedRuleTarget(ruleLineLookup, type, value, target) {
  var ruleLine = type + "," + value + "," + target;
  if (ruleLineLookup[ruleLine]) return;
  throw createUserError(
    "关键规则未正确写入: " + ruleLine + "，请检查 chainRegion / mediaRegion 和订阅代理组"
  );
}

// 判断两个字符串数组集合相等（无视顺序、不允许重复）。
function haveSameStringSet(values, expectedValues) {
  if (values.length !== expectedValues.length) return false;
  var lookup = buildStringLookup(values);
  for (var i = 0; i < expectedValues.length; i++) {
    if (!lookup[expectedValues[i]]) return false;
  }
  return true;
}

// 断言三元目标关系：strictAi = chain，media ≠ chain，relay ≠ chain。
function assertRoutingTargetCoherence(routingTargets) {
  if (routingTargets.strictAiTarget !== routingTargets.chainGroupName) {
    throw createUserError(
      "域外 AI 与支撑平台未直接指向当前 chainRegion 出口，请检查 chainRegion 或代理组注入逻辑"
    );
  }
  if (routingTargets.mediaTarget === routingTargets.chainGroupName) {
    throw createUserError(
      "媒体组选区错误复用了家宽出口组，请检查 mediaRegion 或媒体组选区注入逻辑"
    );
  }
  if (routingTargets.relayTarget === routingTargets.chainGroupName) {
    throw createUserError(
      "当前 chainRegion 跳板错误复用了家宽出口组，请检查地区代理组复用逻辑"
    );
  }
}

// 断言跳板组与媒体组在节点/代理组中均存在。
function assertRoutingTargetsExist(config, routingTargets) {
  if (!hasProxyOrGroup(config, routingTargets.relayTarget)) {
    throw createUserError(
      "当前 chainRegion 跳板不存在，请检查 chainRegion 和订阅代理组"
    );
  }
  if (!hasProxyOrGroup(config, routingTargets.mediaTarget)) {
    throw createUserError(
      "当前 mediaRegion 媒体组选区不存在，请检查 mediaRegion 和订阅代理组"
    );
  }
}

// 断言家宽出口与官方中转节点的 dialer-proxy 状态。
function assertDialerBindings(config, routingTargets) {
  var relayProxy = findProxyByName(config.proxies, BASE.nodeNames.relay);
  if (!relayProxy || relayProxy["dialer-proxy"] !== routingTargets.relayTarget) {
    throw createUserError(
      "家宽出口节点未正确绑定到当前 chainRegion 跳板，请检查代理链路注入逻辑"
    );
  }
  var transitProxy = findProxyByName(config.proxies, BASE.nodeNames.transit);
  if (!transitProxy || transitProxy["dialer-proxy"]) {
    throw createUserError(
      "官方中转节点状态异常，请检查 MiyaIP 凭证.js 和节点注入逻辑"
    );
  }
}

// 断言链式出口组 shape 与成员集合。
function assertChainGroupShape(config, chainGroupName) {
  var expectedMembers = [BASE.nodeNames.transit, BASE.nodeNames.relay];
  var chainGroup = findProxyGroupByName(config["proxy-groups"], chainGroupName);
  if (
    !chainGroup ||
    chainGroup.type !== "select" ||
    !haveSameStringSet(chainGroup.proxies || [], expectedMembers)
  ) {
    throw createUserError(
      "当前 chainRegion 的家宽出口组内容异常，请检查代理组注入逻辑"
    );
  }
}

// 断言媒体组 shape：必须是 url-test、非空、且不含 MiyaIP 节点。
function assertMediaGroupShape(config, mediaTarget) {
  var mediaGroup = findProxyGroupByName(config["proxy-groups"], mediaTarget);
  if (
    !mediaGroup ||
    mediaGroup.type !== "url-test" ||
    !mediaGroup.proxies ||
    mediaGroup.proxies.length === 0 ||
    mediaGroup.proxies.indexOf(BASE.nodeNames.relay) >= 0 ||
    mediaGroup.proxies.indexOf(BASE.nodeNames.transit) >= 0
  ) {
    throw createUserError(
      "当前 mediaRegion 的媒体组选区内容异常，请检查媒体组选区注入逻辑"
    );
  }
}

// 逐条断言一批校验目标在最终规则里命中预期 target。
function assertRuleTargetBatch(ruleLineLookup, validationTargets, expectedTarget) {
  for (var i = 0; i < validationTargets.length; i++) {
    assertManagedRuleTarget(
      ruleLineLookup,
      validationTargets[i].type,
      validationTargets[i].value,
      expectedTarget
    );
  }
}

// 验证关键 AI 家宽、链式浏览器与媒体组选区规则目标，避免静默泄漏或错误地区回退。
function validateManagedRouting(config, routingTargets) {
  assertRoutingTargetCoherence(routingTargets);
  assertRoutingTargetsExist(config, routingTargets);
  assertDialerBindings(config, routingTargets);
  assertChainGroupShape(config, routingTargets.chainGroupName);
  assertMediaGroupShape(config, routingTargets.mediaTarget);

  var ruleLineLookup = buildStringLookup(config.rules);
  assertRuleTargetBatch(ruleLineLookup, buildStrictValidationTargets(), routingTargets.strictAiTarget);
  assertRuleTargetBatch(ruleLineLookup, buildBrowserValidationTargets(), routingTargets.strictAiTarget);
  assertRuleTargetBatch(ruleLineLookup, buildMediaValidationTargets(), routingTargets.mediaTarget);
}

// ---------------------------------------------------------------------------
// 主流程入口
// ---------------------------------------------------------------------------

// 读取并移除注入到 `config._miya` 的 MiyaIP 凭证。
function takeMiyaCredentials(config) {
  if (!config._miya) {
    throw createUserError(
      "缺少 config._miya，请确保 MiyaIP 凭证.js 已启用且排序在本脚本之前"
    );
  }
  var miyaCredentials = config._miya;
  delete config._miya; // 防止凭证输出到最终配置
  return miyaCredentials;
}

// 按初始化、DNS/Sniffer、代理链路、规则注入、最终校验的顺序装配输出配置。
// `derivedOverride` 可选；测试可传入 stub 以隔离源数据依赖，生产路径默认使用模块级 `DERIVED`。
function main(config, derivedOverride) {
  var derived = derivedOverride || DERIVED;
  var miyaCredentials = takeMiyaCredentials(config); // 先取出并隐藏凭证
  var routingTargets;

  writeContainers(config); // 初始化基础容器
  writeDnsAndSniffer(config, derived); // 先写 DNS 与 Sniffer
  writeMiyaProxies(config, miyaCredentials); // 注入 MiyaIP 节点

  routingTargets = resolveRoutingTargets(
    config,
    USER_OPTIONS.chainRegion,
    USER_OPTIONS.mediaRegion
  ); // 解析链路目标
  writeManagedRouting(config, routingTargets, derived); // 写入拨号与规则
  validateManagedRouting(config, routingTargets); // 校验关键目标

  return config;
}
