// 家宽出口覆写 — Clash Verge / Clash Party 单文件脚本（ES5）
// 填写下方 USER_OPTIONS / RESIDENTIAL_CREDENTIALS 后导入覆写页启用。
// @version 14.41

// ===========================================================================
// 用户配置
// ===========================================================================

var USER_OPTIONS = {
  enabled: true, // false=旁路透传
  overrideMode: "merged", // merged | dns-sniffer-only
  rejectQuic: true, // false=允许 HTTP/3
  dnsListen: "127.0.0.1:1053", // 空串回退此默认
};

var RESIDENTIAL_CREDENTIALS = {
  username: "",
  password: "",
  transit: { server: "", port: 8001 },
  homeStatic: { server: "", port: 8022 },
};

// ===========================================================================
// 1. 共享工具函数
// ===========================================================================

// 稳定去重，保留首次出现顺序。
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

// 字符串数组 → 查表对象。
function buildStringLookup(values) {
  var lookup = {};
  for (var i = 0; i < values.length; i++) {
    lookup[values[i]] = true;
  }
  return lookup;
}

// `+.domain` → 规则用裸后缀。
function toSuffix(domainPattern) {
  return domainPattern.indexOf("+.") === 0
    ? domainPattern.substring(2)
    : domainPattern;
}

function createUserError(message) {
  return new Error(message);
}

// DNS listen；空值回退 127.0.0.1:1053。
function resolveDnsListen() {
  var listen = USER_OPTIONS.dnsListen;
  if (listen === undefined || listen === null || listen === "") {
    return "127.0.0.1:1053";
  }
  if (typeof listen !== "string") {
    throw createUserError("USER_OPTIONS.dnsListen 必须是字符串");
  }
  return listen;
}

// rejectQuic 默认开；显式 false 才关。
function shouldRejectQuic() {
  return USER_OPTIONS.rejectQuic !== false;
}

// ===========================================================================
// 2. DNS / Sniffer 策略模块
// ===========================================================================

var DNS_SNIFFER_MODULE = (function () {
  // --- 基础常量 ---

  // 模块内 DNS 常量。
  var BASE = {
    ruleTargets: { direct: "DIRECT" },
    dns: {
      overseas: ["https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"],
      domestic: ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
      domesticGeosite: "geosite:cn",
      overseasGeosite: "geosite:geolocation-!cn",
    },
  };
  // overseas + Quad9
  BASE.dns.fallback = BASE.dns.overseas.concat(["https://dns.quad9.net/dns-query"]);

  // --- 域名模式数据 ---

  // 域名桶只用 `+.domain`；route/dns/sniffer 由 POLICY 注入。

  // --- Fake-IP Filter · 需真实 IP ---
  // NTP / STUN / 游戏联机 / 路由管理等不进 fake-ip。
  var FAKE_IP_BYPASS = {
    localNetwork: [
      "+.lan",
      "+.local",
      "+.localhost",
      "localhost.ptlogin2.qq.com",
    ],
    timeSync: [
      "time.*.com",
      "time.*.gov",
      "time.*.edu.cn",
      "time.*.apple.com",
      "ntp.*.com",
      "ntp1.aliyun.com",
      "+.pool.ntp.org",
    ],
    connectivityTest: ["+.msftconnecttest.com", "+.msftncsi.com"],
    gamingRealtime: [
      "+.srv.nintendo.net",
      "+.stun.playstation.net",
      "xbox.*.microsoft.com",
      "+.xboxlive.com",
      "+.battlenet.com.cn",
      "+.blzstatic.cn",
    ],
    stunRealtime: ["stun.*.*", "stun.*.*.*"],
    homeRouter: [
      "+.router.asus.com",
      "+.linksys.com",
      "+.tplinkwifi.net",
      "+.xiaoqiang.net",
    ],
  };

  // --- Residential Exit · 家宽出口 ---
  var RESIDENTIAL_EXIT = {
    support: {
      // Google/Microsoft 不再整树进严管：日常邮件/搜索/网盘走 GFW/默认组。
      // OAuth 核心 + 登录旁路静态域进严管，避免 Chrome「用 Google 登 Claude/ChatGPT」时
      // 主站家宽、consent/gstatic 走机房导致 Arkose/会话指纹分裂。
      google_auth: [
        "+.accounts.google.com",
        "+.consent.google.com", // OAuth consent 页（非整树 google.com）
        "+.oauth2.googleapis.com",
        "+.www.googleapis.com", // 部分 OAuth token / userinfo
        "+.apis.google.com", // 登录页 JS / GIS
        "+.gstatic.com", // consent / 登录静态资源
        "+.googleusercontent.com", // 登录头像 / 部分 OAuth 资源
        "+.accounts.youtube.com", // 偶发 OAuth 联动
      ],
      microsoft_auth: [
        "+.microsoftonline.com",
        "+.msftauth.net",
        "+.msauth.net",
        // 不含 msecnd.net：微软通用 CDN 过宽，会把大量非登录流量绑进家宽。
        "+.login.live.com",
        "+.login.microsoft.com",
        "+.account.microsoft.com",
      ],
      // Antigravity / VS 扩展更新（与 Gemini IDE 同账号体系）。
      microsoft_developer: ["+.visualstudio.com", "+.vsassets.io"],
      // Claude Code / Codex 拉依赖时出口需与主站一致，避免 CLI 风控分裂。
      developer_git_hosts: ["+.github.com", "+.githubusercontent.com"],
      developer_package_registries: [
        "+.npmjs.org",
        "+.npmjs.com",
        "+.pypi.org",
        "+.pythonhosted.org",
      ],
      // 验防封出口是否生效（勿改 DIRECT）。
      egress_check: ["+.ipinfo.io", "+.ip.sb"],
    },
    // 严管 AI：一线账号服务。OpenRouter / Mistral / HF / Cursor 不进严管。
    ai: {
      anthropic: [
        "+.claude.ai",
        "+.claude.com",
        "+.anthropic.com",
        "+.claudeusercontent.com",
      ],
      openai: [
        "+.openai.com",
        "+.chatgpt.com",
        "+.chat.com",
        "+.sora.com",
        "+.oaiusercontent.com",
        "+.oaistatic.com",
        // azureedge / azurefd / cdn.cloudflare 由 CDN.cloud 覆盖。
        "+.openaicom.imgix.net",
        "+.openaicomproductionae4b.blob.core.windows.net",
        "+.chatgpt.livekit.cloud",
        "+.challenges.cloudflare.com",
      ],
      // Gemini + Antigravity：Web / API / IDE 同一账号体系。
      gemini_antigravity: [
        "+.gemini.google.com",
        "+.aistudio.google.com",
        "+.ai.google.dev",
        "+.aiplatform.googleapis.com",
        "+.generativelanguage.googleapis.com",
        "+.ai.google",
        "+.notebooklm.google",
        "+.antigravity.google",
        "+.antigravity-ide.com",
        "+.cloudcode-pa.googleapis.com",
        "+.daily-cloudcode-pa.googleapis.com",
        "+.daily-cloudcode-pa.sandbox.googleapis.com",
      ],
      perplexity: ["+.perplexity.ai", "+.perplexitycdn.com"],
      meta: ["+.meta.ai"],
      xai: ["+.x.ai", "+.grok.com"],
    },
    // 登录验证 / 订阅支付 / feature flag：必须与 AI 主站同出口。
    integrations: {
      antibot: [
        "+.arkoselabs.com",
        "+.funcaptcha.com",
        "+.recaptcha.net",
      ],
      auth_providers: ["+.auth0.com", "+.auth0cdn.com", "+.clerk.com"],
      payments: ["+.stripe.com", "+.stripe.network"],
      telemetry: [
        "+.statsig.com",
        "+.statsigapi.net",
        "+.featuregates.org",
        "+.featureassets.org",
      ],
    },
    apps: {
      ai: {
        // 桌面 App / IDE；Gemini+Antigravity 同策略；不含 Cursor。
        apps: [
          "Claude",
          "ChatGPT",
          "Codex",
          "Perplexity",
          "Gemini",
          "Antigravity",
          "Antigravity IDE",
        ],
        helperSuffixes: ["Helper"],
        exact: [
          "ChatGPTHelper",
          "ChatGPT.exe",
          "ChatGPT Helper (Renderer)",
          "ChatGPT Helper (GPU)",
          "ChatGPT Helper (Plugin)",
          "Claude.exe",
          "Claude Helper (Renderer)",
          "Claude Helper (GPU)",
          "Claude Helper (Plugin)",
          "Codex.exe",
          "Codex Helper (Renderer)",
          "Codex Helper (GPU)",
          "Codex Helper (Plugin)",
          "Perplexity.exe",
          "Perplexity Helper (Renderer)",
          "Perplexity Helper (GPU)",
          "Perplexity Helper (Plugin)",
          "Gemini.exe",
          "Gemini Helper (Renderer)",
          "Gemini Helper (GPU)",
          "Gemini Helper (Plugin)",
          "Antigravity.exe",
          "Antigravity Helper (Renderer)",
          "Antigravity Helper (GPU)",
          "Antigravity Helper (Plugin)",
          "Antigravity IDE.exe",
          "Antigravity IDE Helper (Renderer)",
          "Antigravity IDE Helper (GPU)",
          "Antigravity IDE Helper (Plugin)",
          // Antigravity IDE language server / tools
          "language_server",
          "language_server.exe",
          "language_server_macos_arm",
          "language_server_macos_x64",
          "language_server_linux_x64",
          "language_server_windows_x64.exe",
          "antigravity_tools",
        ],
        cli: [
          "claude",
          "claude.exe",
          "codex",
          "codex.exe",
          "codex-aarch64-apple-darwin",
          "codex-x86_64-apple-darwin",
          "codex-aarch64-unknown-linux-musl",
          "codex-x86_64-unknown-linux-musl",
          // Gemini CLI + Antigravity CLI（agy）
          "gemini",
          "gemini.exe",
          "agy",
          "agy.exe",
          "antigravity",
          "antigravity.exe",
        ],
      },
      // AI 浏览器：仅 Comet / Dia / Atlas；Chrome / Edge / Safari 等不列入。
      browser: {
        apps: ["Comet", "Dia", "Atlas"],
        helperSuffixes: [
          "Helper",
          "Helper (Renderer)",
          "Helper (GPU)",
          "Helper (Plugin)",
          "Helper (Alerts)",
        ],
      },
    },
  };

  // --- Global Default · 域外默认代理 ---
  var CDN = {
    doh: {
      core: ["+.dns.google", "+.cloudflare-dns.com", "+.quad9.net"],
    },
    cloud: {
      // 仅 OpenAI/Claude 等常用云 CDN 后缀；Akamai/Fastly 过宽，不绑防封出口。
      cloudflare: ["+.cdn.cloudflare.net"],
      aws: ["+.amazonaws.com", "+.awsstatic.com", "+.cloudfront.net"],
      azure_cdn: ["+.azureedge.net", "+.azurefd.net"],
    },
  };

  // --- Media · 其他调度（解锁出口，不走家宽） ---
  // 只维护需地区解锁的主流站；LinkedIn / Slack / Signal / SoundCloud 等落到 GFW/MATCH。
  var MEDIA = {
    video: {
      youtube: [
        "+.youtube.com",
        "+.youtu.be",
        "+.googlevideo.com",
        "+.ytimg.com",
        "+.youtube-nocookie.com",
      ],
      netflix: [
        "+.netflix.com",
        "+.netflix.net",
        "+.nflxvideo.net",
        "+.nflxso.net",
        "+.nflximg.net",
        "+.nflxext.com",
      ],
      disney_plus: [
        "+.disneyplus.com",
        "+.disney-plus.net",
        "+.dssott.com",
        "+.bamgrid.com",
      ],
      hbo_max: ["+.max.com", "+.hbomax.com", "+.hbomaxcdn.com"],
      prime_video: [
        "+.primevideo.com",
        "+.aiv-cdn.net",
        "+.aiv-delivery.net",
      ],
      twitch: ["+.twitch.tv", "+.ttvnw.net", "+.jtvnw.net"],
    },
    music: {
      spotify: ["+.spotify.com", "+.scdn.co", "+.spotifycdn.com"],
    },
    social: {
      twitter: ["+.twitter.com", "+.x.com", "+.twimg.com", "+.t.co"],
      meta: [
        "+.facebook.com",
        "+.fbcdn.net",
        "+.fb.com",
        "+.facebook.net",
        "+.instagram.com",
        "+.cdninstagram.com",
        "+.threads.net",
      ],
      reddit: ["+.reddit.com", "+.redditmedia.com", "+.redditstatic.com"],
      tiktok: [
        "+.tiktok.com",
        "+.tiktokcdn.com",
        "+.tiktokv.com",
        "+.ibyteimg.com",
      ],
    },
    im: {
      telegram: ["+.telegram.org", "+.t.me"],
      discord: [
        "+.discord.com",
        "+.discord.gg",
        "+.discordapp.com",
        "+.discordapp.net",
        "+.discord.media",
      ],
      line: [
        "+.line.me",
        "+.line-apps.com",
        "+.line-scdn.net",
        "+.line-cdn.net",
      ],
      whatsapp: ["+.whatsapp.com", "+.whatsapp.net"],
    },
  };

  // --- CN Direct · 境内直连 ---
  var CN = {
    ai: {
      // 阿里云通义等子域由 CN.cloud 的 aliyun(cs).com 覆盖，不在此重复。
      modelscope: ["+.modelscope.cn"],
      moonshot: ["+.moonshot.cn"],
      zhipu: ["+.chatglm.cn", "+.zhipuai.cn", "+.bigmodel.cn"],
      siliconflow: ["+.siliconflow.cn"],
      deepseek: [
        "+.deepseek.com", // api / platform / chat 全部子域
      ],
      doubao: [
        "+.doubao.com", // 字节豆包
        "+.volcengineapi.com", // 火山方舟（豆包模型 API）
      ],
      minimax: [
        "+.minimaxi.com", // MiniMax 域内域名
        "+.hailuoai.com", // 海螺 AI
      ],
      baichuan: ["+.baichuan-ai.com"],
      stepfun: [
        "+.stepfun.com", // 阶跃星辰
      ],
    },
    office: {
      tencent_messaging_and_collab: [
        "+.qq.com", // 覆盖 docs/weixin/exmail/work.weixin 等 qq 子域
        "+.qqmail.com",
        "+.meeting.tencent.com",
      ],
      alibaba_productivity: [
        "+.dingtalk.com",
        "+.dingtalkapps.com",
        "+.aliyundrive.com",
        "+.quark.cn",
        "+.teambition.com",
      ],
      bytedance_productivity: [
        "+.feishu.cn",
        "+.feishu.net",
        "+.feishucdn.com",
        "+.larksuite.com",
        "+.larkoffice.com",
      ],
      wps_productivity: ["+.wps.cn", "+.wps.com", "+.kdocs.cn", "+.kdocs.com"],
    },
    cloud: {
      alibaba_cloud: ["+.aliyun.com", "+.aliyuncs.com", "+.alibabacloud.com"],
      tencent_cloud: [
        "+.tencentcloud.com",
        "+.cloud.tencent.com",
        "+.qcloud.com",
      ],
      bytedance_cloud: ["+.volcengine.com", "+.volces.com"],
      huawei_cloud: [
        "+.myhuaweicloud.com",
        "+.huaweicloud.com",
        "+.huaweicloud.cn",
      ],
      baidu_cloud_and_cdn: ["+.baidubce.com", "+.bcebos.com", "+.bdstatic.com"],
      jd_cloud: ["+.jdcloud.com", "+.jcloudcs.com"],
      qiniu_cdn: ["+.qiniu.com", "+.qbox.me", "+.qiniucdn.com"],
      upyun: ["+.upyun.com", "+.upaiyun.com"],
      wangsu_cdn: ["+.wangsu.com", "+.wscdns.com", "+.wscloudcdn.com"],
      ctyun: ["+.ctyun.cn"],
      ksyun: ["+.ksyun.com"],
    },
    // 域内消费类高频站点；放 DIRECT 既走最近 CN CDN，也避免占用代理带宽。
    consumer: {
      baidu: [
        "+.baidu.com", // 搜索 / 网盘 / 地图统一入口
        "+.bdimg.com", // 百度图片站静态资源
      ],
      bilibili: [
        "+.bilibili.com",
        "+.hdslb.com", // B 站全站静态 / 图片 CDN
        "+.biliapi.net",
        "+.biliapi.com",
        "+.bilivideo.com", // 视频流分发
        "+.bilicdn1.com",
        "+.biligame.com",
      ],
      weibo_and_sina: [
        "+.weibo.com",
        "+.weibo.cn",
        "+.weibocdn.com",
        "+.sinaimg.cn", // Weibo 图片 / 视频 CDN
        "+.sina.com.cn",
      ],
      zhihu: [
        "+.zhihu.com",
        "+.zhimg.com", // 知乎静态资源
      ],
      xiaohongshu: ["+.xiaohongshu.com", "+.xhscdn.com"],
      douyin_and_kuaishou: [
        "+.douyin.com", // 抖音（与海外 TikTok 不冲突）
        "+.douyinpic.com",
        "+.douyincdn.com",
        "+.kuaishou.com",
        "+.gifshow.com", // 快手早期域 / 静态资源
        "+.yximgs.com", // 快手图片 CDN
      ],
      netease: [
        "+.163.com", // 含网易邮箱 / 网易云音乐 / 新闻
        "+.126.com",
        "+.netease.com",
      ],
      video_streaming: [
        "+.iqiyi.com",
        "+.iqiyipic.com",
        "+.youku.com",
        "+.mgtv.com",
        "+.sohu.com",
      ],
      e_commerce: [
        "+.taobao.com",
        "+.tbcdn.cn",
        "+.taobaocdn.com",
        "+.tmall.com",
        "+.jd.com",
        "+.360buyimg.com", // 京东图片 CDN
        "+.pinduoduo.com",
        "+.yangkeduo.com", // 拼多多前端域
      ],
      local_services: ["+.meituan.com", "+.meituan.net", "+.dianping.com"],
      gaming: [
        "+.mihoyo.com", // 米哈游国服（原神 / 星穹铁道）；hoyoverse.com 走默认
      ],
    },
  };

  // --- Local Direct · 本地与推送直连 ---
  var LOCAL = {
    // push.apple.com 由 OVERSEAS.special.apple 的 +.apple.com 覆盖，不在此重复。
    local_and_push: [
      "+.lan",
      "+.local",
      "+.localhost",
      "+.home.arpa", // RFC 8375 家庭网络保留域
    ],
  };

  // --- Overseas Direct · 域外 DoH + 直连 ---
  var OVERSEAS = {
    special: {
      apple: {
        core: ["+.apple.com", "+.icloud.com"],
        content: [
          "+.icloud-content.com",
          "+.mzstatic.com",
          "+.cdn-apple.com",
          "+.aaplimg.com",
        ],
        services: ["+.apple-cloudkit.com"],
      },
    },
    global: {
      // 域内应用，但使用域外 DoH 解析以避免域内 DNS 返回错误结果。
      cnApps: {
        immersive_translate: ["+.immersivetranslate.com"],
        mineru: ["+.mineru.org.cn", "+.openxlab.org.cn"],
      },
      apps: {
        tailscale: ["+.tailscale.com", "+.tailscale.io", "+.ts.net"],
        zerotier: [
          "+.zerotier.com", // ZeroTier P2P，定位与 Tailscale 类似
        ],
        plex: [
          "+.plex.tv",
          "+.plex.direct", // Plex 客户端直连家用服务器走 plex.direct 通配子域
        ],
        synology: [
          "+.synology.com",
          "+.quickconnect.to", // Synology QuickConnect 中继
        ],
        typeless: ["+.typeless.com"],
        clash_vpn: ["+.51feitu.com", "+.lovetutujiejie.com"],
      },
    },
  };

  // --- DNS Only · 仅解析例外 ---
  // 这些域名只进入 nameserver-policy，不生成分流规则。
  // 用于修正 geosite 大类未覆盖或解析质量异常的个别站点。
  var DNS_ONLY = {
    domestic: {
      cn_registry_and_public: ["+.cnnic.cn", "+.12306.cn"],
    },
    overseas: {
      internet_standards: ["+.iana.org", "+.ietf.org"],
    },
  };

  // --- Network Direct · 网络地址直连 ---
  // 私有 / 链路本地 / CGNAT / Tailscale ULA 都走 DIRECT，避免被无意中走代理。
  var NETWORK = {
    direct: [
      // RFC 1918 私有网络
      { type: "IP-CIDR", value: "10.0.0.0/8", target: BASE.ruleTargets.direct },
      {
        type: "IP-CIDR",
        value: "172.16.0.0/12",
        target: BASE.ruleTargets.direct,
      },
      {
        type: "IP-CIDR",
        value: "192.168.0.0/16",
        target: BASE.ruleTargets.direct,
      },
      // 链路本地
      {
        type: "IP-CIDR",
        value: "169.254.0.0/16",
        target: BASE.ruleTargets.direct,
      },
      // CGNAT (RFC 6598)；含 Tailscale 所用 100.x 段（含 magic DNS 100.100.100.100）
      {
        type: "IP-CIDR",
        value: "100.64.0.0/10",
        target: BASE.ruleTargets.direct,
      },
      // IPv6 ULA + 链路本地（含 Tailscale fd7a:115c:a1e0::/48）
      { type: "IP-CIDR6", value: "fc00::/7", target: BASE.ruleTargets.direct },
      { type: "IP-CIDR6", value: "fe80::/10", target: BASE.ruleTargets.direct },
    ],
  };

  // 端到端样本：domains / processNames / cliNames。
  // 加载期覆盖检查 + 运行期 target 校验 + tests 消费。
  var EXPECTED_ROUTES = {
    toResidential: {
      domains: [
        "claude.ai",
        "chatgpt.com",
        "chat.com",
        "azureedge.net", // OpenAI Azure CDN 由 CDN.cloud 覆盖进支撑
        "chatgpt.livekit.cloud",
        "challenges.cloudflare.com",
        "gemini.google.com",
        "aistudio.google.com",
        "aiplatform.googleapis.com",
        "antigravity.google",
        "antigravity-ide.com",
        "cloudcode-pa.googleapis.com",
        "daily-cloudcode-pa.googleapis.com",
        "daily-cloudcode-pa.sandbox.googleapis.com",
        "perplexity.ai",
        "accounts.google.com",
        "consent.google.com",
        "gstatic.com",
        "apis.google.com",
        "googleusercontent.com",
        "meta.ai",
        "grok.com",
        "arkoselabs.com",
        "stripe.com",
        "statsig.com",
        "ipinfo.io",
        "githubusercontent.com",
        "npmjs.org",
      ],
      processNames: [
        "Claude",
        "Claude.exe",
        "ChatGPT",
        "ChatGPT Helper (Renderer)",
        "Codex",
        "Codex.exe",
        "Perplexity",
        "Perplexity Helper (Renderer)",
        "Gemini",
        "Gemini Helper (Renderer)",
        "Antigravity",
        "Antigravity IDE",
        "language_server",
      ],
      cliNames: [
        "claude",
        "claude.exe",
        "codex",
        "codex.exe",
        "codex-aarch64-apple-darwin",
        "gemini",
        "gemini.exe",
        "agy",
        "antigravity",
      ],
    },
    toMedia: {
      domains: [
        "youtube.com",
        "netflix.com",
        "x.com",
        "twitch.tv",
        "spotify.com",
        "discord.com",
        "line.me",
        "whatsapp.com",
      ],
    },
  };

  // --- 模块内工具函数 ---

  // 合并多组字符串并去重。
  function mergeStringGroups(groups) {
    var mergedValues = [];
    for (var i = 0; i < groups.length; i++) {
      mergedValues.push.apply(mergedValues, groups[i]);
    }
    return uniqueStrings(mergedValues);
  }

  // 展开 App 主进程 / helper / 精确进程名。
  function expandProcessNamesWithHelpers(
    appNames,
    helperSuffixes,
    exactProcessNames,
  ) {
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

  // 差集，保留原顺序。
  function excludeStrings(values, excludedValues) {
    var filteredValues = [];
    var excludedLookup = buildStringLookup(excludedValues);
    for (var i = 0; i < values.length; i++) {
      if (excludedLookup[values[i]]) continue;
      filteredValues.push(values[i]);
    }
    return uniqueStrings(filteredValues);
  }

  // `+.domain` 形状：标签字母数字连字符，禁 `*` / 连续点 / 首尾点。
  var PATTERN_SHAPE =
    /^\+\.[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;

  // 断言全部为合法 `+.domain`。
  function assertPatternsHavePlusPrefix(patterns) {
    for (var i = 0; i < patterns.length; i++) {
      if (!PATTERN_SHAPE.test(patterns[i])) {
        throw createUserError(
          "pattern 形状非法（应为 +.domain）: " + patterns[i],
        );
      }
    }
  }

  // ES5 endsWith。
  function endsWithString(str, suffix) {
    if (suffix.length > str.length) return false;
    return str.lastIndexOf(suffix) === str.length - suffix.length;
  }

  // 分组模式展平去重。
  function flattenGroupedPatterns(groupedPatterns) {
    var flattenedPatterns = [];
    Object.keys(groupedPatterns).forEach(function (groupName) {
      flattenedPatterns.push.apply(
        flattenedPatterns,
        groupedPatterns[groupName],
      );
    });
    return uniqueStrings(flattenedPatterns);
  }
  // --- 策略表（POLICY）与派生分类 ---

  // POLICY：域名模式权威源。字段 key/patterns/route/dnsZone/sniffer/fakeIpBypass。
  // 下游均从此投影；direct 优先于 residential/media；fallback-filter 固定 geoip+gfw。
  function buildPolicy() {
    return [
      // --- residential · 走家宽出口 ---
      {
        key: "residential.support",
        patterns: flattenGroupedPatterns(RESIDENTIAL_EXIT.support),
        route: "residential.support",
        dnsZone: "overseas",
        sniffer: "force",
      },
      {
        key: "residential.ai",
        patterns: flattenGroupedPatterns(RESIDENTIAL_EXIT.ai),
        route: "residential.ai",
        dnsZone: "overseas",
        sniffer: "force",
      },
      {
        key: "residential.integrations",
        patterns: flattenGroupedPatterns(RESIDENTIAL_EXIT.integrations),
        route: "residential.integrations",
        dnsZone: "overseas",
        sniffer: "force",
      },

      // --- media · 走媒体独立选区 ---
      {
        key: "media.video",
        patterns: flattenGroupedPatterns(MEDIA.video),
        route: "media.video",
        dnsZone: "overseas",
      },
      {
        key: "media.music",
        patterns: flattenGroupedPatterns(MEDIA.music),
        route: "media.music",
        dnsZone: "overseas",
      },
      {
        key: "media.social",
        patterns: flattenGroupedPatterns(MEDIA.social),
        route: "media.social",
        dnsZone: "overseas",
      },
      {
        key: "media.im",
        patterns: flattenGroupedPatterns(MEDIA.im),
        route: "media.im",
        dnsZone: "overseas",
      },

      // --- proxy · DoH 端点走通用代理寻址 ---
      {
        key: "default.doh",
        patterns: flattenGroupedPatterns(CDN.doh),
        route: "proxy",
        dnsZone: "overseas",
      },
      // --- residential · CDN 基础设施走家宽出口 ---
      {
        key: "residential.cdn",
        patterns: flattenGroupedPatterns(CDN.cloud),
        route: "residential.cdn",
        dnsZone: "overseas",
        sniffer: "force",
      },
      {
        key: "dnsOnly.domestic",
        patterns: flattenGroupedPatterns(DNS_ONLY.domestic),
        dnsZone: "domestic",
      },
      {
        key: "dnsOnly.overseas",
        patterns: flattenGroupedPatterns(DNS_ONLY.overseas),
        dnsZone: "overseas",
      },

      // --- direct · 直连 ---
      // Apple/iCloud 绑定 domestic DoH：国内有 Apple CDN，域内 DoH 直返 CN 节点，直连最快。
      // sniffer skip：含 push.apple.com 等子域，避免误嗅探推送通道。
      {
        key: "direct.apple",
        patterns: flattenGroupedPatterns(OVERSEAS.special.apple),
        route: "direct",
        dnsZone: "domestic",
        sniffer: "skip",
        fakeIpBypass: true,
      },
      // Tailscale/ZeroTier/Plex/Synology 等直连应用未被墙，domestic DoH 返回真实 IP 即可，
      // 不走 overseas DoH，避免节点断连时解析卡死。
      {
        key: "direct.overseasApps",
        patterns: flattenGroupedPatterns(OVERSEAS.global.apps),
        route: "direct",
        dnsZone: "domestic",
        sniffer: "skip",
      },
      {
        key: "direct.cnAppsOverseasDoh",
        patterns: flattenGroupedPatterns(OVERSEAS.global.cnApps),
        route: "direct",
        dnsZone: "overseas",
        sniffer: "skip",
      },
      {
        key: "direct.cn.ai",
        patterns: flattenGroupedPatterns(CN.ai),
        route: "direct",
        dnsZone: "domestic",
      },
      {
        key: "direct.cn.office",
        patterns: flattenGroupedPatterns(CN.office),
        route: "direct",
        dnsZone: "domestic",
      },
      {
        key: "direct.cn.cloud",
        patterns: flattenGroupedPatterns(CN.cloud),
        route: "direct",
        dnsZone: "domestic",
      },
      {
        key: "direct.cn.consumer",
        patterns: flattenGroupedPatterns(CN.consumer),
        route: "direct",
        dnsZone: "domestic",
      },
      {
        key: "direct.localAndPush",
        patterns: flattenGroupedPatterns(LOCAL),
        route: "direct",
        dnsZone: "domestic",
        sniffer: "skip",
      },
    ];
  }

  var POLICY = buildPolicy();

  // 加载期：校验 POLICY patterns 形状。
  (function () {
    for (var i = 0; i < POLICY.length; i++) {
      assertPatternsHavePlusPrefix(POLICY[i].patterns);
    }
  })();

  // 按谓词投影 POLICY.patterns 并去重。
  function projectPolicyPatterns(predicate) {
    var result = [];
    for (var i = 0; i < POLICY.length; i++) {
      if (predicate(POLICY[i])) result.push.apply(result, POLICY[i].patterns);
    }
    return uniqueStrings(result);
  }

  // POLICY 谓词。
  function matchRoute(route) {
    return function (entry) {
      return entry.route === route;
    };
  }
  function matchSniffer(mode) {
    return function (entry) {
      return entry.sniffer === mode;
    };
  }
  function matchFakeIpBypass(entry) {
    return entry.fakeIpBypass === true;
  }

  // 按 route 投影（direct 优先）。
  function projectRoutedPatterns(route, directPatterns) {
    return excludeStrings(
      projectPolicyPatterns(matchRoute(route)),
      directPatterns,
    );
  }

  // 从 POLICY 投影 residential/media/direct/proxy/sniffer/fakeIpBypass。
  // 家宽 route 桶：support 合并 cdn。
  var RESIDENTIAL_ROUTES = [
    "residential.ai",
    "residential.support",
    "residential.integrations",
    "residential.cdn",
  ];
  var RESIDENTIAL_ROUTE_GROUPS = {
    ai: ["residential.ai"],
    support: ["residential.support", "residential.cdn"],
    integrations: ["residential.integrations"],
  };
  var MEDIA_ROUTE_GROUPS = {
    video: ["media.video"],
    music: ["media.music"],
    social: ["media.social"],
    im: ["media.im"],
  };

  // 按 routeGroups 投影成桶；.all 保持 allRoutes 顺序。
  function buildRouteGrouped(routeGroups, directPatterns, allRoutes) {
    var grouped = {};
    Object.keys(routeGroups).forEach(function (bucketKey) {
      var routes = routeGroups[bucketKey];
      var bucketPatterns = [];
      for (var i = 0; i < routes.length; i++) {
        bucketPatterns.push(projectRoutedPatterns(routes[i], directPatterns));
      }
      grouped[bucketKey] = mergeStringGroups(bucketPatterns);
    });
    var allOrdered = allRoutes;
    if (!allOrdered) {
      allOrdered = [];
      Object.keys(routeGroups).forEach(function (bucketKey) {
        var routes = routeGroups[bucketKey];
        for (var m = 0; m < routes.length; m++) allOrdered.push(routes[m]);
      });
    }
    var allPatterns = [];
    for (var j = 0; j < allOrdered.length; j++) {
      allPatterns.push(projectRoutedPatterns(allOrdered[j], directPatterns));
    }
    grouped.all = mergeStringGroups(allPatterns);
    return grouped;
  }

  function buildDerivedPatterns() {
    var direct = projectPolicyPatterns(matchRoute("direct"));
    var proxy = projectRoutedPatterns("proxy", direct);
    var residential = buildRouteGrouped(
      RESIDENTIAL_ROUTE_GROUPS,
      direct,
      RESIDENTIAL_ROUTES,
    );
    var media = buildRouteGrouped(MEDIA_ROUTE_GROUPS, direct);

    return {
      proxy: proxy,
      residential: residential,
      media: media,
      direct: direct,
      fakeIpBypass: projectPolicyPatterns(matchFakeIpBypass),
      // Sniffer 是 fake-ip 模式的安全网：当 fake-IP 映射丢失或 QUIC 跳过 DNS 时，
      // 从 TLS SNI / HTTP Host 恢复域名，确保 AI 流量命中家宽出口规则而非漏到 MATCH。
      //   force → 所有 sniffer:"force" 条目（家宽出口域名 + Cloudflare 等）
      //   skip  → Tailscale / Plex / Apple 推送等故意用 IP 语义的直连应用
      sniffer: {
        force: projectPolicyPatterns(matchSniffer("force")),
        skip: projectPolicyPatterns(matchSniffer("skip")),
      },
    };
  }

  // 进程入口：aiApps / aiCli / browser。
  function buildDerivedProcessNames() {
    return {
      aiApps: expandProcessNamesWithHelpers(
        RESIDENTIAL_EXIT.apps.ai.apps,
        RESIDENTIAL_EXIT.apps.ai.helperSuffixes,
        RESIDENTIAL_EXIT.apps.ai.exact,
      ),
      aiCli: uniqueStrings(RESIDENTIAL_EXIT.apps.ai.cli.slice()),
      browser: expandProcessNamesWithHelpers(
        RESIDENTIAL_EXIT.apps.browser.apps,
        RESIDENTIAL_EXIT.apps.browser.helperSuffixes,
      ),
    };
  }

  // 下游唯一派生入口。
  var DERIVED = {
    patterns: buildDerivedPatterns(),
    processNames: buildDerivedProcessNames(),
    networkRules: {
      direct: NETWORK.direct.slice(),
    },
  };

  // 裸域是否命中 `+.xxx`（等值或子域）。
  function isDomainCoveredBySuffixPatterns(domain, suffixPatterns) {
    for (var i = 0; i < suffixPatterns.length; i++) {
      var suffix = toSuffix(suffixPatterns[i]);
      if (domain === suffix) return true;
      if (endsWithString(domain, "." + suffix)) return true;
    }
    return false;
  }

  // 样本必须被 DERIVED 覆盖，防止漂移。
  function assertExpectedRoutesCoverage() {
    var i;
    var sample;

    for (i = 0; i < EXPECTED_ROUTES.toResidential.domains.length; i++) {
      sample = EXPECTED_ROUTES.toResidential.domains[i];
      if (
        !isDomainCoveredBySuffixPatterns(
          sample,
          DERIVED.patterns.residential.all,
        )
      ) {
        throw createUserError(
          "toResidential 样本未被 residential 源覆盖: " + sample,
        );
      }
    }

    for (i = 0; i < EXPECTED_ROUTES.toMedia.domains.length; i++) {
      sample = EXPECTED_ROUTES.toMedia.domains[i];
      if (
        !isDomainCoveredBySuffixPatterns(sample, DERIVED.patterns.media.all)
      ) {
        throw createUserError("toMedia 样本未被 media 源覆盖: " + sample);
      }
    }

    var procLookup = buildStringLookup(
      DERIVED.processNames.aiApps.concat(DERIVED.processNames.aiCli),
    );
    var procSamples = EXPECTED_ROUTES.toResidential.processNames.concat(
      EXPECTED_ROUTES.toResidential.cliNames,
    );
    for (i = 0; i < procSamples.length; i++) {
      if (!procLookup[procSamples[i]]) {
        throw createUserError(
          "toResidential 样本进程未在 RESIDENTIAL_EXIT.apps 中: " +
            procSamples[i],
        );
      }
    }
  }

  assertExpectedRoutesCoverage();

  // 字符串 → { type, value } 列表。
  // --- DNS / Sniffer 配置构建 ---

  // POLICY → nameserver-policy。
  function buildNameserverPolicy() {
    var dohByZone = {
      overseas: BASE.dns.overseas,
      domestic: BASE.dns.domestic,
    };
    var policy = {};
    policy[BASE.dns.domesticGeosite] = dohByZone.domestic;
    policy[BASE.dns.overseasGeosite] = dohByZone.overseas;

    for (var i = 0; i < POLICY.length; i++) {
      var entry = POLICY[i];
      if (!entry.dnsZone) continue;
      var dohServers = dohByZone[entry.dnsZone];
      if (!dohServers)
        throw createUserError("nameserver-policy 未知 zone: " + entry.dnsZone);
      for (var j = 0; j < entry.patterns.length; j++) {
        policy[entry.patterns[j]] = dohServers;
      }
    }

    return policy;
  }

  // fake-ip-filter；保留中部 glob（如 time.*.com）。
  function buildDnsFakeIpFilter(derived) {
    return []
      .concat(FAKE_IP_BYPASS.localNetwork)
      .concat(FAKE_IP_BYPASS.timeSync)
      .concat(FAKE_IP_BYPASS.connectivityTest)
      .concat(derived.patterns.fakeIpBypass)
      .concat(FAKE_IP_BYPASS.gamingRealtime)
      .concat(FAKE_IP_BYPASS.stunRealtime)
      .concat(FAKE_IP_BYPASS.homeRouter);
  }

  // fallback-filter：geoip + gfw（高价值域已在 nameserver-policy）。
  function buildDnsFallbackFilter() {
    return {
      geoip: true,
      "geoip-code": "CN",
      geosite: ["gfw"],
      ipcidr: ["240.0.0.0/4", "0.0.0.0/32"],
    };
  }

  // 基础 DNS 骨架。
  //
  // respect-rules: true — 让 DNS 查询也走分流规则，而不是全部从本地直连发出。
  // 效果：
  //   家宽出口域名的 DoH 查询 → 经家宽出口面板出去 → dns.google 看到的是所选出口 IP
  //   direct 域名的 DoH 查询 → 走 direct-nameserver（域内 DoH）→ 本地直连
  //   media 域名的 DoH 查询 → 经 media 代理组出去
  // 为什么需要：
  //   respect-rules: false 时，所有 DoH 查询都从本地网络直连发出。
  //   在 CN 出差时这意味着：
  //     1. 域外 DoH（dns.google / cloudflare）被墙 → 查询超时
  //     2. 即使部分可达，dns.google 也会看到"CN IP 在查 claude.ai"
  //   虽然 fake-ip 模式让数据连接不依赖本地 DNS 结果（代理服务端自行解析），
  //   但 DNS 查询本身仍是从本地发出的——respect-rules: true 堵住这个口。
  // 引导依赖：
  //   proxy-server-nameserver（域内 DoH）负责解析代理服务器本身的域名，
  //   不走分流规则，打破循环依赖。
  function buildDnsBaseConfig() {
    return {
      enable: true,
      listen: resolveDnsListen(),
      ipv6: true,
      "respect-rules": true,
      "enhanced-mode": "fake-ip",
      "fake-ip-range": "198.18.0.1/16",
      "default-nameserver": ["223.5.5.5", "119.29.29.29"],
      nameserver: BASE.dns.domestic,
      "proxy-server-nameserver": BASE.dns.domestic,
      "direct-nameserver": BASE.dns.domestic.slice(),
      "direct-nameserver-follow-policy": true,
      fallback: BASE.dns.fallback,
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

  // 构建 Sniffer 配置。
  // TLS (443/8443) / HTTP (80/8080/8880) 两种协议开启嗅探。
  // QUIC（UDP:443）不在此嗅探：已被规则链最前端的全局 REJECT 拦截（见 buildQuicRejectRules），
  // 客户端回退到 TCP+TLS，仍由 TLS 嗅探覆盖；拦截本身也避免运营商借 QUIC 特征识别代理。
  // force-domain：从 SNI/Host 恢复域名，防止 AI 流量因缺域名漏到 MATCH。
  // skip-domain：保留 IP 语义，避免破坏 P2P 打洞和推送通道。
  function buildSnifferConfig(derived) {
    return {
      enable: true,
      "force-dns-mapping": true,
      "parse-pure-ip": true,
      sniff: {
        TLS: { ports: [443, 8443] },
        HTTP: { ports: [80, 8080, 8880], "override-destination": true },
      },
      "force-domain": derived.patterns.sniffer.force,
      "skip-domain": derived.patterns.sniffer.skip,
    };
  }

  // --- 模块入口 ---

  function applyDnsAndSniffer(config) {
    config.dns = buildDnsConfig(DERIVED);
    config.sniffer = buildSnifferConfig(DERIVED);
    return config;
  }

  return {
    BASE: BASE,
    DERIVED: DERIVED,
    FAKE_IP_BYPASS: FAKE_IP_BYPASS,
    apply: applyDnsAndSniffer,
  };
})();

// ===========================================================================
// 3. 基础常量
// ===========================================================================

// 运行期常量：地区、节点名、组名、合法代理类型。
var BASE = {
  // 分区顺序；总闸插入家宽后：🇺🇸 → 🏠 → 🇸🇬 → 🇯🇵 → 🇰🇷 → 🌸 → 🇭🇰
  regionPreferenceOrder: ["US", "SG", "JP", "KR", "TW", "HK"],
  regions: {
    US: { regex: /🇺🇸|美国|United\s*States|^US(?:[|丨\-_ ]|\d)/i, label: "美国", flag: "🇺🇸" },
    SG: { regex: /🇸🇬|新加坡|Singapore|^SG(?:[|丨\-_ ]|\d)/i, label: "新加坡", flag: "🇸🇬" },
    JP: { regex: /🇯🇵|日本|Japan|^JP(?:[|丨\-_ ]|\d)/i, label: "日本", flag: "🇯🇵" },
    KR: { regex: /🇰🇷|韩国|韓國|Korea|^KR(?:[|丨\-_ ]|\d)/i, label: "韩国", flag: "🇰🇷" },
    // 不用 🇹🇼；🌸=中华台北
    TW: {
      regex: /🌸|🇹🇼|中华台北|中華台北|Chinese\s*Taipei|\bTPE\b|台湾|台灣|Taiwan|^TW(?:[|丨\-_ ]|\d)/i,
      label: "中华台北", flag: "🌸",
    },
    HK: { regex: /🇭🇰|香港|Hong\s*Kong|^HK(?:[|丨\-_ ]|\d)/i, label: "香港", flag: "🇭🇰" },
  },
  residentialFlag: "🏠",
  nodeNames: {
    transit: "🏠 家宽出口（官方中转）",
    homeStatic: "🏠 家宽出口（静态IP）",
  },
  defaultProxyGroupKeywords: ["PROXY", "节点选择", "手动选择", "GLOBAL"],
  ruleTargets: { direct: "DIRECT" },
  rulePrefixes: { match: "MATCH," },
  urlTestProbeUrl: "http://cp.cloudflare.com/generate_204",
  residentialProxyNameKeyword: "家宽出口",
  groupNameSuffixes: { base: "节点组" },
  groupNamePrefixes: { base: "az.分区测速." },
  residentialGroupName: "az.其他测速.🏠 家宽节点组",
  validProxyTypes: [
    "http", "https", "socks5", "ss", "ssr", "vmess",
    "trojan", "vless", "hysteria", "tuic", "snell", "wireguard",
  ],
};

// ===========================================================================
// 4. 代理出口与选区
// ===========================================================================

// 确保 proxies / proxy-groups / rules 容器存在。
function writeContainers(config) {
  if (!config.proxies) config.proxies = [];
  if (!config["proxy-groups"]) config["proxy-groups"] = [];
  if (!config.rules) config.rules = [];
}

// 地区键转大写；非法输入直接抛错。
function normalizeRegionKey(region) {
  if (typeof region !== "string" || region === "") {
    throw createUserError("region 必须是非空字符串，实际: " + region);
  }
  return region.toUpperCase();
}

function resolveRegionMeta(region) {
  var regionKey = normalizeRegionKey(region);
  var source = BASE.regions[regionKey];
  if (!source) return null;
  return {
    regex: source.regex,
    label: source.label,
    flag: source.flag,
    code: regionKey,
  };
}

// 组名：az.分区测速.<旗> <标签>节点组
function buildRegionGroupName(regionMeta, groupNameSuffix) {
  return (
    BASE.groupNamePrefixes.base +
    regionMeta.flag +
    " " +
    regionMeta.label +
    groupNameSuffix
  );
}

// 家宽 SOCKS5 节点；无认证字段则省略。
function buildResidentialSocksProxy(endpoint, proxyName) {
  if (BASE.validProxyTypes.indexOf("socks5") < 0) {
    throw createUserError(
      "家宽出口代理类型 socks5 不在 Clash 合法代理类型列表中，请检查 BASE.validProxyTypes",
    );
  }
  var proxy = {
    name: proxyName,
    type: "socks5",
    server: endpoint.server,
    port: endpoint.port,
    udp: true,
  };
  if (endpoint.username) proxy.username = endpoint.username;
  if (endpoint.password) proxy.password = endpoint.password;
  return proxy;
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

// 判断代理组名是否包含默认代理核心词。
function defaultProxyGroupNameMatches(groupName, keyword) {
  if (typeof groupName !== "string" || typeof keyword !== "string")
    return false;
  return groupName.toUpperCase().indexOf(keyword.toUpperCase()) >= 0;
}

// 识别订阅默认代理组：精确名 → MATCH 目标 → 关键词子串。
// MATCH 优先于松散子串，避免「PROXY 备用」类组抢走订阅真主组。
function resolveDefaultProxyGroupName(config) {
  var proxyGroups = config["proxy-groups"] || [];
  var exactNames = ["PROXY", "GLOBAL"];
  var i;
  var j;

  for (i = 0; i < exactNames.length; i++) {
    for (j = 0; j < proxyGroups.length; j++) {
      if (
        typeof proxyGroups[j].name === "string" &&
        proxyGroups[j].name.toUpperCase() === exactNames[i]
      ) {
        return proxyGroups[j].name;
      }
    }
  }

  var matchTarget = resolveDefaultGroupFromMatch(config);
  if (matchTarget) return matchTarget;

  for (i = 0; i < BASE.defaultProxyGroupKeywords.length; i++) {
    for (j = 0; j < proxyGroups.length; j++) {
      if (
        defaultProxyGroupNameMatches(
          proxyGroups[j].name,
          BASE.defaultProxyGroupKeywords[i],
        )
      ) {
        return proxyGroups[j].name;
      }
    }
  }
  return null;
}

// 从 MATCH 规则提取默认代理组名。
function resolveDefaultGroupFromMatch(config) {
  var rules = config.rules || [];
  for (var i = rules.length - 1; i >= 0; i--) {
    var line = rules[i];
    if (line.indexOf(BASE.rulePrefixes.match) === 0) {
      var commaIndex = line.indexOf(",");
      if (commaIndex >= 0) {
        var targetName = line.substring(commaIndex + 1);
        if (findProxyGroupByName(config["proxy-groups"], targetName)) {
          return targetName;
        }
      }
    }
  }
  return null;
}

// 将管理组追加到订阅默认代理组的候选列表。
// prepend=true 时插到默认组最前（防封总闸优先可见）。
function writeManagedGroupIntoDefaultProxy(
  config,
  managedGroupName,
  defaultProxyGroupName,
  prepend,
) {
  if (!defaultProxyGroupName) return;
  var defaultProxyGroup = findProxyGroupByName(
    config["proxy-groups"],
    defaultProxyGroupName,
  );
  if (!defaultProxyGroup || !defaultProxyGroup.proxies) return;
  var nextProxyNames = [].concat(defaultProxyGroup.proxies);
  if (prepend) nextProxyNames.unshift(managedGroupName);
  else nextProxyNames.push(managedGroupName);
  defaultProxyGroup.proxies = uniqueStrings(nextProxyNames);
}

// 判断给定名称是否在节点或代理组中存在。
function hasProxyOrGroup(config, targetName) {
  return !!(
    findProxyByName(config.proxies || [], targetName) ||
    findProxyGroupByName(config["proxy-groups"] || [], targetName)
  );
}

// 收集匹配地区特征且非家宽出口的节点名称列表。
function collectRegionNodeNames(proxies, regionRegex) {
  var regionNodeNames = [];
  for (var i = 0; i < proxies.length; i++) {
    var proxy = proxies[i];
    if (
      regionRegex.test(proxy.name) &&
      proxy.name.indexOf(BASE.residentialProxyNameKeyword) < 0
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
    tolerance: 50,
  });
}

// 按名称删除代理节点（清理上轮残留的家宽出口节点）。
function removeNamedProxy(config, proxyName) {
  var proxies = config.proxies || [];
  var index = findNamedItemIndex(proxies, proxyName);
  if (index >= 0) proxies.splice(index, 1);
}

// 注入家宽 SOCKS5 节点，并清理旧节点名。
function writeResidentialExitProxies(config, residentialExits) {
  removeNamedProxy(config, "家宽出口（家庭静态 IP）");
  removeNamedProxy(config, "家宽出口（官方中转）");
  removeNamedProxy(config, "家宽出口（静态IP）");

  if (residentialExits.homeStatic) {
    upsertNamedItem(
      config.proxies,
      buildResidentialSocksProxy(
        residentialExits.homeStatic,
        BASE.nodeNames.homeStatic,
      ),
    );
  } else {
    removeNamedProxy(config, BASE.nodeNames.homeStatic);
  }

  if (residentialExits.transit) {
    upsertNamedItem(
      config.proxies,
      buildResidentialSocksProxy(
        residentialExits.transit,
        BASE.nodeNames.transit,
      ),
    );
  } else {
    removeNamedProxy(config, BASE.nodeNames.transit);
  }
}

// 家宽实体名：官方中转 → 静态IP。
function listResidentialExitNodeNames(residentialExits) {
  var names = [];
  if (residentialExits && residentialExits.transit) {
    names.push(BASE.nodeNames.transit);
  }
  if (residentialExits && residentialExits.homeStatic) {
    names.push(BASE.nodeNames.homeStatic);
  }
  return names;
}

// 家宽组成员；无实体则降级挂分区/DIRECT。
function buildResidentialExitMembers(residentialExits, regionalTargets) {
  var members = listResidentialExitNodeNames(residentialExits);
  if (members.length === 0) {
    return buildDegradedResidentialMembers(regionalTargets);
  }
  return members;
}

// 仅根据订阅节点创建或修正指定地区的 `url-test` 代理组。
function writeRegionGroup(config, region, groupNameSuffix) {
  var regionMeta = resolveRegionMeta(region);
  if (!regionMeta) return null;

  var regionRegex = regionMeta.regex;
  var groupName = buildRegionGroupName(regionMeta, groupNameSuffix);
  var proxyGroups = config["proxy-groups"];

  // 台湾组更名：清掉中华民国旗旧组（无论本轮是否仍有 TW 节点）。
  if (regionMeta.code === "TW") {
    removeNamedProxyGroup(config, "az.分区测速.🇹🇼 台湾节点组");
  }

  var regionNodeNames = collectRegionNodeNames(config.proxies, regionRegex);
  if (regionNodeNames.length === 0) return null;

  upsertRegionUrlTestGroup(proxyGroups, groupName, regionNodeNames); // 用订阅地区节点创建或修正目标组

  return groupName;
}

// 按名删除代理组。
function removeNamedProxyGroup(config, groupName) {
  var groups = config["proxy-groups"] || [];
  var index = findNamedItemIndex(groups, groupName);
  if (index >= 0) groups.splice(index, 1);
}

// 写入家宽 select 组，并清理旧组名。
function writeResidentialGroup(config, memberProxies) {
  var residentialGroupName = BASE.residentialGroupName;
  removeNamedProxyGroup(config, "az.核心出口.🏠 家宽出口");
  removeNamedProxyGroup(config, "az.其他测速.家宽节点组");

  upsertNamedItem(config["proxy-groups"], {
    name: residentialGroupName,
    type: "select",
    proxies: memberProxies.slice(),
  });

  return residentialGroupName;
}

// 无家宽凭证时：分区测速组，否则 DIRECT。
function buildDegradedResidentialMembers(regionalTargets) {
  var members = listRegionalExitChoices(regionalTargets);
  if (members.length === 0) members.push("DIRECT");
  return members;
}

// UI 面板组名。
var UI_GROUPS = {
  // 严管 → 防封出口
  strictExit: "az.严管调度.🏠 防封出口",
  ai: "az.严管调度.🤖 AI 服务",
  support: "az.严管调度.🔑 登录旁路",
  integrations: "az.严管调度.💳 支付验证",
  // 其他 → 解锁出口
  otherExit: "az.其他调度.🌏 解锁出口",
  video: "az.其他调度.🎬 视频流媒体",
  music: "az.其他调度.🎵 音乐播客",
  social: "az.其他调度.🌐 社交长文",
  im: "az.其他调度.💬 即时通讯",
};

function listRegionalExitChoices(regionalTargets) {
  var regionOrder = [];
  var order = BASE.regionPreferenceOrder;
  var targets = regionalTargets || {};
  for (var i = 0; i < order.length; i++) {
    if (targets[order[i]]) regionOrder.push(targets[order[i]]);
  }
  return regionOrder;
}

// 总闸候选：🇺🇸 → 🏠家宽 → 🇸🇬 → 🇯🇵 → 🇰🇷 → 🌸 → 🇭🇰
function buildRegionAndResidentialExitChoices(residentialTarget, regionalTargets) {
  var targets = regionalTargets || {};
  var order = BASE.regionPreferenceOrder;
  var choices = [];
  var insertedHome = false;
  for (var i = 0; i < order.length; i++) {
    var code = order[i];
    if (targets[code]) choices.push(targets[code]);
    // 家宽紧跟美国；无美区时由循环后补插到最前
    if (code === "US" && !insertedHome) {
      choices.push(residentialTarget);
      insertedHome = true;
    }
  }
  if (!insertedHome) choices.push(residentialTarget);
  return uniqueStrings(choices);
}

function buildStrictAntiBanExitChoices(residentialTarget, regionalTargets) {
  return buildRegionAndResidentialExitChoices(residentialTarget, regionalTargets);
}

function buildOtherUnlockExitChoices(residentialTarget, regionalTargets) {
  return buildRegionAndResidentialExitChoices(residentialTarget, regionalTargets);
}

// 写入 UI 策略组；分类面板只挂各自总闸。
function writeExpandedProxyGroups(
  config,
  residentialTarget,
  regionalTargets,
  exitNodeNames,
) {
  var proxyGroups = config["proxy-groups"];
  var strictChoices = buildStrictAntiBanExitChoices(residentialTarget, regionalTargets);
  var otherChoices = buildOtherUnlockExitChoices(residentialTarget, regionalTargets);
  var strictOnly = [UI_GROUPS.strictExit];
  var otherOnly = [UI_GROUPS.otherExit];

  var subgroups = [
    { name: UI_GROUPS.strictExit, type: "select", proxies: strictChoices },
    { name: UI_GROUPS.ai, type: "select", proxies: strictOnly },
    { name: UI_GROUPS.support, type: "select", proxies: strictOnly },
    { name: UI_GROUPS.integrations, type: "select", proxies: strictOnly },
    { name: UI_GROUPS.otherExit, type: "select", proxies: otherChoices },
    { name: UI_GROUPS.video, type: "select", proxies: otherOnly },
    { name: UI_GROUPS.music, type: "select", proxies: otherOnly },
    { name: UI_GROUPS.social, type: "select", proxies: otherOnly },
    { name: UI_GROUPS.im, type: "select", proxies: otherOnly },
  ];
  for (var i = 0; i < subgroups.length; i++) {
    upsertNamedItem(proxyGroups, subgroups[i]);
  }
}

// 解析路由目标：地区测速组 → 家宽出口组 → UI 面板。
// 无任何家宽出口节点时，家宽组降级为地区候选（或 DIRECT）。
function resolveRoutingTargets(config, residentialExits) {
  var defaultProxyGroupName = resolveDefaultProxyGroupName(config);
  var regionalTargets = {};
  var definedRegions = BASE.regionPreferenceOrder;
  var i;
  var code;
  var standardGroup;
  var hasHomeStatic = !!(residentialExits && residentialExits.homeStatic);
  var hasTransit = !!(residentialExits && residentialExits.transit);
  var hasResidentialExit = hasHomeStatic || hasTransit;

  for (i = 0; i < definedRegions.length; i++) {
    code = definedRegions[i];
    standardGroup = writeRegionGroup(
      config,
      code,
      BASE.groupNameSuffixes.base,
    );
    if (standardGroup) {
      writeManagedGroupIntoDefaultProxy(
        config,
        standardGroup,
        defaultProxyGroupName,
      );
      regionalTargets[code] = standardGroup;
    }
  }

  var exitNodeNames = listResidentialExitNodeNames(residentialExits || {});
  var residentialMembers = buildResidentialExitMembers(
    residentialExits || {},
    regionalTargets,
  );
  var residentialGroupName = writeResidentialGroup(config, residentialMembers);

  // 实体节点与家宽组都写入默认代理组，刷新后仍能在 PROXY 里直接看到家宽出口。
  var k;
  for (k = 0; k < exitNodeNames.length; k++) {
    writeManagedGroupIntoDefaultProxy(
      config,
      exitNodeNames[k],
      defaultProxyGroupName,
    );
  }
  writeManagedGroupIntoDefaultProxy(
    config,
    residentialGroupName,
    defaultProxyGroupName,
  );

  writeExpandedProxyGroups(
    config,
    residentialGroupName,
    regionalTargets,
    exitNodeNames,
  );
  // 默认组露出总闸；防封出口置顶，开箱先看见家宽防封。
  writeManagedGroupIntoDefaultProxy(
    config,
    UI_GROUPS.strictExit,
    defaultProxyGroupName,
    true,
  );
  writeManagedGroupIntoDefaultProxy(
    config,
    UI_GROUPS.otherExit,
    defaultProxyGroupName,
  );
  cleanupSubscriptionProxyGroups(config, defaultProxyGroupName);

  return {
    residentialGroupName: residentialGroupName,
    defaultProxyTarget: defaultProxyGroupName || residentialGroupName,
    hasHomeStatic: hasHomeStatic,
    hasTransit: hasTransit,
    hasResidentialExit: hasResidentialExit,
    expectedResidentialMembers: residentialMembers.slice(),
    exitNodeNames: exitNodeNames.slice(),
  };
}

// 清除订阅自带的代理组（自动选择、故障转移、Bahamut 等），
// 只保留 az.* 管理组和订阅默认代理组作为 MATCH/DoH/GFW 出口。
function cleanupSubscriptionProxyGroups(config, defaultProxyGroupName) {
  var groups = config["proxy-groups"];
  var managedGroups = [];

  for (var i = 0; i < groups.length; i++) {
    var gName = groups[i].name;
    if (gName.indexOf("az.") === 0 || gName === defaultProxyGroupName) {
      managedGroups.push(groups[i]);
    }
  }

  // 清理默认组中指向已删除订阅组的引用
  if (defaultProxyGroupName) {
    for (var j = 0; j < managedGroups.length; j++) {
      if (
        managedGroups[j].name === defaultProxyGroupName &&
        managedGroups[j].proxies
      ) {
        var cleanProxies = [];
        var oldProxies = managedGroups[j].proxies;
        for (var k = 0; k < oldProxies.length; k++) {
          var pName = oldProxies[k];
          if (
            pName === "DIRECT" ||
            pName === "REJECT" ||
            pName.indexOf("az.") === 0 ||
            findProxyByName(config.proxies, pName)
          ) {
            cleanProxies.push(pName);
          }
        }
        managedGroups[j].proxies = cleanProxies;
        break;
      }
    }
  }

  config["proxy-groups"] = managedGroups;
}

function writeManagedRouting(config, routingTargets, derived) {
  writeManagedRules(config, routingTargets, derived);
}

// ===========================================================================
// 5. 规则注入
// ===========================================================================

// 规则标识 TYPE,value。
function getRuleIdentity(ruleLine) {
  var firstCommaIndex = ruleLine.indexOf(",");
  if (firstCommaIndex < 0) return null;

  var secondCommaIndex = ruleLine.indexOf(",", firstCommaIndex + 1);
  if (secondCommaIndex < 0) return null;

  return ruleLine.substring(0, secondCommaIndex);
}

// 按 TYPE,value 去重，保留首次。
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

// 拦截 QUIC（UDP:443）；rejectQuic=false 关闭。
function buildQuicRejectRules() {
  if (!shouldRejectQuic()) return [];
  return ["AND,((NETWORK,udp),(DST-PORT,443)),REJECT"];
}

// 规则链：QUIC → 严管域 → 媒体 → DoH → 直连 → CN → 进程 → GFW → MATCH。
// 进程在 GFW 前，避免 AI 漏到机房默认组。
function buildManagedRules(derived, routingTargets) {
  var concatenated = buildQuicRejectRules()
    .concat(buildResidentialDomainRules(derived))
    .concat(buildMediaRules(derived))
    .concat(buildProxyRules(derived, routingTargets.defaultProxyTarget))
    .concat(buildDirectRules(derived))
    .concat(buildChinaFallbackRules())
    .concat(buildStrictProcessRules(derived))
    .concat(buildBrowserResidentialRules(derived))
    .concat(buildGfwProxyRule(routingTargets.defaultProxyTarget));
  return dedupeRulesByIdentity(concatenated);
}

// 注入管理规则（置顶），由脚本生成 MATCH 兜底。
// 同时清除订阅的 rule-providers，防止 RULE-SET 规则逃逸。
function writeManagedRules(config, routingTargets, derived) {
  var managedRules = buildManagedRules(derived, routingTargets);

  // 清空所有订阅规则，写入管理规则 + 管理 MATCH
  config.rules.length = 0;
  config.rules.push.apply(config.rules, managedRules);
  config.rules.push("MATCH," + routingTargets.defaultProxyTarget);

  // 清除订阅 rule-providers
  if (
    typeof config["rule-providers"] === "object" &&
    config["rule-providers"] !== null
  ) {
    config["rule-providers"] = {};
  }
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

// 批量追加多个进程分组。
function appendProcessRuleGroups(ruleLines, processGroups, target) {
  for (var i = 0; i < processGroups.length; i++) {
    appendProcessRules(ruleLines, processGroups[i], target);
  }
}

// 返回应纳入严格 AI 路由的进程分组；AI CLI 固定走家宽出口面板。
function buildStrictProcessGroups(derived) {
  return [derived.processNames.aiApps, derived.processNames.aiCli];
}

// 对一组派生域名桶批量生成 DOMAIN-SUFFIX 规则。
// 不再自动生成 DOMAIN-KEYWORD：一级标签子串会误路由（如 you→youtube、cloud→华为云）。
// bucket 每个键（跳过汇总键 all）映射到 targetByKey 中同名的 UI 面板。
function appendDomainRuleGroups(ruleLines, bucket, targetByKey) {
  Object.keys(bucket).forEach(function (bucketKey) {
    if (bucketKey === "all") return;
    var target = targetByKey[bucketKey];
    appendSuffixRules(ruleLines, bucket[bucketKey], target);
  });
}

// 生成家宽出口域名规则：AI / 支撑平台 / 集成服务显式锁定到家宽出口面板。
function buildResidentialDomainRules(derived) {
  var ruleLines = [];
  appendDomainRuleGroups(ruleLines, derived.patterns.residential, UI_GROUPS);
  return ruleLines;
}

// 生成 AI App / CLI 进程兜底规则。放在 CN 之后、GFW 之前：
// 明确域名与国内直连仍优先；未维护的 gfw 域由进程接管进严管面板。
function buildStrictProcessRules(derived) {
  var ruleLines = [];
  appendProcessRuleGroups(
    ruleLines,
    buildStrictProcessGroups(derived),
    UI_GROUPS.ai,
  ); // 统一丢向 AI 可视化面板
  return ruleLines;
}

// 生成 DoH 端点的代理规则，确保 DNS 查询在境外加密隧道内完成。
function buildProxyRules(derived, defaultProxyTarget) {
  var ruleLines = [];
  appendSuffixRules(ruleLines, derived.patterns.proxy, defaultProxyTarget);
  return ruleLines;
}

// 生成浏览器进程规则，承载按应用名强制分流的 AI 浏览器进程。
function buildBrowserResidentialRules(derived) {
  var ruleLines = [];
  appendProcessRuleGroups(
    ruleLines,
    [derived.processNames.browser],
    UI_GROUPS.ai,
  ); // 统一丢向 AI 高敏阵列
  return ruleLines;
}

// 生成媒体组选区规则，只承载媒体域名。
function buildMediaRules(derived) {
  var ruleLines = [];
  appendDomainRuleGroups(ruleLines, derived.patterns.media, UI_GROUPS);
  return ruleLines;
}

// 生成所有 DIRECT 规则：固定 IP-CIDR 网段（带 `no-resolve`）+ 全部 direct 模式。
function buildDirectRules(derived) {
  var ruleLines = [];
  for (var i = 0; i < derived.networkRules.direct.length; i++) {
    var r = derived.networkRules.direct[i];
    ruleLines.push(r.type + "," + r.value + "," + r.target + ",no-resolve");
  }
  appendSuffixRules(
    ruleLines,
    derived.patterns.direct,
    BASE.ruleTargets.direct,
  );
  return ruleLines;
}

// 生成中国站点直连兜底。DNS geosite 已负责解析，这里负责未显式维护域名的出口。
function buildChinaFallbackRules() {
  return [
    "GEOSITE,cn," + BASE.ruleTargets.direct,
    "GEOIP,CN," + BASE.ruleTargets.direct,
  ];
}

// 生成 GFWList 代理规则，GFW 域通过 GEOSITE,gfw 走默认代理组。
function buildGfwProxyRule(defaultProxyTarget) {
  return ["GEOSITE,gfw," + defaultProxyTarget];
}

// 基于预构建的规则行查找表 O(1) 断言管理规则是否命中预期目标。
function assertManagedRuleTargetExpanded(
  ruleLineLookup,
  type,
  value,
  validTargets,
) {
  for (var i = 0; i < validTargets.length; i++) {
    var ruleLine = type + "," + value + "," + validTargets[i];
    if (ruleLineLookup[ruleLine]) return;
  }
  throw createUserError(
    "关键规则未正确写入: " +
      type +
      "," +
      value +
      "（未查到映射至合规的可视化分组），请检查脚本源数据覆盖",
  );
}

// 断言家宽出口组在节点/代理组中存在。
function assertRoutingTargetsExist(config, routingTargets) {
  if (!hasProxyOrGroup(config, routingTargets.residentialGroupName)) {
    throw createUserError("当前家宽出口组不存在，请检查代理组注入逻辑");
  }
}

// 断言已配置的家宽出口节点存在，未配置的不得残留。
function assertResidentialExitBindings(config, routingTargets) {
  var homeProxy = findProxyByName(config.proxies, BASE.nodeNames.homeStatic);
  var transitProxy = findProxyByName(config.proxies, BASE.nodeNames.transit);

  if (routingTargets.hasHomeStatic) {
    if (!homeProxy || homeProxy.type !== "socks5") {
      throw createUserError(
        "静态IP 节点状态异常，请检查 RESIDENTIAL_CREDENTIALS.homeStatic",
      );
    }
  } else if (homeProxy) {
    throw createUserError(
      "未配置静态IP 时不应残留该节点，请检查节点清理逻辑",
    );
  }

  if (routingTargets.hasTransit) {
    if (!transitProxy || transitProxy.type !== "socks5") {
      throw createUserError(
        "官方中转节点状态异常，请检查 RESIDENTIAL_CREDENTIALS 和节点注入逻辑",
      );
    }
  } else if (transitProxy) {
    throw createUserError(
      "无官方中转凭证时不应残留官方中转节点，请检查节点清理逻辑",
    );
  }
}

// 断言家宽出口组 shape：有出口时成员集合须匹配；无出口时不得挂管理节点。
function assertResidentialGroupShape(config, routingTargets) {
  var residentialGroupName = routingTargets.residentialGroupName;
  var residentialGroup = findProxyGroupByName(
    config["proxy-groups"],
    residentialGroupName,
  );
  if (!residentialGroup || residentialGroup.type !== "select") {
    throw createUserError("当前家宽出口组内容异常，请检查代理组注入逻辑");
  }

  var proxies = residentialGroup.proxies || [];
  if (proxies.length === 0) {
    throw createUserError("当前家宽出口组内容异常，请检查代理组注入逻辑");
  }

  if (routingTargets.hasResidentialExit) {
    if (
      !haveSameStringSet(proxies, routingTargets.expectedResidentialMembers)
    ) {
      throw createUserError("当前家宽出口组内容异常，请检查代理组注入逻辑");
    }
    return;
  }

  for (var i = 0; i < proxies.length; i++) {
    var member = proxies[i];
    if (
      member === BASE.nodeNames.transit ||
      member === BASE.nodeNames.homeStatic
    ) {
      throw createUserError("无家宽凭证时家宽出口组不应挂管理出口节点");
    }
    if (member === "DIRECT" || member === "REJECT") continue;
    if (!hasProxyOrGroup(config, member)) {
      throw createUserError("当前家宽出口组内容异常，请检查代理组注入逻辑");
    }
  }
}

// 分类面板必须只挂对应总闸，防止各自另选导致 IP 分裂。
function assertCategoryExitCoupling(config, exitGroupName, categoryNames, label) {
  var exitGroup = findProxyGroupByName(config["proxy-groups"], exitGroupName);
  if (!exitGroup || exitGroup.type !== "select") {
    throw createUserError("缺少" + label + "出口组: " + exitGroupName);
  }
  if (!exitGroup.proxies || exitGroup.proxies.length === 0) {
    throw createUserError(label + "出口候选不能为空");
  }

  for (var i = 0; i < categoryNames.length; i++) {
    var group = findProxyGroupByName(config["proxy-groups"], categoryNames[i]);
    if (
      !group ||
      group.type !== "select" ||
      !haveSameStringSet(group.proxies || [], [exitGroupName])
    ) {
      throw createUserError(
        label + "分类面板必须只挂出口总闸: " + categoryNames[i],
      );
    }
  }
}

// 严管三分类只挂防封出口。
function assertStrictExitCoupling(config) {
  assertCategoryExitCoupling(
    config,
    UI_GROUPS.strictExit,
    [UI_GROUPS.ai, UI_GROUPS.support, UI_GROUPS.integrations],
    "严管防封",
  );
}

// 其他调度解锁出口与防封分离；四分类只挂解锁出口。
function assertOtherExitCoupling(config) {
  assertCategoryExitCoupling(
    config,
    UI_GROUPS.otherExit,
    [UI_GROUPS.video, UI_GROUPS.music, UI_GROUPS.social, UI_GROUPS.im],
    "其他解锁",
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

// 逐条断言一批校验目标在最终规则里命中预期合规集合的任何一个。
function assertRuleTargetBatchExpanded(
  ruleLineLookup,
  validationTargets,
  validTargets,
) {
  for (var i = 0; i < validationTargets.length; i++) {
    assertManagedRuleTargetExpanded(
      ruleLineLookup,
      validationTargets[i].type,
      validationTargets[i].value,
      validTargets,
    );
  }
}

// 验证关键规则目标是否正确写入。
function validateManagedRouting(config, routingTargets, derived) {
  assertRoutingTargetsExist(config, routingTargets);
  assertResidentialExitBindings(config, routingTargets);
  assertResidentialGroupShape(config, routingTargets);
  assertStrictExitCoupling(config);
  assertOtherExitCoupling(config);

  var ruleLineLookup = buildStringLookup(config.rules);
  var validationTargets = buildRoutingValidationTargets(derived);
  // 断言规则落在正确的 UI 分组中
  assertRuleTargetBatchExpanded(ruleLineLookup, validationTargets.strict, [
    UI_GROUPS.ai,
    UI_GROUPS.support,
    UI_GROUPS.integrations,
  ]);
  assertRuleTargetBatchExpanded(ruleLineLookup, validationTargets.browser, [
    UI_GROUPS.ai,
  ]);
  assertRuleTargetBatchExpanded(ruleLineLookup, validationTargets.media, [
    UI_GROUPS.video,
    UI_GROUPS.music,
    UI_GROUPS.social,
    UI_GROUPS.im,
  ]);
}

// ===========================================================================
// 6. 路由校验
// ===========================================================================

function buildRoutingValidationTargets(derived) {
  return {
    strict: buildDomainValidationTargets(derived.patterns.residential.all)
      .concat(buildProcessValidationTargets(derived.processNames.aiApps))
      .concat(buildProcessValidationTargets(derived.processNames.aiCli)),
    media: buildDomainValidationTargets(derived.patterns.media.all),
    browser: buildProcessValidationTargets(derived.processNames.browser),
  };
}

function buildValidationTargets(ruleType, values, valueMapper) {
  var targets = [];
  var mapValue =
    valueMapper ||
    function (value) {
      return value;
    };
  for (var i = 0; i < values.length; i++) {
    targets.push({ type: ruleType, value: mapValue(values[i]) });
  }
  return targets;
}

function buildDomainValidationTargets(domainPatterns) {
  return buildValidationTargets("DOMAIN-SUFFIX", domainPatterns, toSuffix);
}

function buildProcessValidationTargets(processNames) {
  return buildValidationTargets("PROCESS-NAME", processNames);
}

// 家宽出口主流程：容器 → 节点 → 路由 → 规则 → 校验。
function applyResidentialExit(config, derived, residentialExits) {
  var routingTargets;

  writeContainers(config);
  writeResidentialExitProxies(config, residentialExits || {});

  routingTargets = resolveRoutingTargets(config, residentialExits || {});
  writeManagedRouting(config, routingTargets, derived);
  validateManagedRouting(config, routingTargets, derived);

  return config;
}

// ===========================================================================
// 7. 覆写入口
// ===========================================================================

// 文档占位符：未改配置时不得静默注入。
var RESIDENTIAL_CREDENTIAL_PLACEHOLDERS = {
  username: ["你的用户名", "changeme", "example"],
  password: ["你的密码", "changeme", "example"],
  server: ["transit.example.com", "example.com", "localhost", "home.example.com"],
};

function isResidentialCredentialPlaceholder(kind, value) {
  if (typeof value !== "string" || value === "") return false;
  var placeholders = RESIDENTIAL_CREDENTIAL_PLACEHOLDERS[kind] || [];
  var normalized = value.toLowerCase();
  for (var i = 0; i < placeholders.length; i++) {
    if (placeholders[i].toLowerCase() === normalized) return true;
  }
  return false;
}

function isValidProxyPort(port) {
  return typeof port === "number" && port > 0 && port < 65536;
}

// 共用认证：顶层优先，空则回退端点内嵌（兼容旧配置）。
function getSharedResidentialAuth(credentials) {
  var username =
    credentials && typeof credentials.username === "string" ? credentials.username : "";
  var password =
    credentials && typeof credentials.password === "string" ? credentials.password : "";
  if (username === "" || password === "") {
    var nestedSources = [];
    if (credentials && credentials.transit) nestedSources.push(credentials.transit);
    if (credentials && credentials.homeStatic) nestedSources.push(credentials.homeStatic);
    for (var i = 0; i < nestedSources.length; i++) {
      var nested = nestedSources[i];
      if (
        nested &&
        typeof nested.username === "string" &&
        nested.username !== "" &&
        typeof nested.password === "string" &&
        nested.password !== ""
      ) {
        if (username === "") username = nested.username;
        if (password === "") password = nested.password;
        break;
      }
    }
  }
  return { username: username, password: password };
}

// requireAuth=true：官方中转必填；false：静态IP 可空。
function hasValidSharedResidentialAuth(credentials, requireAuth) {
  var auth = getSharedResidentialAuth(credentials);
  if (requireAuth && (auth.username === "" || auth.password === "")) return false;
  if (auth.username !== "" && isResidentialCredentialPlaceholder("username", auth.username)) {
    return false;
  }
  if (auth.password !== "" && isResidentialCredentialPlaceholder("password", auth.password)) {
    return false;
  }
  return true;
}

// 端点仅校验 server/port；allowLocalhost 时放行 localhost。
function hasConfiguredEndpointServer(endpoint, allowLocalhost) {
  if (
    !endpoint ||
    typeof endpoint.server !== "string" ||
    endpoint.server === "" ||
    !isValidProxyPort(endpoint.port)
  ) {
    return false;
  }
  if (
    !(allowLocalhost && endpoint.server.toLowerCase() === "localhost") &&
    isResidentialCredentialPlaceholder("server", endpoint.server)
  ) {
    return false;
  }
  return true;
}

// 官方中转：server/port + 共用认证（必填）。
function hasConfiguredTransitCredentials(credentials) {
  return (
    !!credentials &&
    hasConfiguredEndpointServer(credentials.transit, false) &&
    hasValidSharedResidentialAuth(credentials, true)
  );
}

// 静态IP：server/port；认证可选；允许 localhost。
function hasConfiguredHomeStaticCredentials(credentials) {
  return (
    !!credentials &&
    hasConfiguredEndpointServer(credentials.homeStatic, true) &&
    hasValidSharedResidentialAuth(credentials, false)
  );
}

function hasConfiguredResidentialCredentials(credentials) {
  return (
    hasConfiguredTransitCredentials(credentials) ||
    hasConfiguredHomeStaticCredentials(credentials)
  );
}

function cloneEndpointCredentials(endpoint, sharedAuth) {
  var auth = sharedAuth || { username: "", password: "" };
  return {
    server: endpoint.server,
    port: endpoint.port,
    username: auth.username,
    password: auth.password,
  };
}

function normalizeOverrideMode(mode) {
  if (mode === undefined || mode === null || mode === "") return "merged";
  if (typeof mode !== "string") {
    throw createUserError("USER_OPTIONS.overrideMode 必须是字符串");
  }
  var normalizedMode = mode.toLowerCase();
  if (
    normalizedMode === "merged" ||
    normalizedMode === "option-b" ||
    normalizedMode === "optionb" ||
    normalizedMode === "full"
  ) {
    return "merged";
  }
  if (
    normalizedMode === "dns-sniffer-only" ||
    normalizedMode === "dns-sniffer" ||
    normalizedMode === "dns" ||
    normalizedMode === "option-a" ||
    normalizedMode === "optiona"
  ) {
    return "dns-sniffer-only";
  }
  throw createUserError(
    "未知 USER_OPTIONS.overrideMode: " + mode + "，可选 merged / dns-sniffer-only",
  );
}

function shouldApplyOnlyDnsAndSniffer() {
  return normalizeOverrideMode(USER_OPTIONS.overrideMode) === "dns-sniffer-only";
}

// 解析家宽出口；都未配置则降级为空。
function resolveResidentialExits(credentials) {
  var sharedAuth = getSharedResidentialAuth(credentials);
  return {
    transit: hasConfiguredTransitCredentials(credentials)
      ? cloneEndpointCredentials(credentials.transit, sharedAuth)
      : null,
    homeStatic: hasConfiguredHomeStaticCredentials(credentials)
      ? cloneEndpointCredentials(credentials.homeStatic, sharedAuth)
      : null,
  };
}

function main(config) {
  if (USER_OPTIONS.enabled === false) return config;
  DNS_SNIFFER_MODULE.apply(config);
  if (shouldApplyOnlyDnsAndSniffer()) return config;
  return applyResidentialExit(
    config,
    DNS_SNIFFER_MODULE.DERIVED,
    resolveResidentialExits(RESIDENTIAL_CREDENTIALS),
  );
}
