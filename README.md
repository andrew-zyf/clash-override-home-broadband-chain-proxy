![封面图](img/封面图.png)

# 用家宽 IP 访问 Claude / ChatGPT 的 Clash 链式代理覆写

借助机场 + 家宽 IP 的链式代理，把域外 AI 服务的出口切到住宅 IP，同时避免因为规则遗漏、DNS 分类错误或错误地区回退，把流量送到直连或不想要的地区。

> 开源仓库：[github.com/andrew-zyf/clash-override-chain-proxy](https://github.com/andrew-zyf/clash-override-chain-proxy)
>
> 当前主脚本版本：`v8.6`
>
> 当前 README 与进程规则按 **macOS / MacBook** 环境维护。

## 这份脚本现在保证什么

- 你手动选择哪个 `chainRegion`，域外 AI 网站、服务、支撑平台和验证站点就强制走哪个地区的家宽出口
- 如果当前 `chainRegion` 找不到可用跳板，或者关键规则没正确指向该出口，脚本直接报错，不静默回退
- 域内直连、域外应用直连、网络地址直连保持 `DIRECT`
- DNS、Sniffer、规则三层使用同一套分类，不让 AI 主站和支撑平台在解析阶段先跑偏

这份脚本不保证“永不封号”。它保证的是：不会因为这份覆写脚本自身的静默退化、规则冲突或配置遗漏，把你送到直连或错误地区。

## 工作原理

```text
请求 → Clash → 跳板节点（机场线路） → MiyaIP 家宽IP → 目标服务
                  ↑ dialer-proxy           ↑ HTTP 代理
```

脚本在覆写阶段做六件事：

1. 注入 MiyaIP 家宽出口与官方中转节点
2. 先覆写 DNS，让域外 AI / 支撑平台 / 域外应用直连走域外 DoH，Apple / 域内直连走域内 DoH
3. 再覆写 Sniffer，让 AI 主站和支撑平台优先保留域名语义
4. 解析当前 `chainRegion` 的跳板组和家宽出口组
5. 注入并置顶 AI 强制家宽链式代理、普通链式代理、三类 `DIRECT` 规则
6. 校验关键规则是否真正写入当前 `chainRegion` 出口，若失败则报错

## 文件说明

- **[`src/家宽IP-链式代理.js`](src/%E5%AE%B6%E5%AE%BDIP-%E9%93%BE%E5%BC%8F%E4%BB%A3%E7%90%86.js)**：主脚本，全部逻辑都在这里
- **[`src/MiyaIP 凭证_样本.js`](src/MiyaIP%20%E5%87%AD%E8%AF%81_%E6%A0%B7%E6%9C%AC.js)**：凭证模板
- **[`tests/validate.js`](tests/validate.js)**：本地回归校验脚本

## 配置流程

先准备四样东西：

1. **Clash Party**：[GitHub 下载](https://github.com/mihomo-party-org/clash-party)
2. **机场订阅**：推荐 [办公娱乐好帮手](https://xn--9kq10e0y7h.site/index.html?register=twb6RIec)
3. **静态家宽 IP**：推荐 [MiyaIP](https://www.miyaip.com/?invitecode=7670643)
4. **本仓库脚本**：[`src/MiyaIP 凭证_样本.js`](src/MiyaIP%20%E5%87%AD%E8%AF%81_%E6%A0%B7%E6%9C%AC.js) 和 [`src/家宽IP-链式代理.js`](src/%E5%AE%B6%E5%AE%BDIP-%E9%93%BE%E5%BC%8F%E4%BB%A3%E7%90%86.js)

### 1. 导入机场订阅

把订阅导入 Clash Party。订阅里的节点是这份脚本的跳板来源。脚本会优先复用现成的地区代理组；没有就按地区自动生成。

### 2. 创建凭证文件

复制 [`src/MiyaIP 凭证_样本.js`](src/MiyaIP%20%E5%87%AD%E8%AF%81_%E6%A0%B7%E6%9C%AC.js) 为 `MiyaIP 凭证.js`，填入真实信息：

```javascript
function main(config) {
  config._miya = {
    username: "你的用户名",
    password: "你的密码",
    relay: {
      server: "12.34.56.78",
      port: 8022,
    },
    transit: {
      server: "transit.miyaip.com",
      port: 8001,
    },
  };
  return config;
}
```

### 3. 在 Clash Party 中按顺序导入两个覆写脚本

1. `MiyaIP 凭证.js`
2. [`家宽IP-链式代理.js`](src/%E5%AE%B6%E5%AE%BDIP-%E9%93%BE%E5%BC%8F%E4%BB%A3%E7%90%86.js)

凭证脚本必须排在前面，否则主脚本读不到 `config._miya`。

![Clash Party 覆写页面](img/Clash%20Party%20覆写.png)

### 4. 调整参数

[`src/家宽IP-链式代理.js`](src/%E5%AE%B6%E5%AE%BDIP-%E9%93%BE%E5%BC%8F%E4%BB%A3%E7%90%86.js) 顶部只有四个用户参数：

```javascript
var USER_OPTIONS = {
  chainRegion: "SG",
  manualNode: "",
  enableBrowserProcessProxy: false,
  enableAiCliProcessProxy: true,
};
```

- `chainRegion`：`US / JP / HK / SG`，决定域外 AI 和支撑平台当前从哪个地区的家宽出口出去
- `manualNode`：手动指定跳板节点名；留空则自动匹配该地区可用节点或地区组
- `enableBrowserProcessProxy`：默认 `false`，是否让 `Comet`、`Dia`、`Atlas`、`Google Chrome` 及其 helper 走普通链式代理
- `enableAiCliProcessProxy`：默认 `true`，是否让 `claude`、`gemini`、`codex` 走链式代理

### 5. 启用并验证

1. 打开两个覆写脚本
2. 切回机场配置并启动代理
3. 在 Clash Party 中确认：
   - 使用 **规则模式**
   - 开启 **TUN 模式**
4. 在代理组中确认：
   - 有当前地区的跳板组
   - 有当前地区的家宽出口组，例如 `🇸🇬|新加坡-链式代理-家宽IP出口`
5. 访问 [ping0.cc](https://ping0.cc/) 或 [ipinfo.io](https://ipinfo.io/)，确认出口是住宅 IP
6. 打开 [claude.ai](https://claude.ai/) 或 ChatGPT macOS App，确认命中当前 `chainRegion` 的家宽出口组

![Clash Party 代理组页面](img/Clash%20Party%20代理组.png)

## 分流一览

- **域外 AI 与支撑平台**：直接命中当前 `chainRegion` 的家宽出口。包括 Claude、ChatGPT、Sora、Gemini、NotebookLM、Perplexity、OpenRouter、Grok / xAI，以及 Google、Microsoft、GitHub、VS Code 等登录、下载、IDE 相关平台
- **AI 进程管控**：只保留 AI App 与 AI CLI。当前默认覆盖 `Claude`、`ChatGPT`、`Perplexity`、`Cursor`，以及 `claude`、`gemini`、`codex`
- **浏览器进程管控**：可选进入普通链式代理，默认关闭；当前只维护 `Comet`、`Dia`、`Atlas`、`Google Chrome` 及其明显 helper
- **社交与流媒体**：走普通链式代理，跟随 `chainRegion`
- **域内直连**：固定 `DIRECT`。包括域内 AI，以及腾讯、阿里、字节、WPS 的主力办公 / 沟通 / 协作产品相关域名
- **域外应用直连**：固定 `DIRECT + DOH_OVERSEAS + skip-domain`。当前先实装 `Tailscale`；`Typeless` 预留到后续补充
- **网络地址直连**：固定 `DIRECT`。当前主要是 Tailnet 地址段

## 本地校验

修改规则后，建议跑一遍：

```bash
node tests/validate.js
```

[`tests/validate.js`](tests/validate.js) 会检查：

- 管理规则不重复
- AI 严格链式代理规则优先于普通链式代理和 `DIRECT` 规则
- 域外 AI 与支撑平台是否直接指向当前 `chainRegion` 出口
- 浏览器和 AI CLI 开关是否只影响各自进程规则
- 只有 AI 与浏览器服务保留进程管控，其它类别不再写 `PROCESS-NAME`
- 域内直连、域外应用直连、网络地址直连是否仍命中预期规则
- DNS `nameserver-policy`、`fallback-filter`、Sniffer 是否仍覆盖关键对象，且域外应用直连不会覆盖 AI 严格链式代理
- 找不到可用地区跳板或 `manualNode` 无效时，是否直接报错

## 常见问题

- **报错“缺少 `config._miya`”**：覆写顺序反了，`MiyaIP 凭证.js` 必须排在主脚本前面
- **出口不是住宅 IP**：优先检查 MiyaIP 凭证、账户余额和中转信息
- **报错找不到可用地区跳板**：当前 `chainRegion` 在你的订阅里没有对应地区节点，或者节点命名无法被脚本识别；改 `chainRegion` 或填写 `manualNode`
- **为什么浏览器默认不是整进程代理**：因为浏览器里有大量普通网站流量，默认把整个浏览器送入链式代理，副作用太大
- **为什么只保留 AI 和浏览器的进程管控**：因为它们最容易绕开纯域名分流，且最直接影响域外 AI 的出口一致性；其它类别进程规则过多，会增加误伤和维护成本
- **为什么有“域外应用直连”**：像 Tailscale 这类对象需要 `DIRECT`，但 DNS 仍应固定走域外 DoH，避免因为解析落到国内或错误链路，暴露异常区域画像

## 兼容性

- 运行环境：Clash Party 的 JavaScriptCore
- 语法范围：ES5
- 进程分流覆盖：当前只维护 macOS 常见命名
