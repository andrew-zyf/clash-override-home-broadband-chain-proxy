const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const repoRoot = path.resolve(__dirname, "..");
const scriptPath = path.join(repoRoot, "src", "家宽IP-链式代理.js");
const scriptCode = fs.readFileSync(scriptPath, "utf8");

// 关键链路目标和受管规则前缀。
const EXPECTED = {
  chainGroupName: "🇸🇬|新加坡-链式代理-家宽IP出口",
  relayGroupName: "🇸🇬|新加坡线路-链式代理-跳板",
  managedRulePrefix: [
    "PROCESS-NAME,Claude,🇸🇬|新加坡-链式代理-家宽IP出口",
    "PROCESS-NAME,Claude Helper,🇸🇬|新加坡-链式代理-家宽IP出口",
    "PROCESS-NAME,ChatGPT,🇸🇬|新加坡-链式代理-家宽IP出口",
    "PROCESS-NAME,ChatGPT Helper,🇸🇬|新加坡-链式代理-家宽IP出口",
    "PROCESS-NAME,Perplexity,🇸🇬|新加坡-链式代理-家宽IP出口",
    "PROCESS-NAME,Perplexity Helper,🇸🇬|新加坡-链式代理-家宽IP出口",
    "PROCESS-NAME,Cursor,🇸🇬|新加坡-链式代理-家宽IP出口",
    "PROCESS-NAME,Cursor Helper,🇸🇬|新加坡-链式代理-家宽IP出口",
    "PROCESS-NAME,claude,🇸🇬|新加坡-链式代理-家宽IP出口",
    "PROCESS-NAME,gemini,🇸🇬|新加坡-链式代理-家宽IP出口",
    "PROCESS-NAME,codex,🇸🇬|新加坡-链式代理-家宽IP出口"
  ],
  direct: {
    domesticOfficeDomains: [
      "+.docs.qq.com",
      "+.dingtalk.com",
      "+.feishu.cn",
      "+.wps.cn"
    ],
    domesticOfficeRules: [
      "DOMAIN-SUFFIX,docs.qq.com,DIRECT",
      "DOMAIN-SUFFIX,dingtalk.com,DIRECT",
      "DOMAIN-SUFFIX,feishu.cn,DIRECT",
      "DOMAIN-SUFFIX,wps.cn,DIRECT"
    ],
    overseasAppRules: [
      "DOMAIN-SUFFIX,tailscale.com,DIRECT",
      "DOMAIN-SUFFIX,tailscale.io,DIRECT",
      "DOMAIN-SUFFIX,ts.net,DIRECT",
      "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
      "IP-CIDR,100.100.100.100/32,DIRECT,no-resolve",
      "IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve"
    ]
  },
  process: {
    browserManaged: ["Comet", "Dia", "Atlas", "Google Chrome"],
    browserExcluded: ["Arc", "Microsoft Edge"],
    aiCliManaged: ["claude", "gemini", "codex"],
    aiCliExcluded: ["opencode"],
    unmanagedChain: ["Google Drive", "Visual Studio Code"],
    unmanagedDirect: ["WeChat", "Tailscale"]
  },
  dns: {
    overseasPolicyDomains: [
      "+.sora.com",
      "+.notebooklm.google",
      "+.m365.cloud.microsoft"
    ],
    strictSnifferDomains: ["+.claude.ai", "+.google.com"],
    fakeIpDomains: ["+.xboxlive.com", "stun.*.*"],
    overseasAppDomains: ["+.tailscale.com", "+.tailscale.io", "+.ts.net"]
  }
};

// 读取脚本并构造隔离执行环境。
function loadSandbox() {
  const sandbox = {
    console,
    Object,
    Array,
    String,
    Error
  };
  vm.createContext(sandbox);
  vm.runInContext(scriptCode, sandbox, { filename: scriptPath });
  return sandbox;
}

// 构造最小基础配置，只保留当前脚本实际依赖的对象。
function createBaseConfig() {
  return {
    proxies: [
      { name: "🇸🇬 SG Auto 01", type: "ss" },
      { name: "🇭🇰 HK Auto 01", type: "ss" }
    ],
    "proxy-groups": [
      {
        name: "节点选择",
        type: "select",
        proxies: ["🇸🇬 SG Auto 01"]
      }
    ],
    rules: [
      "DOMAIN-SUFFIX,claude.ai,DIRECT",
      "DOMAIN-SUFFIX,tailscale.com,REJECT",
      "MATCH,节点选择"
    ],
    _miya: {
      username: "user",
      password: "pass",
      relay: { server: "1.2.3.4", port: 8000 },
      transit: { server: "transit.example.com", port: 8001 }
    }
  };
}

// 运行主脚本，并允许测试按需覆写配置或沙箱。
function runMain(configMutator, sandboxMutator) {
  const sandbox = loadSandbox();
  const config = createBaseConfig();

  if (typeof sandboxMutator === "function") sandboxMutator(sandbox);
  if (typeof configMutator === "function") configMutator(config);

  return {
    sandbox,
    output: sandbox.main(config)
  };
}

// 提取受管规则身份，用于检查同一规则是否重复注入。
function extractRuleIdentity(ruleLine) {
  const firstCommaIndex = ruleLine.indexOf(",");
  const secondCommaIndex = ruleLine.indexOf(",", firstCommaIndex + 1);
  return ruleLine.slice(0, secondCommaIndex);
}

// 断言规则前缀没有重复身份。
function assertNoDuplicateRuleIdentities(ruleLines) {
  const seen = new Set();
  for (const ruleLine of ruleLines) {
    const identity = extractRuleIdentity(ruleLine);
    if (seen.has(identity)) {
      throw new Error("Duplicate managed rule identity found: " + identity);
    }
    seen.add(identity);
  }
}

function assertRuleExists(ruleLines, ruleLine) {
  assert(ruleLines.includes(ruleLine), "Expected rule not found: " + ruleLine);
}

function assertRuleMissing(ruleLines, ruleLine) {
  assert(!ruleLines.includes(ruleLine), "Unexpected rule found: " + ruleLine);
}

function assertRulesExist(ruleLines, expectedRules) {
  for (const ruleLine of expectedRules) {
    assertRuleExists(ruleLines, ruleLine);
  }
}

function assertRulesMissing(ruleLines, unexpectedRules) {
  for (const ruleLine of unexpectedRules) {
    assertRuleMissing(ruleLines, ruleLine);
  }
}

function assertRulePrefix(actualRules, expectedPrefix) {
  const actualPrefix = Array.prototype.slice.call(actualRules, 0, expectedPrefix.length);
  assert.strictEqual(JSON.stringify(actualPrefix), JSON.stringify(expectedPrefix));
}

function assertProcessRules(output, enabled, processNames, target) {
  for (const processName of processNames) {
    const ruleLine = "PROCESS-NAME," + processName + "," + target;
    if (enabled) assertRuleExists(output.rules, ruleLine);
    else assertRuleMissing(output.rules, ruleLine);
  }
}

function findGroup(output, groupName) {
  return output["proxy-groups"].find((group) => group.name === groupName);
}

function assertNameserverPolicyValues(output, domains, expectedValue) {
  for (const domain of domains) {
    assert.deepStrictEqual(output.dns["nameserver-policy"][domain], expectedValue);
  }
}

function assertArrayIncludesAll(values, expectedValues, label) {
  for (const expectedValue of expectedValues) {
    assert(
      values.includes(expectedValue),
      label + " missing expected value: " + expectedValue
    );
  }
}

function assertArrayExcludesAll(values, excludedValues, label) {
  for (const excludedValue of excludedValues) {
    assert(
      !values.includes(excludedValue),
      label + " unexpectedly contains: " + excludedValue
    );
  }
}

// 严格链式路由必须覆盖域外 AI 主域和受管 AI 进程。
function assertCoreStrictRouting(output) {
  assertRulesExist(output.rules, [
    "DOMAIN-SUFFIX,claude.ai," + EXPECTED.chainGroupName,
    "DOMAIN-SUFFIX,google.com," + EXPECTED.chainGroupName,
    "DOMAIN-SUFFIX,youtube.com," + EXPECTED.chainGroupName,
    "PROCESS-NAME,Claude," + EXPECTED.chainGroupName,
    "PROCESS-NAME,claude," + EXPECTED.chainGroupName
  ]);
  assertRulesMissing(output.rules, [
    "PROCESS-NAME,Comet," + EXPECTED.chainGroupName,
    "DOMAIN-SUFFIX,claude.ai,DIRECT"
  ]);
}

// 域内办公域名只走 DIRECT，不再依赖进程规则。
function assertDomesticDirectCoverage(output, sandbox) {
  assertRulesExist(output.rules, EXPECTED.direct.domesticOfficeRules);
  assertRulesMissing(output.rules, [
    "PROCESS-NAME,WeChat,DIRECT",
    "PROCESS-NAME,DingTalk,DIRECT",
    "PROCESS-NAME,Feishu,DIRECT",
    "PROCESS-NAME,WPS Office,DIRECT"
  ]);
  assertNameserverPolicyValues(
    output,
    EXPECTED.direct.domesticOfficeDomains,
    sandbox.BASE.dns.domestic
  );
}

// 域外应用直连保持 DIRECT、域外 DoH 和 skip-domain 组合。
function assertOverseasAppDirectCoverage(output, sandbox) {
  assertRulesExist(output.rules, EXPECTED.direct.overseasAppRules);
  assertRulesMissing(output.rules, [
    "PROCESS-NAME,Tailscale,DIRECT",
    "PROCESS-NAME,tailscale,DIRECT",
    "PROCESS-NAME,IPNExtension,DIRECT"
  ]);
  assertNameserverPolicyValues(
    output,
    EXPECTED.dns.overseasAppDomains,
    sandbox.BASE.dns.overseas
  );
  assertArrayIncludesAll(
    output.dns["fallback-filter"].domain,
    EXPECTED.dns.overseasAppDomains,
    "fallback-filter.domain"
  );
  assertArrayIncludesAll(
    output.sniffer["skip-domain"],
    EXPECTED.dns.overseasAppDomains,
    "sniffer.skip-domain"
  );
  assertArrayExcludesAll(
    output.dns["fake-ip-filter"],
    ["+.tailscale.com"],
    "fake-ip-filter"
  );
}

// DNS 和 Sniffer 仍要覆盖关键域外 AI 与支撑平台。
function assertDnsAndSniffer(output, sandbox) {
  assertNameserverPolicyValues(
    output,
    EXPECTED.dns.overseasPolicyDomains,
    sandbox.BASE.dns.overseas
  );
  assertArrayIncludesAll(
    output.dns["fake-ip-filter"],
    EXPECTED.dns.fakeIpDomains,
    "fake-ip-filter"
  );
  assertArrayIncludesAll(
    output.dns["fallback-filter"].domain,
    ["+.sora.com", "+.youtube.com"],
    "fallback-filter.domain"
  );
  assertArrayIncludesAll(
    output.sniffer["force-domain"],
    EXPECTED.dns.strictSnifferDomains,
    "sniffer.force-domain"
  );
}

function testDefaultConfig() {
  const result = runMain();
  const sandbox = result.sandbox;
  const output = result.output;

  assert.strictEqual(sandbox.USER_OPTIONS.enableBrowserProcessProxy, false);
  assert.strictEqual(output._miya, undefined);
  assert.strictEqual(
    output.proxies.find((proxy) => proxy.name === "自选节点 + 家宽IP")["dialer-proxy"],
    EXPECTED.relayGroupName
  );
  assert(findGroup(output, EXPECTED.chainGroupName), "Expected chain group to exist");

  assertCoreStrictRouting(output);
  assertDomesticDirectCoverage(output, sandbox);
  assertOverseasAppDirectCoverage(output, sandbox);
  assertDnsAndSniffer(output, sandbox);
  assertNoDuplicateRuleIdentities(output.rules.slice(0, 250));
  assertRulePrefix(output.rules, EXPECTED.managedRulePrefix);
}

function testEnableBrowserProcessProxy() {
  const output = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.enableBrowserProcessProxy = true;
  }).output;

  assertProcessRules(
    output,
    true,
    EXPECTED.process.browserManaged,
    EXPECTED.chainGroupName
  );
  assertProcessRules(
    output,
    false,
    EXPECTED.process.browserExcluded,
    EXPECTED.chainGroupName
  );
}

function testAiCliProcessProxyDefaultsOn() {
  const output = runMain().output;
  assertProcessRules(
    output,
    true,
    EXPECTED.process.aiCliManaged,
    EXPECTED.chainGroupName
  );
  assertProcessRules(
    output,
    false,
    EXPECTED.process.aiCliExcluded,
    EXPECTED.chainGroupName
  );
}

function testDisableAiCliProcessProxy() {
  const output = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.enableAiCliProcessProxy = false;
  }).output;

  assertProcessRules(
    output,
    false,
    EXPECTED.process.aiCliManaged.concat(EXPECTED.process.aiCliExcluded),
    EXPECTED.chainGroupName
  );
}

function testOnlyAiAndBrowserProcessesAreManaged() {
  const output = runMain().output;

  assertProcessRules(
    output,
    false,
    EXPECTED.process.unmanagedChain,
    EXPECTED.chainGroupName
  );
  assertRulesMissing(
    output.rules,
    EXPECTED.process.unmanagedDirect.map(function (processName) {
      return "PROCESS-NAME," + processName + ",DIRECT";
    })
  );
}

function testMissingRegionFails() {
  const sandbox = loadSandbox();
  const config = createBaseConfig();
  config.proxies = config.proxies.filter(function (proxy) {
    return proxy.name.indexOf("🇸🇬") < 0;
  });
  config["proxy-groups"] = [{ name: "节点选择", type: "select", proxies: ["🇭🇰 HK Auto 01"] }];
  sandbox.USER_OPTIONS.chainRegion = "US";

  assert.throws(
    function () {
      sandbox.main(config);
    },
    /未找到可用的 US 跳板节点或代理组/
  );
}

function testMissingStrictTargetFails() {
  const sandbox = loadSandbox();
  const originalResolveRoutingTargets = sandbox.resolveRoutingTargets;
  sandbox.resolveRoutingTargets = function (config, region) {
    const routingTargets = originalResolveRoutingTargets(config, region);
    routingTargets.strictAiTarget = "错误目标";
    return routingTargets;
  };

  assert.throws(
    function () {
      sandbox.main(createBaseConfig());
    },
    /域外 AI 与支撑平台未直接指向当前 chainRegion 出口/
  );
}

testDefaultConfig();
testEnableBrowserProcessProxy();
testAiCliProcessProxyDefaultsOn();
testDisableAiCliProcessProxy();
testOnlyAiAndBrowserProcessesAreManaged();
testMissingRegionFails();
testMissingStrictTargetFails();

console.log("validate.js: all checks passed");
