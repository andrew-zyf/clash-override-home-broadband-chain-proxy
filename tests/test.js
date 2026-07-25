// 家宽出口覆写 — 测试套件（16 单元 + 30 集成）
//
// 覆盖 residential-exit-override.js 的纯函数与端到端行为。
// 运行：node tests/test.js

"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const overridePath = path.join(
  __dirname,
  "..",
  "src",
  "residential-exit-override.js",
);
const overrideCode = fs.readFileSync(overridePath, "utf8");

const TEST_SHARED_AUTH = {
  username: "user",
  password: "pass",
};

const TEST_TRANSIT = {
  server: "residential-transit.test",
  port: 8001,
};

const TEST_HOME_STATIC = {
  server: "192.168.1.1",
  port: 1080,
};

const EMPTY_CREDENTIALS = {
  username: "",
  password: "",
  transit: { server: "", port: 8001 },
  homeStatic: { server: "", port: 1080 },
};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

function loadSandbox() {
  const sandbox = { console, Object, Array, String, Error };
  vm.createContext(sandbox);
  vm.runInContext(overrideCode, sandbox, { filename: overridePath });
  return sandbox;
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function baseConfig() {
  return {
    proxies: [
      { name: "🇸🇬 SG Auto 01", type: "ss" },
      { name: "🇭🇰 HK Auto 01", type: "ss" },
      { name: "🇺🇸 US Auto 01", type: "ss" },
    ],
    "proxy-groups": [
      { name: "PROXY", type: "select", proxies: ["🇸🇬 SG Auto 01"] },
    ],
    rules: [
      "DOMAIN-SUFFIX,claude.ai,DIRECT",
      "DOMAIN-SUFFIX,tailscale.com,REJECT",
      "MATCH,PROXY",
    ],
  };
}

function runMain(configMutator, sandboxMutator) {
  const sandbox = loadSandbox();
  sandbox.RESIDENTIAL_CREDENTIALS = {
    username: TEST_SHARED_AUTH.username,
    password: TEST_SHARED_AUTH.password,
    transit: cloneJson(TEST_TRANSIT),
    homeStatic: { server: "", port: 1080 },
  };
  if (typeof sandboxMutator === "function") sandboxMutator(sandbox);

  let config = baseConfig();
  if (typeof configMutator === "function") {
    config = configMutator(config, sandbox) || config;
  }

  return {
    sandbox,
    derived: cloneJson(sandbox.DNS_SNIFFER_MODULE.DERIVED),
    dnsBase: cloneJson(sandbox.DNS_SNIFFER_MODULE.BASE.dns),
    output: sandbox.main(config),
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function findGroup(output, name) {
  return (output["proxy-groups"] || []).find((g) => g.name === name);
}

function findProxy(output, name) {
  return (output.proxies || []).find((p) => p.name === name);
}

function regionGroup(sandbox, code) {
  return sandbox.buildRegionGroupName(
    sandbox.resolveRegionMeta(code),
    sandbox.BASE.groupNameSuffixes.base,
  );
}

function regionOrder(output, sandbox) {
  const order = [];
  const us = regionGroup(sandbox, "US");
  if (findGroup(output, us)) order.push(us);
  for (const code of ["JP", "SG", "HK"]) {
    const name = regionGroup(sandbox, code);
    if (findGroup(output, name)) order.push(name);
  }
  return order;
}

function residentialExitNames(output, sandbox) {
  const names = [];
  if (findProxy(output, sandbox.BASE.nodeNames.homeStatic)) {
    names.push(sandbox.BASE.nodeNames.homeStatic);
  }
  if (findProxy(output, sandbox.BASE.nodeNames.transit)) {
    names.push(sandbox.BASE.nodeNames.transit);
  }
  names.push(sandbox.BASE.residentialGroupName);
  return names;
}

function expectedAntiBanChoices(output, sandbox) {
  const names = [];
  if (findProxy(output, sandbox.BASE.nodeNames.homeStatic)) {
    names.push(sandbox.BASE.nodeNames.homeStatic);
  }
  if (findProxy(output, sandbox.BASE.nodeNames.transit)) {
    names.push(sandbox.BASE.nodeNames.transit);
  }
  if (names.length > 0) return names;
  return [sandbox.BASE.residentialGroupName];
}

function expectedUnlockChoices(output, sandbox) {
  return regionOrder(output, sandbox).concat(
    residentialExitNames(output, sandbox),
  );
}

function preferredAntiBan(output, sandbox) {
  if (findProxy(output, sandbox.BASE.nodeNames.homeStatic)) {
    return sandbox.BASE.nodeNames.homeStatic;
  }
  if (findProxy(output, sandbox.BASE.nodeNames.transit)) {
    return sandbox.BASE.nodeNames.transit;
  }
  return sandbox.BASE.residentialGroupName;
}

function preferredUnlock(output, sandbox) {
  const us = regionGroup(sandbox, "US");
  if (findGroup(output, us)) return us;
  return preferredAntiBan(output, sandbox);
}

function suffixRule(domain, target) {
  return "DOMAIN-SUFFIX," + domain + "," + target;
}

function processRule(name, target) {
  return "PROCESS-NAME," + name + "," + target;
}

function assertRulesExist(rules, expected) {
  for (const line of expected) {
    assert(rules.includes(line), "missing rule: " + line);
  }
}

function assertRulesMissing(rules, unexpected) {
  for (const line of unexpected) {
    assert(!rules.includes(line), "unexpected rule: " + line);
  }
}

function assertBefore(rules, earlier, later) {
  const i = rules.indexOf(earlier);
  const j = rules.indexOf(later);
  assert(i >= 0, "missing earlier: " + earlier);
  assert(j >= 0, "missing later: " + later);
  assert(i < j, "order: " + earlier + " before " + later);
}

function assertIncludes(list, expected, label) {
  for (const v of expected) {
    assert(list.includes(v), label + " missing: " + v);
  }
}

function assertExcludes(list, unexpected, label) {
  for (const v of unexpected) {
    assert(!list.includes(v), label + " has: " + v);
  }
}

function assertNsPolicy(output, domains, expected) {
  for (const domain of domains) {
    assert.deepEqual(output.dns["nameserver-policy"][domain], expected);
  }
}

function sameSet(a, b) {
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every((v) => set.has(v));
}

function ruleIdentity(line) {
  const first = line.indexOf(",");
  const second = line.indexOf(",", first + 1);
  return line.slice(0, second);
}

// ===========================================================================
// Unit tests (16)
// ===========================================================================

const S = loadSandbox();

function testToSuffix() {
  assert.strictEqual(S.toSuffix("+.claude.ai"), "claude.ai");
  assert.strictEqual(S.toSuffix("claude.ai"), "claude.ai");
  assert.strictEqual(S.toSuffix("+."), "");
  assert.strictEqual(S.toSuffix(""), "");
}

function testUniqueStrings() {
  const a = (v) => Array.prototype.slice.call(v);
  assert.deepStrictEqual(a(S.uniqueStrings(["a", "b", "a"])), ["a", "b"]);
  assert.deepStrictEqual(a(S.uniqueStrings([])), []);
}

function testBuildStringLookup() {
  const lookup = S.buildStringLookup(["a", "b"]);
  assert.strictEqual(lookup.a, true);
  assert.strictEqual(lookup.c, undefined);
  assert.strictEqual(Object.keys(S.buildStringLookup([])).length, 0);
}

function testCreateUserError() {
  const err = S.createUserError("boom");
  assert(err instanceof Error);
  assert.strictEqual(err.message, "boom");
}

function testNormalizeOverrideMode() {
  assert.strictEqual(S.normalizeOverrideMode("merged"), "merged");
  assert.strictEqual(S.normalizeOverrideMode("dns-sniffer-only"), "dns-sniffer-only");
  assert.strictEqual(S.normalizeOverrideMode("full"), "merged");
  assert.strictEqual(S.normalizeOverrideMode("dns"), "dns-sniffer-only");
  assert.strictEqual(S.normalizeOverrideMode(""), "merged");
  assert.throws(() => S.normalizeOverrideMode("invalid"), /未知/);
  assert.throws(() => S.normalizeOverrideMode(1), /必须是字符串/);
}

function testVersionMarker() {
  assert(overrideCode.includes("// @version 14.33"));
  const lines = overrideCode.split("\n").filter((l) => l.includes("@version "));
  assert.strictEqual(lines.length, 1);
}

function testUiGroupNames() {
  assert.strictEqual(S.UI_GROUPS.strictExit, "az.严管调度.🏠 防封出口");
  assert.strictEqual(S.UI_GROUPS.ai, "az.严管调度.🤖 AI 服务");
  assert.strictEqual(S.UI_GROUPS.support, "az.严管调度.🔑 登录旁路");
  assert.strictEqual(S.UI_GROUPS.integrations, "az.严管调度.💳 支付验证");
  assert.strictEqual(S.UI_GROUPS.otherExit, "az.其他调度.🌏 解锁出口");
  assert.strictEqual(S.BASE.residentialGroupName, "az.核心出口.🏠 家宽出口");
  assert.notStrictEqual(S.UI_GROUPS.strictExit, S.UI_GROUPS.otherExit);
}

function testScriptHygiene() {
  assert(!new RegExp("Mi" + "ya", "i").test(overrideCode));
  assert(!overrideCode.includes(["routeBrowser", "ToResidential", "Exit"].join("")));
  assert(!overrideCode.includes(["办公", "娱乐", "好帮手"].join("")));
}

function testDefaultProxyKeywords() {
  assert.deepEqual(S.BASE.defaultProxyGroupKeywords, [
    "PROXY",
    "节点选择",
    "手动选择",
    "GLOBAL",
  ]);
}

function testFakeIpBypass() {
  const bip = S.DNS_SNIFFER_MODULE.FAKE_IP_BYPASS;
  assert(bip.localNetwork.includes("+.lan"));
  assert(!bip.localNetwork.includes("+.push.apple.com"));
  assert(bip.timeSync.includes("ntp.*.com"));
  assert(bip.timeSync.includes("+.pool.ntp.org"));
  assert(!bip.timeSync.includes("pool.ntp.org"));
  assert(bip.stunRealtime.includes("stun.*.*"));
}

function testDnsFakeIpFilterDnsOnly() {
  const sandbox = loadSandbox();
  sandbox.USER_OPTIONS.overrideMode = "dns-sniffer-only";
  sandbox.RESIDENTIAL_CREDENTIALS = cloneJson(EMPTY_CREDENTIALS);
  const output = sandbox.main({ proxies: [], "proxy-groups": [], rules: [] });
  const fif = output.dns["fake-ip-filter"];
  assertIncludes(fif, ["+.apple.com", "ntp.*.com", "stun.*.*", "+.xboxlive.com"], "fif");
  assert.strictEqual(output._residential, undefined);
}

function testCredentialValidation() {
  const fn = S.hasConfiguredResidentialCredentials;
  assert.strictEqual(
    fn({
      username: "u",
      password: "p",
      transit: { server: "5.6.7.8", port: 443 },
      homeStatic: { server: "", port: 1080 },
    }),
    true,
  );
  assert.strictEqual(
    fn({
      username: "u",
      password: "p",
      transit: { server: "5.6.7.8", port: 65536 },
      homeStatic: { server: "", port: 1080 },
    }),
    false,
  );
  assert.strictEqual(
    fn({
      username: "你的用户名",
      password: "你的密码",
      transit: { server: "ok.example.org", port: 8001 },
      homeStatic: { server: "", port: 1080 },
    }),
    false,
  );
  assert.strictEqual(
    fn({
      username: "u",
      password: "p",
      transit: { server: "transit.example.com", port: 8001 },
      homeStatic: { server: "", port: 1080 },
    }),
    false,
  );
  assert.strictEqual(fn(S.RESIDENTIAL_CREDENTIALS), false);
  assert.strictEqual(
    S.hasConfiguredHomeStaticCredentials({
      username: "",
      password: "",
      homeStatic: { server: "192.168.1.1", port: 1080 },
    }),
    true,
  );
  assert.strictEqual(
    S.hasConfiguredHomeStaticCredentials({
      username: "",
      password: "",
      homeStatic: { server: "localhost", port: 1080 },
    }),
    true,
  );
  assert.strictEqual(
    S.hasConfiguredHomeStaticCredentials({
      username: "",
      password: "",
      homeStatic: { server: "home.example.com", port: 1080 },
    }),
    false,
  );
  // 共用认证注入到两个出口
  const exits = S.resolveResidentialExits({
    username: "shared-user",
    password: "shared-pass",
    transit: { server: "5.6.7.8", port: 8001 },
    homeStatic: { server: "10.0.0.2", port: 1080 },
  });
  assert.strictEqual(exits.transit.username, "shared-user");
  assert.strictEqual(exits.homeStatic.username, "shared-user");
  assert.strictEqual(exits.homeStatic.password, "shared-pass");
}

function testValidProxyTypes() {
  assertIncludes(S.BASE.validProxyTypes, ["http", "https", "socks5"], "types");
}

function testBuildExitProxies() {
  const transit = S.buildResidentialSocksProxy(
    { server: "1.2.3.4", port: 8080, username: "u", password: "p" },
    "t",
  );
  assert.strictEqual(transit.type, "socks5");
  assert.strictEqual(transit.udp, true);
  assert.strictEqual(transit.username, "u");

  const home = S.buildResidentialSocksProxy(
    { server: "10.0.0.1", port: 1080, username: "", password: "" },
    "h",
  );
  assert.strictEqual(home.type, "socks5");
  assert.strictEqual(home.username, undefined);

  assert.strictEqual(S.BASE.nodeNames.transit, "家宽出口（官方中转）");
  assert.strictEqual(S.BASE.nodeNames.homeStatic, "家宽出口（静态IP）");

  const saved = S.BASE.validProxyTypes.slice();
  S.BASE.validProxyTypes.splice(S.BASE.validProxyTypes.indexOf("socks5"), 1);
  try {
    assert.throws(
      () =>
        S.buildResidentialSocksProxy(
          { server: "1.2.3.4", port: 8080, username: "u", password: "p" },
          "t",
        ),
      /socks5 不在/,
    );
  } finally {
    S.BASE.validProxyTypes.length = 0;
    S.BASE.validProxyTypes.push.apply(S.BASE.validProxyTypes, saved);
  }
}

function testBuildStrictAntiBanExitChoices() {
  const home = S.BASE.residentialGroupName;
  // 有实体节点时只挂扁平节点，不套家宽组
  assert.deepEqual(S.buildStrictAntiBanExitChoices(["a", "b"], home), [
    "a",
    "b",
  ]);
  assert.deepEqual(S.buildStrictAntiBanExitChoices([], home), [home]);
}

function testBuildOtherUnlockExitChoices() {
  const home = S.BASE.residentialGroupName;
  const regional = {
    US: "az.US",
    JP: "az.JP",
    SG: "az.SG",
    HK: "az.HK",
  };
  assert.deepEqual(
    S.buildOtherUnlockExitChoices(["node"], home, regional),
    ["az.US", "az.JP", "az.SG", "az.HK", "node", home],
  );
}

const unitTests = [
  ["toSuffix", testToSuffix],
  ["uniqueStrings", testUniqueStrings],
  ["buildStringLookup", testBuildStringLookup],
  ["createUserError", testCreateUserError],
  ["normalizeOverrideMode", testNormalizeOverrideMode],
  ["versionMarker", testVersionMarker],
  ["uiGroupNames", testUiGroupNames],
  ["scriptHygiene", testScriptHygiene],
  ["defaultProxyKeywords", testDefaultProxyKeywords],
  ["fakeIpBypass", testFakeIpBypass],
  ["dnsFakeIpFilterDnsOnly", testDnsFakeIpFilterDnsOnly],
  ["credentialValidation", testCredentialValidation],
  ["validProxyTypes", testValidProxyTypes],
  ["buildExitProxies", testBuildExitProxies],
  ["buildStrictAntiBanExitChoices", testBuildStrictAntiBanExitChoices],
  ["buildOtherUnlockExitChoices", testBuildOtherUnlockExitChoices],
];

// ===========================================================================
// Integration tests (30)
// ===========================================================================

function testMergedHappyPath() {
  const { sandbox, output } = runMain();
  assert.strictEqual(output._residential, undefined);
  assert.strictEqual(
    output.rules[0],
    "AND,((NETWORK,udp),(DST-PORT,443)),REJECT",
  );

  const transit = findProxy(output, sandbox.BASE.nodeNames.transit);
  assert(transit);
  assert.strictEqual(transit.type, "socks5");
  assert.strictEqual(transit.server, TEST_TRANSIT.server);
  assert.strictEqual(findProxy(output, sandbox.BASE.nodeNames.homeStatic), undefined);

  const residential = findGroup(output, sandbox.BASE.residentialGroupName);
  assert(sameSet(residential.proxies, [sandbox.BASE.nodeNames.transit]));

  const proxy = findGroup(output, "PROXY");
  assert.strictEqual(
    proxy.proxies[0],
    sandbox.UI_GROUPS.strictExit,
    "PROXY should lead with anti-ban exit",
  );
  assertIncludes(
    proxy.proxies,
    [
      sandbox.BASE.residentialGroupName,
      regionGroup(sandbox, "US"),
      sandbox.UI_GROUPS.strictExit,
      sandbox.UI_GROUPS.otherExit,
    ],
    "PROXY",
  );

  const ids = new Set();
  for (const line of output.rules) {
    const id = ruleIdentity(line);
    assert(!ids.has(id), "duplicate rule id: " + id);
    ids.add(id);
  }
}

function testAntiBanAndUnlockExits() {
  const { sandbox, output } = runMain();
  const antiBan = findGroup(output, sandbox.UI_GROUPS.strictExit);
  const unlock = findGroup(output, sandbox.UI_GROUPS.otherExit);

  assert.deepEqual(antiBan.proxies, expectedAntiBanChoices(output, sandbox));
  assert.strictEqual(antiBan.proxies[0], preferredAntiBan(output, sandbox));
  for (const region of regionOrder(output, sandbox)) {
    assert(antiBan.proxies.indexOf(region) < 0, "anti-ban has region: " + region);
  }

  assert.deepEqual(unlock.proxies, expectedUnlockChoices(output, sandbox));
  assert.strictEqual(unlock.proxies[0], preferredUnlock(output, sandbox));
}

function testCategoryExitCoupling() {
  const { sandbox, output } = runMain();
  for (const name of [
    sandbox.UI_GROUPS.ai,
    sandbox.UI_GROUPS.support,
    sandbox.UI_GROUPS.integrations,
  ]) {
    assert.deepEqual(findGroup(output, name).proxies, [sandbox.UI_GROUPS.strictExit]);
  }
  for (const name of [
    sandbox.UI_GROUPS.video,
    sandbox.UI_GROUPS.music,
    sandbox.UI_GROUPS.social,
    sandbox.UI_GROUPS.im,
  ]) {
    assert.deepEqual(findGroup(output, name).proxies, [sandbox.UI_GROUPS.otherExit]);
  }
}

function testBrokenStrictCouplingFails() {
  assert.throws(
    () =>
      runMain(null, (sb) => {
        const original = sb.writeExpandedProxyGroups;
        sb.writeExpandedProxyGroups = function (
          config,
          residentialTarget,
          regionalTargets,
          exitNodeNames,
        ) {
          original(config, residentialTarget, regionalTargets, exitNodeNames);
          const ai = config["proxy-groups"].find((g) => g.name === sb.UI_GROUPS.ai);
          ai.proxies = ["DIRECT"];
        };
      }),
    /严管防封分类面板必须只挂出口总闸/,
  );
}

function testEmptyCredentialsDegrade() {
  const { sandbox, output } = runMain(null, (sb) => {
    sb.RESIDENTIAL_CREDENTIALS = cloneJson(EMPTY_CREDENTIALS);
  });
  assert.strictEqual(findProxy(output, sandbox.BASE.nodeNames.transit), undefined);
  assert.strictEqual(findProxy(output, sandbox.BASE.nodeNames.homeStatic), undefined);
  const residential = findGroup(output, sandbox.BASE.residentialGroupName);
  assert(residential.proxies.length > 0);
  assert.deepEqual(
    findGroup(output, sandbox.UI_GROUPS.strictExit).proxies,
    [sandbox.BASE.residentialGroupName],
  );
  assert.strictEqual(output.dns.enable, true);
  assertRulesExist(output.rules, [suffixRule("claude.ai", sandbox.UI_GROUPS.ai)]);
}

function testPlaceholderCredentialsDegrade() {
  const { sandbox, output } = runMain(null, (sb) => {
    sb.RESIDENTIAL_CREDENTIALS = {
      username: "你的用户名",
      password: "你的密码",
      transit: { server: "transit.example.com", port: 8001 },
      homeStatic: { server: "home.example.com", port: 1080 },
    };
  });
  assert.strictEqual(findProxy(output, sandbox.BASE.nodeNames.transit), undefined);
  assert.strictEqual(findProxy(output, sandbox.BASE.nodeNames.homeStatic), undefined);
  assert(findGroup(output, sandbox.UI_GROUPS.ai));
}

function testHomeStaticOnly() {
  const { sandbox, output } = runMain(null, (sb) => {
    sb.RESIDENTIAL_CREDENTIALS = {
      username: "",
      password: "",
      transit: { server: "", port: 8001 },
      homeStatic: cloneJson(TEST_HOME_STATIC),
    };
  });
  const home = findProxy(output, sandbox.BASE.nodeNames.homeStatic);
  assert.strictEqual(home.type, "socks5");
  assert.strictEqual(home.server, TEST_HOME_STATIC.server);
  assert.strictEqual(home.username, undefined);
  assert.strictEqual(findProxy(output, sandbox.BASE.nodeNames.transit), undefined);
  assert.deepEqual(findGroup(output, sandbox.BASE.residentialGroupName).proxies, [
    sandbox.BASE.nodeNames.homeStatic,
  ]);
  assert.strictEqual(
    findGroup(output, sandbox.UI_GROUPS.strictExit).proxies[0],
    sandbox.BASE.nodeNames.homeStatic,
  );
}

function testHomeStaticPreferredOverTransit() {
  const { sandbox, output } = runMain(null, (sb) => {
    sb.RESIDENTIAL_CREDENTIALS.homeStatic = cloneJson(TEST_HOME_STATIC);
  });
  const home = findProxy(output, sandbox.BASE.nodeNames.homeStatic);
  const transit = findProxy(output, sandbox.BASE.nodeNames.transit);
  assert(home);
  assert(transit);
  assert.strictEqual(home.username, TEST_SHARED_AUTH.username);
  assert.strictEqual(transit.username, TEST_SHARED_AUTH.username);
  assert.strictEqual(home.password, TEST_SHARED_AUTH.password);
  assert.deepEqual(findGroup(output, sandbox.BASE.residentialGroupName).proxies, [
    sandbox.BASE.nodeNames.homeStatic,
    sandbox.BASE.nodeNames.transit,
  ]);
  assert.strictEqual(
    findGroup(output, sandbox.UI_GROUPS.strictExit).proxies[0],
    sandbox.BASE.nodeNames.homeStatic,
  );
}

function testNoRegionNodesStillWorks() {
  const { sandbox, output } = runMain((config) => {
    config.proxies = [];
    config["proxy-groups"] = [{ name: "PROXY", type: "select", proxies: [] }];
  });
  assert.deepEqual(findGroup(output, sandbox.BASE.residentialGroupName).proxies, [
    sandbox.BASE.nodeNames.transit,
  ]);
  assert.deepEqual(
    findGroup(output, sandbox.UI_GROUPS.strictExit).proxies,
    expectedAntiBanChoices(output, sandbox),
  );
}

function testStrictDomainRouting() {
  const { sandbox, output } = runMain();
  const ai = sandbox.UI_GROUPS.ai;
  const support = sandbox.UI_GROUPS.support;
  const integrations = sandbox.UI_GROUPS.integrations;
  assertRulesExist(output.rules, [
    suffixRule("claude.ai", ai),
    suffixRule("chatgpt.com", ai),
    suffixRule("gemini.google.com", ai),
    suffixRule("antigravity.google", ai),
    suffixRule("antigravity-ide.com", ai),
    suffixRule("cloudcode-pa.googleapis.com", ai),
    suffixRule("meta.ai", ai),
    suffixRule("grok.com", ai),
    suffixRule("accounts.google.com", support),
    suffixRule("consent.google.com", support),
    suffixRule("gstatic.com", support),
    suffixRule("npmjs.org", support),
    suffixRule("azureedge.net", support),
    suffixRule("arkoselabs.com", integrations),
    suffixRule("stripe.com", integrations),
    suffixRule("statsig.com", integrations),
  ]);
}

function testTrimmedStrictListsAbsent() {
  const { sandbox, output } = runMain();
  assertRulesMissing(output.rules, [
    suffixRule("google.com", sandbox.UI_GROUPS.support),
    suffixRule("microsoft.com", sandbox.UI_GROUPS.support),
    suffixRule("vercel.com", sandbox.UI_GROUPS.support),
    suffixRule("gitlab.com", sandbox.UI_GROUPS.support),
    suffixRule("akamai.net", sandbox.UI_GROUPS.support),
    suffixRule("fastly.net", sandbox.UI_GROUPS.support),
    suffixRule("midjourney.com", sandbox.UI_GROUPS.ai),
    suffixRule("cohere.com", sandbox.UI_GROUPS.ai),
    suffixRule("windsurf.com", sandbox.UI_GROUPS.ai),
    suffixRule("openrouter.ai", sandbox.UI_GROUPS.ai),
    suffixRule("mistral.ai", sandbox.UI_GROUPS.ai),
    suffixRule("huggingface.co", sandbox.UI_GROUPS.ai),
    suffixRule("cursor.sh", sandbox.UI_GROUPS.ai),
    suffixRule("cursor.com", sandbox.UI_GROUPS.ai),
    suffixRule("intercom.io", sandbox.UI_GROUPS.integrations),
    suffixRule("posthog.com", sandbox.UI_GROUPS.integrations),
    suffixRule("hcaptcha.com", sandbox.UI_GROUPS.integrations),
    suffixRule("clerk.dev", sandbox.UI_GROUPS.integrations),
    suffixRule("ping0.cc", sandbox.UI_GROUPS.support),
    suffixRule("openaiapi-site.azureedge.net", sandbox.UI_GROUPS.ai),
    processRule("SunBrowser", sandbox.UI_GROUPS.ai),
  ]);
}

function testMediaDomainRouting() {
  const { sandbox, output } = runMain();
  assertRulesExist(output.rules, [
    suffixRule("youtube.com", sandbox.UI_GROUPS.video),
    suffixRule("netflix.com", sandbox.UI_GROUPS.video),
    suffixRule("spotify.com", sandbox.UI_GROUPS.music),
    suffixRule("x.com", sandbox.UI_GROUPS.social),
    suffixRule("discord.com", sandbox.UI_GROUPS.im),
    suffixRule("whatsapp.com", sandbox.UI_GROUPS.im),
  ]);
  assertRulesMissing(output.rules, [
    suffixRule("youtube.com", sandbox.UI_GROUPS.ai),
    suffixRule("linkedin.com", sandbox.UI_GROUPS.social),
    suffixRule("slack.com", sandbox.UI_GROUPS.im),
    suffixRule("signal.org", sandbox.UI_GROUPS.im),
    suffixRule("soundcloud.com", sandbox.UI_GROUPS.music),
    suffixRule("hulu.com", sandbox.UI_GROUPS.video),
  ]);
}

function testCdnCloudScope() {
  const { sandbox, output } = runMain();
  assertRulesExist(output.rules, [
    suffixRule("amazonaws.com", sandbox.UI_GROUPS.support),
    suffixRule("cloudfront.net", sandbox.UI_GROUPS.support),
    suffixRule("cdn.cloudflare.net", sandbox.UI_GROUPS.support),
  ]);
  assertRulesMissing(output.rules, [
    suffixRule("amazon.com", sandbox.UI_GROUPS.support),
    suffixRule("pages.dev", sandbox.UI_GROUPS.support),
    suffixRule("workers.dev", sandbox.UI_GROUPS.support),
  ]);
}

function testProcessRouting() {
  const { sandbox, derived, output } = runMain();
  const ai = sandbox.UI_GROUPS.ai;
  assertRulesExist(output.rules, [
    processRule("Claude", ai),
    processRule("claude", ai),
    processRule("codex", ai),
    processRule("ChatGPT Helper (Renderer)", ai),
    processRule("Comet", ai),
    processRule("Dia", ai),
    processRule("Atlas", ai),
    // Gemini + Antigravity：App / IDE / CLI 同一策略
    processRule("Gemini", ai),
    processRule("Gemini Helper (Renderer)", ai),
    processRule("Antigravity", ai),
    processRule("Antigravity IDE", ai),
    processRule("language_server", ai),
    processRule("gemini", ai),
    processRule("agy", ai),
    processRule("antigravity", ai),
  ]);
  for (const name of derived.processNames.aiCli) {
    assertRulesExist(output.rules, [processRule(name, ai)]);
  }
  assertRulesMissing(output.rules, [
    processRule("Google Chrome", ai),
    processRule("Safari", ai),
    processRule("SunBrowser", ai),
    processRule("Cursor", ai),
    processRule("Cursor Helper (Renderer)", ai),
    processRule("opencode", ai),
    processRule("WeChat", "DIRECT"),
    processRule("Quotio", ai),
  ]);
  assertIncludes(derived.processNames.browser, ["Comet", "Dia", "Atlas"], "ai browsers");
  assertExcludes(derived.processNames.browser, ["SunBrowser"], "browser");
  assertExcludes(derived.processNames.aiApps, ["Cursor"], "aiApps");
  assertIncludes(derived.processNames.aiApps, ["Gemini", "Antigravity", "Antigravity IDE"], "gemini/agy apps");
  assertIncludes(derived.processNames.aiCli, ["gemini", "agy", "antigravity"], "gemini/agy cli");
}

function testRuleOrder() {
  const { sandbox, output } = runMain();
  const ai = sandbox.UI_GROUPS.ai;
  const quic = "AND,((NETWORK,udp),(DST-PORT,443)),REJECT";
  const claude = suffixRule("claude.ai", ai);
  const youtube = suffixRule("youtube.com", sandbox.UI_GROUPS.video);
  const cn = "GEOSITE,cn,DIRECT";
  const geoip = "GEOIP,CN,DIRECT";
  const proc = processRule("Claude", ai);
  const gfw = "GEOSITE,gfw,PROXY";
  const match = "MATCH,PROXY";

  assertBefore(output.rules, quic, claude);
  assertBefore(output.rules, claude, youtube);
  assertBefore(output.rules, youtube, cn);
  assertBefore(output.rules, cn, geoip);
  assertBefore(output.rules, geoip, proc);
  assertBefore(output.rules, proc, gfw);
  assertBefore(output.rules, gfw, match);
  assert.strictEqual(
    output.rules.filter((r) => r.indexOf("DOMAIN-KEYWORD,") === 0).length,
    0,
  );
}

function testDnsAndSnifferMerged() {
  const { dnsBase, output } = runMain();
  assert.strictEqual(output.dns.listen, "127.0.0.1:1053");
  assertNsPolicy(output, [dnsBase.domesticGeosite], dnsBase.domestic);
  assertNsPolicy(output, [dnsBase.overseasGeosite], dnsBase.overseas);
  assertNsPolicy(
    output,
    ["+.claude.ai", "+.chatgpt.com", "+.accounts.google.com", "+.meta.ai"],
    dnsBase.overseas,
  );
  assertNsPolicy(output, ["+.qq.com", "+.apple.com", "+.12306.cn"], dnsBase.domestic);
  assertNsPolicy(output, ["+.iana.org"], dnsBase.overseas);
  assert.strictEqual(output.dns["fallback-filter"].domain, undefined);
  assertIncludes(
    output.sniffer["force-domain"],
    ["+.claude.ai", "+.openai.com", "+.challenges.cloudflare.com"],
    "force",
  );
  assertExcludes(
    output.sniffer["force-domain"],
    ["+.google.com", "+.cloudflare.com", "geosite:openai"],
    "force",
  );
  assertIncludes(
    output.sniffer["skip-domain"],
    ["+.apple.com", "+.tailscale.com"],
    "skip",
  );
}

function testDnsOnlyMode() {
  const config = baseConfig();
  const proxies = cloneJson(config.proxies);
  const groups = cloneJson(config["proxy-groups"]);
  const rules = config.rules.slice();
  const { sandbox, dnsBase, output } = runMain(
    () => config,
    (sb) => {
      sb.USER_OPTIONS.overrideMode = "dns-sniffer-only";
      sb.RESIDENTIAL_CREDENTIALS = cloneJson(EMPTY_CREDENTIALS);
    },
  );
  assert.deepEqual(output.proxies, proxies);
  assert.deepEqual(output["proxy-groups"], groups);
  assert.deepEqual(output.rules, rules);
  assert.strictEqual(output.dns.enable, true);
  assertNsPolicy(output, ["+.claude.ai", "+.chatgpt.com"], dnsBase.overseas);
  assertIncludes(output.sniffer["force-domain"], ["+.claude.ai"], "force");
}

function testDirectCnAndOverseas() {
  const { dnsBase, output } = runMain();
  assertRulesExist(output.rules, [
    "DOMAIN-SUFFIX,qq.com,DIRECT",
    "DOMAIN-SUFFIX,aliyuncs.com,DIRECT",
    "DOMAIN-SUFFIX,tailscale.com,DIRECT",
    "DOMAIN-SUFFIX,immersivetranslate.com,DIRECT",
    "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
  ]);
  assertNsPolicy(output, ["+.qq.com", "+.tailscale.com"], dnsBase.domestic);
  assertNsPolicy(output, ["+.immersivetranslate.com"], dnsBase.overseas);
  assertIncludes(output.sniffer["skip-domain"], ["+.tailscale.com", "+.mineru.org.cn"], "skip");
}

function testQuicAndDnsListenOptions() {
  const off = runMain(null, (sb) => {
    sb.USER_OPTIONS.rejectQuic = false;
  });
  assertRulesMissing(off.output.rules, [
    "AND,((NETWORK,udp),(DST-PORT,443)),REJECT",
  ]);

  const listen = runMain(null, (sb) => {
    sb.USER_OPTIONS.dnsListen = "0.0.0.0:1053";
  });
  assert.strictEqual(listen.output.dns.listen, "0.0.0.0:1053");
}

function testDefaultProxyResolution() {
  const exact = runMain((config) => {
    config["proxy-groups"] = [
      { name: "办公PROXY", type: "select", proxies: ["🇸🇬 SG Auto 01"] },
      { name: "PROXY", type: "select", proxies: ["🇺🇸 US Auto 01"] },
    ];
    config.rules = ["MATCH,PROXY"];
  });
  assertRulesExist(exact.output.rules, ["MATCH,PROXY", "GEOSITE,gfw,PROXY"]);
  assertRulesMissing(exact.output.rules, ["MATCH,办公PROXY"]);

  const match = runMain((config) => {
    config["proxy-groups"] = [
      { name: "PROXY备用", type: "select", proxies: ["🇸🇬 SG Auto 01"] },
      { name: "手动选择", type: "select", proxies: ["🇺🇸 US Auto 01"] },
    ];
    config.rules = ["MATCH,手动选择"];
  });
  assertRulesExist(match.output.rules, ["MATCH,手动选择", "GEOSITE,gfw,手动选择"]);
  assertRulesMissing(match.output.rules, ["MATCH,PROXY备用"]);
}

function testGfwAndMatchTargets() {
  const { output } = runMain();
  assertRulesExist(output.rules, [
    "DOMAIN-SUFFIX,dns.google,PROXY",
    "GEOSITE,gfw,PROXY",
    "MATCH,PROXY",
  ]);
  assertBefore(output.rules, "GEOIP,CN,DIRECT", "GEOSITE,gfw,PROXY");
}

function testDisabledSwitch() {
  const { output } = runMain(null, (sb) => {
    sb.USER_OPTIONS.enabled = false;
  });
  const base = baseConfig();
  assert.deepEqual(output.proxies, base.proxies);
  assert.deepEqual(output["proxy-groups"], base["proxy-groups"]);
  assert.deepEqual(output.rules, base.rules);
  assert.strictEqual(output.dns, undefined);
}

function testSubscriptionCleanup() {
  const { sandbox, output } = runMain((config) => {
    config.rules = [
      "DOMAIN-KEYWORD,openai,办公娱乐好帮手",
      "DOMAIN-SUFFIX,some-random-domain.co,办公娱乐好帮手",
      "MATCH,办公娱乐好帮手",
    ];
    config["proxy-groups"].push(
      { name: "自动选择", type: "url-test", proxies: ["🇸🇬 SG Auto 01"] },
      { name: "Bahamut", type: "select", proxies: ["PROXY"] },
    );
    config["rule-providers"] = {
      "GFWList-Site": { type: "http", behavior: "domain", url: "https://example.com/gfw.mrs" },
    };
  });
  assertRulesMissing(output.rules, [
    "DOMAIN-KEYWORD,openai,办公娱乐好帮手",
    "MATCH,办公娱乐好帮手",
  ]);
  assertRulesExist(output.rules, [
    "MATCH,PROXY",
    suffixRule("openai.com", sandbox.UI_GROUPS.ai),
  ]);
  assert.strictEqual(findGroup(output, "自动选择"), undefined);
  assert.strictEqual(findGroup(output, "Bahamut"), undefined);
  assert(findGroup(output, "PROXY"));
  assert.deepEqual(output["rule-providers"], {});
}

function testReconcileAndRerun() {
  const first = runMain((config) => {
    const base = loadSandbox().BASE;
    config.proxies.push({
      name: base.nodeNames.transit,
      type: "socks5",
      server: "bad",
      port: 2,
      username: "bad",
      password: "bad",
      udp: false,
    });
    config["proxy-groups"].push(
      { name: base.residentialGroupName, type: "select", proxies: ["DIRECT"] },
      { name: "🇸🇬 错误地区组", type: "select", proxies: ["DIRECT"] },
    );
  });
  assert.strictEqual(
    findProxy(first.output, first.sandbox.BASE.nodeNames.transit).server,
    TEST_TRANSIT.server,
  );
  assert.deepEqual(
    findGroup(first.output, first.sandbox.UI_GROUPS.strictExit).proxies,
    expectedAntiBanChoices(first.output, first.sandbox),
  );

  const second = runMain(() => cloneJson(first.output));
  for (const name of [
    second.sandbox.BASE.residentialGroupName,
    regionGroup(second.sandbox, "US"),
    second.sandbox.UI_GROUPS.strictExit,
  ]) {
    assert.strictEqual(
      second.output["proxy-groups"].filter((g) => g.name === name).length,
      1,
      "duplicate after rerun: " + name,
    );
  }
}

function testRegionDetection() {
  const english = runMain((config) => {
    config.proxies = [
      { name: "United States 01", type: "ss" },
      { name: "Hong Kong 02", type: "ss" },
      { name: "Singapore premium", type: "ss" },
      { name: "Japan Tokyo", type: "ss" },
    ];
    config["proxy-groups"] = [
      { name: "PROXY", type: "select", proxies: ["United States 01"] },
    ];
    config.rules = ["MATCH,PROXY"];
  });
  for (const code of ["US", "HK", "SG", "JP"]) {
    assert(findGroup(english.output, regionGroup(english.sandbox, code)));
  }

  const compact = runMain((config) => {
    config.proxies = [
      { name: "US_Tokyo_01", type: "ss" },
      { name: "SG01", type: "ss" },
    ];
    config["proxy-groups"] = [
      { name: "PROXY", type: "select", proxies: ["US_Tokyo_01"] },
    ];
    config.rules = ["MATCH,PROXY"];
  });
  assert(findGroup(compact.output, regionGroup(compact.sandbox, "US")));
  assert(findGroup(compact.output, regionGroup(compact.sandbox, "SG")));
}

function testHkOnlyRegion() {
  const { sandbox, output } = runMain((config) => {
    config.proxies = [{ name: "🇭🇰 HK Auto 01", type: "ss" }];
    config["proxy-groups"] = [
      { name: "PROXY", type: "select", proxies: ["🇭🇰 HK Auto 01"] },
    ];
    config.rules = ["MATCH,PROXY"];
  });
  assert(findGroup(output, regionGroup(sandbox, "HK")));
  assert.strictEqual(findGroup(output, regionGroup(sandbox, "US")), undefined);
  assert.strictEqual(
    findGroup(output, sandbox.UI_GROUPS.otherExit).proxies[0],
    regionGroup(sandbox, "HK"),
  );
}

function testDnsOnlyNamesPolicy() {
  // 与 dns-only 模式互补：确认 DNS_ONLY 域不进规则链
  const { output } = runMain();
  const identities = output.rules.map(ruleIdentity);
  assert(!identities.includes("DOMAIN-SUFFIX,cnnic.cn"));
  assert(!identities.includes("DOMAIN-SUFFIX,iana.org"));
}

function testExpectedRoutesCoverage() {
  // 加载期 assertExpectedRoutesCoverage 已校验样本覆盖；此处核对关键样本落点。
  const { sandbox, output } = runMain();
  assertRulesExist(output.rules, [
    suffixRule("claude.ai", sandbox.UI_GROUPS.ai),
    suffixRule("azureedge.net", sandbox.UI_GROUPS.support),
    suffixRule("youtube.com", sandbox.UI_GROUPS.video),
    suffixRule("discord.com", sandbox.UI_GROUPS.im),
  ]);
}

const integrationTests = [
  ["mergedHappyPath", testMergedHappyPath],
  ["antiBanAndUnlockExits", testAntiBanAndUnlockExits],
  ["categoryExitCoupling", testCategoryExitCoupling],
  ["brokenStrictCouplingFails", testBrokenStrictCouplingFails],
  ["emptyCredentialsDegrade", testEmptyCredentialsDegrade],
  ["placeholderCredentialsDegrade", testPlaceholderCredentialsDegrade],
  ["homeStaticOnly", testHomeStaticOnly],
  ["homeStaticPreferredOverTransit", testHomeStaticPreferredOverTransit],
  ["noRegionNodesStillWorks", testNoRegionNodesStillWorks],
  ["strictDomainRouting", testStrictDomainRouting],
  ["trimmedStrictListsAbsent", testTrimmedStrictListsAbsent],
  ["mediaDomainRouting", testMediaDomainRouting],
  ["cdnCloudScope", testCdnCloudScope],
  ["processRouting", testProcessRouting],
  ["ruleOrder", testRuleOrder],
  ["dnsAndSnifferMerged", testDnsAndSnifferMerged],
  ["dnsOnlyMode", testDnsOnlyMode],
  ["directCnAndOverseas", testDirectCnAndOverseas],
  ["quicAndDnsListenOptions", testQuicAndDnsListenOptions],
  ["defaultProxyResolution", testDefaultProxyResolution],
  ["gfwAndMatchTargets", testGfwAndMatchTargets],
  ["disabledSwitch", testDisabledSwitch],
  ["subscriptionCleanup", testSubscriptionCleanup],
  ["reconcileAndRerun", testReconcileAndRerun],
  ["regionDetection", testRegionDetection],
  ["hkOnlyRegion", testHkOnlyRegion],
  ["dnsOnlyNamesPolicy", testDnsOnlyNamesPolicy],
  ["expectedRoutesCoverage", testExpectedRoutesCoverage],
  // 补齐至 30：浏览器进 AI、启用默认行为
  ["browserPinnedToAi", function testBrowserPinnedToAi() {
    const { sandbox, derived, output } = runMain();
    for (const name of derived.processNames.browser) {
      assertRulesExist(output.rules, [processRule(name, sandbox.UI_GROUPS.ai)]);
    }
  }],
  ["enabledDefaultApplies", function testEnabledDefaultApplies() {
    const { output } = runMain();
    assert.strictEqual(output.dns.enable, true);
    assert.strictEqual(output.sniffer.enable, true);
    assert(output.rules.some((r) => r.indexOf("DOMAIN-SUFFIX,openai.com") === 0));
  }],
];

// ===========================================================================
// Runner
// ===========================================================================

function runSuite(label, tests) {
  console.log(label + " (" + tests.length + "):");
  let failed = 0;
  for (const [name, fn] of tests) {
    try {
      fn();
      console.log("  PASS " + name);
    } catch (err) {
      failed += 1;
      console.log("  FAIL " + name);
      console.log("    " + (err && err.stack ? err.stack : err));
    }
  }
  return failed;
}

assert.strictEqual(unitTests.length, 16, "expected 16 unit tests");
assert.strictEqual(integrationTests.length, 30, "expected 30 integration tests");

let failures = 0;
failures += runSuite("Unit tests", unitTests);
console.log("");
failures += runSuite("Integration tests", integrationTests);

if (failures > 0) {
  console.log("\n" + failures + " check(s) failed");
  process.exit(1);
}

console.log(
  "\nAll " + (unitTests.length + integrationTests.length) + " checks passed",
);
