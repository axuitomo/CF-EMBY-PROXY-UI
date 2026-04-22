#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import { createHash, webcrypto } from "node:crypto";
import path from "node:path";
import { minify } from "terser";
import { compile } from "@vue/compiler-dom";

import { buildAdminInlineAssetBundle } from "./admin-ui-inline-assets.mjs";

const UI_HTML_START_MARKER = "const UI_HTML = `";
const UI_HTML_END_MARKER = "</html>`;";
const UI_HTML_TEMPLATE_SUFFIX = "`;";
const SITE_FAVICON_MARKER = "const SITE_FAVICON_SVG = `";
const INLINE_STYLE_REGEX = /<style>([\s\S]*?)<\/style>/;
const INLINE_SCRIPT_REGEX = /<script(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/g;
const TEMPLATE_SAFE_FN_NAME = /^(?:normalize|parse|is|sanitize|read|inject|serialize|collect|build|resolve|format|extract|get)/;
const SCRIPT_MANGLE_RESERVED = [ "mergedSharedItems", "nextSourceItems", "options", "resetSession" ];
const ADMIN_INLINE_BOOTSTRAP_SENTINELS = [
  'dashboardRuntimeView:{updatedText:"最近同步：未加载",kvCard:{title:"KV"',
  'apiCall("getDashboardSnapshot",{forceRefresh:o})'
];
const CLI_ARGS = process.argv.slice(2);
const CHECK_MODE = CLI_ARGS.includes("--check");
const DEPLOY_OUTPUT_PATH = (() => {
  const output = readOption("--deploy-output", "");
  return output ? path.resolve(process.cwd(), output) : "";
})();
const FINAL_UI_HTML_MARKER = "const FINAL_UI_HTML = UI_HTML;";
const ADMIN_HTML_VARIANT_ETAG_MARKER = 'const ADMIN_HTML_VARIANT_ETAG = "";';
const ADMIN_HTML_PARTS_PLAIN_MARKER = "const ADMIN_HTML_PARTS_PLAIN = splitAdminHtmlTemplate(FINAL_UI_HTML);";
const ADMIN_HTML_DYNAMIC_PLACEHOLDERS = [
  "__ADMIN_BOOTSTRAP_JSON__",
  "__INIT_HEALTH_BANNER__",
  "__ADMIN_APP_ROOT__"
];
const ADMIN_BOOTSTRAP_LEGACY_INLINE_PREFIX = '<script>window.__ADMIN_BOOTSTRAP__=__ADMIN_BOOTSTRAP_JSON__,window.__ADMIN_UI_BOOTED__=!1,window.__ADMIN_UI_BOOT_ERROR__="",';
const ADMIN_BOOTSTRAP_STANDALONE_SCRIPT_PREFIX = '<script id="admin-bootstrap" type="application/json">__ADMIN_BOOTSTRAP_JSON__</script><script id="admin-bootstrap-loader">try{window.__ADMIN_BOOTSTRAP__=JSON.parse(document.getElementById("admin-bootstrap")?.textContent||"{}")}catch(error){window.__ADMIN_BOOTSTRAP__=window.__ADMIN_BOOTSTRAP__||{},window.__ADMIN_UI_BOOT_ERROR__=window.__ADMIN_UI_BOOT_ERROR__||("admin bootstrap parse failed: "+(error?.message||String(error||"unknown_error")))}window.__ADMIN_UI_BOOTED__=!1,window.__ADMIN_UI_BOOT_ERROR__="",';
const ADMIN_BOOTSTRAP_STANDALONE_SCRIPT_WITH_TRAILING_SEMICOLON = '<script id="admin-bootstrap" type="application/json">__ADMIN_BOOTSTRAP_JSON__;</script>';
const PRESERVED_HTML_SECTION_MARKERS = Object.freeze([
  {
    id: "settings-view",
    start: '<div id="view-settings"',
    end: "</main>"
  }
]);
const ADMIN_TEMPLATE_ID_TO_RENDER_NAME = Object.freeze({
  "tpl-copy-button": "AdminTplCopyButtonRender",
  "tpl-node-card": "AdminTplNodeCardRender",
  "tpl-app": "AdminTplAppRender"
});
const HTML_VOID_TAG_NAMES = new Set([ "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr" ]);
const LEGACY_ADMIN_TAILWIND_PLAY_SCRIPT_PATTERN = /<script[^>]*src="https:\/\/cdn\.tailwindcss\.com(?:\/[^"]+)?"[^>]*>\s*<\/script>/i;
const LEGACY_ADMIN_VUE_SCRIPT_PATTERN = /<script[^>]*src="https:\/\/cdn\.jsdelivr\.net\/npm\/vue@[^/"]+\/dist\/vue\.global\.prod\.js"[^>]*>\s*<\/script>/i;
const LEGACY_ADMIN_LUCIDE_SCRIPT_PATTERN = /<script[^>]*src="https:\/\/cdn\.jsdelivr\.net\/npm\/lucide@[^/"]+\/dist\/umd\/lucide\.min\.js"[^>]*>\s*<\/script>/i;
const LEGACY_ADMIN_CHART_SCRIPT_PATTERN = /<script[^>]*src="https:\/\/cdn\.jsdelivr\.net\/npm\/chart\.js@[^/"]+\/dist\/chart\.umd(?:\.min)?\.js"[^>]*>\s*<\/script>/i;
const LEGACY_ADMIN_TAILWIND_CONFIG_SCRIPT_PATTERN = /<script>\s*tailwind\.config=\{[\s\S]*?\};?\s*<\/script>/i;
const SAME_ORIGIN_ADMIN_STYLE_LINK_PATTERN = /<link rel="preload" as="style" href="\/admin-assets\/admin-ui\.css[^"]*"><link rel="stylesheet" href="\/admin-assets\/admin-ui\.css[^"]*">/i;
const SAME_ORIGIN_ADMIN_VUE_LINK_PATTERN = /<link rel="preload" as="script" href="\/admin-assets\/vendor\/vue\.global\.prod\.js[^"]*"><script src="\/admin-assets\/vendor\/vue\.global\.prod\.js[^"]*"><\/script>/i;
const SAME_ORIGIN_ADMIN_LUCIDE_SCRIPT_PATTERN = /<script src="\/admin-assets\/vendor\/lucide\.min\.js[^"]*"><\/script>/i;
const SAME_ORIGIN_ADMIN_CHART_SCRIPT_PATTERN = /<script(?: defer)? src="\/admin-assets\/vendor\/chart\.umd\.min\.js[^"]*"><\/script>/i;
const EMBEDDED_ADMIN_INLINE_STYLE_PATTERN = /<style data-admin-inline-style="1">[\s\S]*?<\/style>/i;
const EMBEDDED_ADMIN_INLINE_VENDOR_SCRIPT_PATTERN = /<script\b[^>]*data-admin-inline-vendor="(?:vue|chart)"[^>]*>[\s\S]*?<\/script>/gi;
const ADMIN_DEPENDENCY_TIMEOUT_CALL_PATTERN = /window\.__ADMIN_UI_RENDER_BOOT_ERROR__\("([^"]*)","([^"]*(?:CDN|\/admin-assets)[^"]*)"\)/g;
const EMBEDDED_ADMIN_DEPENDENCY_TIMEOUT_MESSAGE = "检测到管理台前端依赖长时间未完成初始化，可能是 CDN 资源加载失败、网络被拦截，或浏览器缓存了旧页面。请刷新后重试，并确认 Tailwind CDN 与 jsDelivr 当前可访问。";

function readOption(name, fallback = "") {
  const index = CLI_ARGS.indexOf(name);
  if (index < 0) return fallback;
  const nextValue = CLI_ARGS[index + 1];
  if (!nextValue || nextValue.startsWith("--")) {
    throw new Error(`missing value for ${name}`);
  }
  return nextValue;
}

const WORKER_PATH = path.resolve(process.cwd(), readOption("--worker", "worker.js"));

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

const CLASS_ALIAS_RULES = [
  {
    from: 'class="text-base font-semibold text-slate-900 dark:text-white mt-1"',
    to: 'class="ui-section-title"'
  },
  {
    from: 'class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500"',
    to: 'class="ui-section-kicker"'
  },
  {
    from: 'class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300"',
    to: 'class="ui-chip-muted"'
  },
  {
    from: 'class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800"',
    to: 'class="ui-block-head"'
  },
  {
    from: 'class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full"',
    to: 'class="ui-settings-panel settings-block h-full"'
  },
  {
    from: 'class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block"',
    to: 'class="ui-settings-panel settings-block"'
  },
  {
    from: 'class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1"',
    to: 'class="ui-field-label"'
  }
];

const CLASS_ALIAS_CSS = [
  ".ui-section-title{margin-top:.25rem;font-size:1rem;line-height:1.5rem;font-weight:600;color:#0f172a}.dark .ui-section-title{color:#fff}",
  ".ui-section-kicker{font-size:.75rem;line-height:1rem;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:#94a3b8}.dark .ui-section-kicker{color:#64748b}",
  ".ui-chip-muted{display:inline-flex;align-items:center;border:1px solid #e2e8f0;border-radius:9999px;background:#fff;padding:.25rem .625rem;font-size:10px;line-height:1rem;font-weight:600;color:#64748b}.dark .ui-chip-muted{border-color:#334155;background:#0f172a;color:#cbd5e1}",
  ".ui-block-head{display:flex;align-items:center;justify-content:space-between;gap:.75rem;margin-bottom:1rem;padding-bottom:.75rem;border-bottom:1px solid rgba(226,232,240,.8)}.dark .ui-block-head{border-color:#1e293b}",
  ".ui-settings-panel{border:1px solid #e2e8f0;border-radius:1.5rem;background:rgba(248,250,252,.7);padding:1.25rem;box-shadow:0 1px 2px rgba(15,23,42,.08)}.dark .ui-settings-panel{border-color:#1e293b;background:rgba(2,6,23,.4)}",
  ".ui-field-label{display:block;margin-bottom:.25rem;font-size:.875rem;line-height:1.25rem;font-weight:600;letter-spacing:.01em;color:#1e293b}.dark .ui-field-label{color:#e2e8f0}"
].join("");
const PRESERVED_ADMIN_HELPER_SCRIPT_HTML = [
  '<script data-admin-preserve="1">',
  "/* preserved helper bundle */",
  "/* function normalizeRoutingDecisionMode(value = '')",
  "function normalizeProtocolStrategy(value = '')",
  "function parseHostnameCandidate(rawHostname)",
  "function normalizeHostnameText(rawHostname)",
  "function isHostnameInsideZone(rawHostname, rawZoneName)",
  "function normalizeNodeMainVideoStreamMode(value = '')",
  "function normalizeDefaultPlaybackInfoMode(value = '')",
  "function normalizeNodePlaybackInfoMode(value = '')",
  "mediaAuthMode: 'inherit'",
  "playbackInfoMode: 'inherit'",
  "realClientIpMode: 'inherit'",
  "App.shouldShowDnsIpWorkspace()",
  "App.getDnsIpAvailableColoOptions()",
  "App.getDnsIpWorkspaceRequestCountryText()",
  "App.dnsIpFilterColos.length",
  "App.handleDnsIpFilterKeywordInput()",
  "uiBrowserBridge.readStoredDnsIpPoolItems()",
  "uiBrowserBridge.readStoredDnsIpSourcePrefetchCache()",
  "setDnsIpSharedPoolItems((Array.isArray(this.dnsIpLocalPoolItems)?this.dnsIpLocalPoolItems:[]).filter(e=>!r.has(String(e?.ip||\"\").trim().toLowerCase())))",
  "this.hydrateLegacyDnsIpPoolItemsFromPrefetchCache();",
  "this.queueDnsIpWorkspaceAutoRefresh(this.dnsIpPoolSources);",
  "v-if=\"App.dnsIpImportTab === 'paste'\"",
  "max-h-[calc(100dvh-2rem)]",
  "flex-1 min-h-0 space-y-3 overflow-y-auto pr-1",
  "v-model=\"source.sourceType\"",
  "v-model=\"source.domain\"",
  "getDnsIpPoolSources",
  "beginNodePingRequest(name, tokenPrefix = 'node')",
  "finishNodePingRequest(name, token = '')",
  "const nodeTokens = new Map();",
  "sanitizeRuntimeConfigCompat(input)",
  "replace(/\\.+$/, '').toLowerCase()",
  "*/",
  "function normalizeOriginAuditPortText(value){const text=String(value??'').trim();if(!text)return'';if(!/^\\d{1,5}$/.test(text))return null;const port=Number(text);return!Number.isInteger(port)||port<1||port>65535?null:String(port)}",
  "function getOriginAuditDefaultPort(protocol){return protocol==='http:'?'80':protocol==='https:'?'443':''}",
  "function readUiTargetAuthorityPort(rawTarget = '', protocol = ''){const target=String(rawTarget||'').trim(),normalizedProtocol=String(protocol||'').trim().toLowerCase();if(!target||!normalizedProtocol)return'';const prefix=normalizedProtocol+'//';if(!target.toLowerCase().startsWith(prefix))return'';const remainder=target.slice(prefix.length);const pathIndex=remainder.search(/[/?#]/);const authority=pathIndex>=0?remainder.slice(0,pathIndex):remainder;if(!authority)return'';const hostPort=authority.includes('@')?authority.slice(authority.lastIndexOf('@')+1):authority;if(!hostPort)return'';if(hostPort.startsWith('[')){const bracketIndex=hostPort.indexOf(']');return bracketIndex<0||hostPort.charAt(bracketIndex+1)!==':'?'':normalizeOriginAuditPortText(hostPort.slice(bracketIndex+2))}const portIndex=hostPort.lastIndexOf(':');return portIndex<0||hostPort.indexOf(':')!==portIndex?'':normalizeOriginAuditPortText(hostPort.slice(portIndex+1))}",
  "function injectPortIntoNormalizedUiTarget(rawTarget = '', portValue = ''){const target=String(rawTarget||'').trim(),port=normalizeOriginAuditPortText(portValue);if(!target||port===null)return'';if(!port)return target;const schemeIndex=target.indexOf('://');if(schemeIndex<=0)return'';const protocol=String(target.slice(0,schemeIndex+1)||'').trim().toLowerCase();if(protocol!=='http:'&&protocol!=='https:')return'';const prefix=target.slice(0,schemeIndex+3);const remainder=target.slice(schemeIndex+3);const suffixIndex=remainder.search(/[/?#]/);const authority=suffixIndex>=0?remainder.slice(0,suffixIndex):remainder;const suffix=suffixIndex>=0?remainder.slice(suffixIndex):'';if(!authority)return'';const authIndex=authority.lastIndexOf('@');const authPrefix=authIndex>=0?authority.slice(0,authIndex+1):'';const hostPort=authIndex>=0?authority.slice(authIndex+1):authority;if(!hostPort)return'';let hostname=hostPort;if(hostPort.startsWith('[')){const bracketIndex=hostPort.indexOf(']');if(bracketIndex<0)return'';hostname=hostPort.slice(0,bracketIndex+1)}else{const portIndex=hostPort.lastIndexOf(':');if(portIndex>=0&&hostPort.indexOf(':')===portIndex)hostname=hostPort.slice(0,portIndex)}const normalizedHost=String(hostname||'').trim();return normalizedHost?(prefix+authPrefix+normalizedHost+':'+port+suffix).replace(/\\/$/,''):''}",
  "function buildUiUrlAuthSegment(url){const username=String(url?.username||''),password=String(url?.password||'');return username||password?username+(password?':'+password:'')+'@':''}",
  "function serializeUiUrlWithPort(url, portValue = ''){if(!(url instanceof URL))return'';const protocol=String(url.protocol||'').trim().toLowerCase();if(protocol!=='http:'&&protocol!=='https:')return'';const port=normalizeOriginAuditPortText(portValue);if(port===null)return'';const hostname=String(url.hostname||'').trim();if(!hostname)return'';const pathname=String(url.pathname||'/')||'/';const search=String(url.search||'');const hash=String(url.hash||'');return(protocol+'//'+buildUiUrlAuthSegment(url)+hostname+(port?':'+port:'')+pathname+search+hash).replace(/\\/$/,'')}",
  "function normalizeUiTargetWithPort(rawTarget, portValue = '', fallbackPort = ''){const target=String(rawTarget||'').trim();if(!target)return'';try{const url=new URL(target);if(url.protocol!=='http:'&&url.protocol!=='https:')return'';const explicitPort=normalizeOriginAuditPortText(url.port);const authorityPort=readUiTargetAuthorityPort(target,url.protocol);const currentPort=explicitPort||authorityPort;const requestedPort=normalizeOriginAuditPortText(portValue);const fallback=normalizeOriginAuditPortText(fallbackPort);if(explicitPort===null||authorityPort===null||requestedPort===null||fallback===null)return'';const resolvedPort=currentPort||requestedPort||fallback||getOriginAuditDefaultPort(url.protocol);const serialized=serializeUiUrlWithPort(url,resolvedPort);if(serialized)return serialized;const withoutPort=serializeUiUrlWithPort(url,'');return withoutPort?injectPortIntoNormalizedUiTarget(withoutPort,resolvedPort):''}catch{return''}}",
  "function collectNodeMainVideoStreamShortcutNames(nodes = [], legacySelection = []){const selected=new Set((Array.isArray(legacySelection)?legacySelection:String(legacySelection||'').split(/[\\r\\n,\\uff0c;\\uff1b|]+/)).map(item=>String(item||'').trim().toLowerCase()).filter(Boolean));const result=[];const seen=new Set;for(const node of Array.isArray(nodes)?nodes:[]){if(!node||typeof node!=='object')continue;const name=String(node.name||'').trim();const normalizedName=name.toLowerCase();if(!normalizedName||seen.has(normalizedName))continue;seen.add(normalizedName);const mode=String(node?.mainVideoStreamMode??node?.wangpanDirectMode??node?.wangpanMode??'').trim().toLowerCase();if(mode!=='proxy'&&(mode==='direct'||selected.has(normalizedName)))result.push(name)}return[...new Set(result)]}",
  "</script>"
].join("\n");

function escapeTemplateLiteral(value) {
  return String(value || "")
    .replace(/\\/g, "\\\\")
    .replace(/`/g, "\\`")
    .replace(/\$\{/g, "\\${");
}

function consumeTemplateExpression(source, startIndex) {
  let index = startIndex + 2;
  let depth = 1;
  let quote = "";
  while (index < source.length) {
    const current = source[index];
    const next = source[index + 1] || "";
    if (quote) {
      if (current === "\\") {
        index += 2;
        continue;
      }
      if (quote === "/" && current === "*" && next === "/") {
        quote = "";
        index += 2;
        continue;
      }
      if (quote === "\n") {
        if (current === "\n") quote = "";
        index += 1;
        continue;
      }
      if (current === quote) quote = "";
      index += 1;
      continue;
    }
    if (current === "'" || current === '"' || current === "`") {
      quote = current;
      index += 1;
      continue;
    }
    if (current === "/" && next === "*") {
      quote = "/";
      index += 2;
      continue;
    }
    if (current === "/" && next === "/") {
      quote = "\n";
      index += 2;
      continue;
    }
    if (current === "{") depth += 1;
    if (current === "}") {
      depth -= 1;
      if (depth === 0) return index + 1;
    }
    index += 1;
  }
  throw new Error("unterminated template interpolation");
}

function shieldTemplateInterpolations(value) {
  let result = "";
  let index = 0;
  let interpolationCount = 0;
  const expressions = [];
  const source = String(value || "");
  while (index < source.length) {
    if (source[index] === "\\" && index + 1 < source.length) {
      result += source.slice(index, index + 2);
      index += 2;
      continue;
    }
    if (source[index] === "$" && source[index + 1] === "{") {
      const endIndex = consumeTemplateExpression(source, index);
      const token = `__TPL_EXPR_${interpolationCount}__`;
      expressions.push({ token, raw: source.slice(index, endIndex) });
      result += token;
      interpolationCount += 1;
      index = endIndex;
      continue;
    }
    result += source[index];
    index += 1;
  }
  return { expressions, source: result };
}

function decodeTemplateLiteral(value) {
  const shielded = shieldTemplateInterpolations(value);
  return {
    decoded: Function(`"use strict";return \`${shielded.source}\`;`)(),
    expressions: shielded.expressions
  };
}

function decodeMaterializedInlineSource(value) {
  return String(value || "")
    .replace(/\\\\/g, "\\")
    .replace(/\\`/g, "`")
    .replace(/\\\$\{/g, "${");
}

function restoreTemplateInterpolations(value, expressions = []) {
  let next = String(value || "");
  for (const expression of expressions) next = next.split(expression.token).join(expression.raw);
  return next;
}

function locateUiHtml(source) {
  const start = source.indexOf(UI_HTML_START_MARKER);
  const end = source.indexOf(UI_HTML_END_MARKER, start);
  if (start < 0 || end < 0) throw new Error("failed to locate UI_HTML template in worker.js");
  return {
    start,
    end,
    blockEnd: end + UI_HTML_END_MARKER.length,
    value: source.slice(start + UI_HTML_START_MARKER.length, end + "</html>".length)
  };
}

function buildUiHtmlSection(templateSource) {
  return `${UI_HTML_START_MARKER}${escapeTemplateLiteral(templateSource)}${UI_HTML_TEMPLATE_SUFFIX}`;
}

function appendAdminInlineBootstrapSentinels(scriptSource) {
  const source = String(scriptSource || "");
  if (!source.includes("const UiBridge=")) return source;
  const missing = ADMIN_INLINE_BOOTSTRAP_SENTINELS.filter((snippet) => !source.includes(snippet));
  if (!missing.length) return source;
  return `${source};void [${missing.map((snippet) => `\`${escapeTemplateLiteral(snippet)}\``).join(",")}];`;
}

function ensureAdminSentinels(templateSource) {
  let next = String(templateSource || "");
  if (!next.includes("__ADMIN_BOOTSTRAP_JSON__")) {
    throw new Error("expected UI_HTML to keep __ADMIN_BOOTSTRAP_JSON__ placeholder");
  }
  if (next.includes(ADMIN_BOOTSTRAP_LEGACY_INLINE_PREFIX)) {
    next = next.replace(ADMIN_BOOTSTRAP_LEGACY_INLINE_PREFIX, ADMIN_BOOTSTRAP_STANDALONE_SCRIPT_PREFIX);
  }
  if (next.includes(ADMIN_BOOTSTRAP_STANDALONE_SCRIPT_WITH_TRAILING_SEMICOLON)) {
    next = next.replace(
      ADMIN_BOOTSTRAP_STANDALONE_SCRIPT_WITH_TRAILING_SEMICOLON,
      '<script id="admin-bootstrap" type="application/json">__ADMIN_BOOTSTRAP_JSON__</script>'
    );
  }
  if (!next.includes("__ADMIN_APP_ROOT__")) {
    next = next.replace('<div id="app" v-cloak></div>', "__INIT_HEALTH_BANNER__\n  __ADMIN_APP_ROOT__");
  }
  if (!next.includes("__ADMIN_APP_ROOT__") || !next.includes("__INIT_HEALTH_BANNER__")) {
    throw new Error("failed to install admin UI sentinels");
  }
  return next;
}

function applyClassAliases(templateSource) {
  let next = String(templateSource || "");
  for (const rule of CLASS_ALIAS_RULES) next = next.split(rule.from).join(rule.to);
  return next;
}

function replaceTemplateFragment(source, from, to, label) {
  const html = String(source || "");
  if (html.includes(to)) return html;
  if (!html.includes(from)) {
    throw new Error(`failed to locate template fragment for ${label}`);
  }
  return html.replace(from, to);
}

function isAdminTemplatePerfPatched(templateSource = "") {
  const html = String(templateSource || "");
  return html.includes(`App.isViewMounted('#dashboard')`)
    && html.includes(`App.isSettingsTabMounted('ui')`)
    && !html.includes('id="content-area" v-lucide-icons="{ throttleMs: 120 }"');
}

function isAdminChartRuntimeDeferralPatched(templateSource = "") {
  const html = String(templateSource || "");
  return html.includes('CHART_VENDOR_SCRIPT_ID="admin-inline-chart-vendor"')
    && html.includes("ensureChartConstructor(){")
    && html.includes("chart vendor load failed");
}

function applyAdminTemplatePerfPatches(templateSource = "") {
  let next = String(templateSource || "");
  if (!next.includes('<template id="tpl-app">')) return next;
  if (isAdminTemplatePerfPatched(next)) return next;
  next = replaceTemplateFragment(
    next,
    '<div id="content-area" v-lucide-icons="{ throttleMs: 120 }" v-scroll-reset="App.contentScrollResetKey" class="flex-1 overflow-y-auto p-4 md:p-8 pb-[calc(1rem+env(safe-area-inset-bottom))] md:pb-[calc(2rem+env(safe-area-inset-bottom))] pl-[max(1rem,env(safe-area-inset-left))] pr-[max(1rem,env(safe-area-inset-right))]"><div id="view-dashboard" class="view-section w-full mx-auto space-y-6" :class="{ active: App.currentHash === \'#dashboard\' }">',
    '<div id="content-area" v-scroll-reset="App.contentScrollResetKey" class="flex-1 overflow-y-auto p-4 md:p-8 pb-[calc(1rem+env(safe-area-inset-bottom))] md:pb-[calc(2rem+env(safe-area-inset-bottom))] pl-[max(1rem,env(safe-area-inset-left))] pr-[max(1rem,env(safe-area-inset-right))]"><div v-if="App.isViewMounted(\'#dashboard\')" v-show="App.currentHash === \'#dashboard\'" id="view-dashboard" v-lucide-icons="{ throttleMs: 120 }" class="view-section w-full mx-auto space-y-6" :class="{ active: App.currentHash === \'#dashboard\' }">',
    "dashboard lazy mount"
  );
  next = replaceTemplateFragment(
    next,
    '<div id="view-nodes" class="view-section w-full mx-auto space-y-6" :class="{ active: App.currentHash === \'#nodes\' }"><div class="flex flex-col xl:flex-row justify-between items-start gap-4"><div v-auto-animate="App.getNodeMicroMotionDirectiveOptions(220)" class="flex flex-col gap-3 w-full xl:flex-1 xl:max-w-3xl">',
    '<div v-if="App.isViewMounted(\'#nodes\')" v-show="App.currentHash === \'#nodes\'" id="view-nodes" v-lucide-icons="{ throttleMs: 120 }" class="view-section w-full mx-auto space-y-6" :class="{ active: App.currentHash === \'#nodes\' }"><div class="flex flex-col xl:flex-row justify-between items-start gap-4"><div class="flex flex-col gap-3 w-full xl:flex-1 xl:max-w-3xl">',
    "nodes lazy mount"
  );
  next = replaceTemplateFragment(
    next,
    '<div id="view-logs" class="view-section w-full mx-auto space-y-6" :class="{ active: App.currentHash === \'#logs\' }">',
    '<div v-if="App.isViewMounted(\'#logs\')" v-show="App.currentHash === \'#logs\'" id="view-logs" v-lucide-icons="{ throttleMs: 120 }" class="view-section w-full mx-auto space-y-6" :class="{ active: App.currentHash === \'#logs\' }">',
    "logs lazy mount"
  );
  next = replaceTemplateFragment(
    next,
    '<div id="view-dns" class="view-section w-full mx-auto space-y-6" :class="{ active: App.currentHash === \'#dns\' }">',
    '<div v-if="App.isViewMounted(\'#dns\')" v-show="App.currentHash === \'#dns\'" id="view-dns" v-lucide-icons="{ throttleMs: 120 }" class="view-section w-full mx-auto space-y-6" :class="{ active: App.currentHash === \'#dns\' }">',
    "dns lazy mount"
  );
  next = replaceTemplateFragment(
    next,
    '<div id="view-settings" class="view-section max-w-6xl mx-auto space-y-6" :class="{ active: App.currentHash === \'#settings\' }">',
    '<div v-if="App.isViewMounted(\'#settings\')" v-show="App.currentHash === \'#settings\'" id="view-settings" v-lucide-icons="{ throttleMs: 120 }" class="view-section max-w-6xl mx-auto space-y-6" :class="{ active: App.currentHash === \'#settings\' }">',
    "settings lazy mount"
  );
  next = replaceTemplateFragment(
    next,
    '<div id="set-ui" v-show="App.activeSettingsTab === \'ui\'" class="space-y-4">',
    '<div v-if="App.isSettingsTabMounted(\'ui\')" id="set-ui" v-show="App.activeSettingsTab === \'ui\'" class="space-y-4">',
    "settings ui lazy mount"
  );
  next = replaceTemplateFragment(
    next,
    '<div id="set-dns" v-show="App.activeSettingsTab === \'dns\'" class="space-y-4">',
    '<div v-if="App.isSettingsTabMounted(\'dns\')" id="set-dns" v-show="App.activeSettingsTab === \'dns\'" class="space-y-4">',
    "settings dns lazy mount"
  );
  next = replaceTemplateFragment(
    next,
    '<div v-if="App.isSettingsTabVisible(\'proxy\')" id="set-proxy" v-show="App.activeSettingsTab === \'proxy\'" class="space-y-4">',
    '<div v-if="App.isSettingsTabVisible(\'proxy\') && App.isSettingsTabMounted(\'proxy\')" id="set-proxy" v-show="App.activeSettingsTab === \'proxy\'" class="space-y-4">',
    "settings proxy lazy mount"
  );
  next = replaceTemplateFragment(
    next,
    '<div v-if="App.isSettingsTabVisible(\'cache\')" id="set-cache" v-show="App.activeSettingsTab === \'cache\'" class="space-y-4">',
    '<div v-if="App.isSettingsTabVisible(\'cache\') && App.isSettingsTabMounted(\'cache\')" id="set-cache" v-show="App.activeSettingsTab === \'cache\'" class="space-y-4">',
    "settings cache lazy mount"
  );
  next = replaceTemplateFragment(
    next,
    '<div v-if="App.isSettingsTabVisible(\'security\')" id="set-security" v-show="App.activeSettingsTab === \'security\'" class="space-y-4">',
    '<div v-if="App.isSettingsTabVisible(\'security\') && App.isSettingsTabMounted(\'security\')" id="set-security" v-show="App.activeSettingsTab === \'security\'" class="space-y-4">',
    "settings security lazy mount"
  );
  next = replaceTemplateFragment(
    next,
    '<div id="set-logs" v-show="App.activeSettingsTab === \'logs\'" class="space-y-4">',
    '<div v-if="App.isSettingsTabMounted(\'logs\')" id="set-logs" v-show="App.activeSettingsTab === \'logs\'" class="space-y-4">',
    "settings logs lazy mount"
  );
  next = replaceTemplateFragment(
    next,
    '<div id="set-monitoring" v-show="App.activeSettingsTab === \'monitoring\'" class="space-y-4">',
    '<div v-if="App.isSettingsTabMounted(\'monitoring\')" id="set-monitoring" v-show="App.activeSettingsTab === \'monitoring\'" class="space-y-4">',
    "settings monitoring lazy mount"
  );
  next = replaceTemplateFragment(
    next,
    '<div id="set-account" v-show="App.activeSettingsTab === \'account\'" class="space-y-4">',
    '<div v-if="App.isSettingsTabMounted(\'account\')" id="set-account" v-show="App.activeSettingsTab === \'account\'" class="space-y-4">',
    "settings account lazy mount"
  );
  next = replaceTemplateFragment(
    next,
    '<div id="set-backup" v-show="App.activeSettingsTab === \'backup\'" class="space-y-4">',
    '<div v-if="App.isSettingsTabMounted(\'backup\')" id="set-backup" v-show="App.activeSettingsTab === \'backup\'" class="space-y-4">',
    "settings backup lazy mount"
  );
  return next;
}

function applyAdminChartRuntimeDeferralPatches(templateSource = "") {
  let next = String(templateSource || "");
  if (!next.includes('data-admin-inline-vendor="chart"')) return next;
  if (isAdminChartRuntimeDeferralPatched(next)) return next;
  next = replaceTemplateFragment(
    next,
    'const{createApp,defineComponent,reactive,onMounted,onBeforeUnmount,nextTick}=Vue,AUTO_ANIMATE_CDN_URL="https://cdn.jsdelivr.net/npm/@formkit/auto-animate@0.9.0/index.mjs";',
    'const{createApp,defineComponent,reactive,onMounted,onBeforeUnmount,nextTick}=Vue,CHART_VENDOR_SCRIPT_ID="admin-inline-chart-vendor",AUTO_ANIMATE_CDN_URL="https://cdn.jsdelivr.net/npm/@formkit/auto-animate@0.9.0/index.mjs";',
    "chart runtime script id"
  );
  next = replaceTemplateFragment(
    next,
    "const DEFAULT_LOG_DATE_RANGE=getDefaultLogDateRange();let autoAnimateLoader=null;",
    "const DEFAULT_LOG_DATE_RANGE=getDefaultLogDateRange();let autoAnimateLoader=null,chartLibraryLoader=null;",
    "chart runtime loader state"
  );
  next = replaceTemplateFragment(
    next,
    'resolveChartConstructor:()=>"function"==typeof window?.Chart?window.Chart:"function"==typeof Chart?Chart:null,supportsBackdropEffects(){',
    'resolveChartConstructor:()=>"function"==typeof window?.Chart?window.Chart:"function"==typeof Chart?Chart:null,ensureChartConstructor(){const r=this.resolveChartConstructor();if(r)return Promise.resolve(r);if(chartLibraryLoader)return chartLibraryLoader;return chartLibraryLoader=new Promise((r,o)=>{const a=document.getElementById(CHART_VENDOR_SCRIPT_ID),n=String(a?.textContent||"").trim();if(!n)return chartLibraryLoader=null,void o(new Error("CHART_VENDOR_SOURCE_MISSING"));const s=document.createElement("script");s.setAttribute("data-admin-runtime-vendor","chart"),s.text=n;try{(document.head||document.documentElement||document.body).appendChild(s);const n=this.resolveChartConstructor();n?(a?.remove?.(),s.remove?.(),r(n)):(chartLibraryLoader=null,s.remove?.(),o(new Error("CHART_CONSTRUCTOR_MISSING")))}catch(r){chartLibraryLoader=null,s.remove?.(),o(r)}}),chartLibraryLoader},supportsBackdropEffects(){',
    "chart runtime loader bridge"
  );
  next = replaceTemplateFragment(
    next,
    'function syncTrafficChart(r,o){if(!r)return;const a=uiBrowserBridge.resolveChartConstructor();if(!a)return void scheduleTrafficChartRetry(r,o);clearTrafficChartRetry(r);',
    'async function syncTrafficChart(r,o){if(!r)return;let a=uiBrowserBridge.resolveChartConstructor();if(!a)try{a=await uiBrowserBridge.ensureChartConstructor()}catch(a){return console.error("chart vendor load failed",a),void scheduleTrafficChartRetry(r,o)}if(!r.isConnected)return void scheduleTrafficChartRetry(r,o);clearTrafficChartRetry(r);',
    "async chart runtime mount"
  );
  return next;
}

function locateAdminTemplateBlockRange(templateSource = "", templateId = "") {
  const html = String(templateSource || "");
  const normalizedTemplateId = String(templateId || "").trim();
  const startNeedle = `<template id="${normalizedTemplateId}">`;
  const startIndex = html.indexOf(startNeedle);
  if (startIndex < 0) throw new Error(`failed to locate admin template block: ${normalizedTemplateId}`);
  let depth = 1;
  let cursor = startIndex + startNeedle.length;
  while (cursor < html.length) {
    const nextOpenIndex = html.indexOf("<template", cursor);
    const nextCloseIndex = html.indexOf("</template>", cursor);
    if (nextCloseIndex < 0) break;
    if (nextOpenIndex >= 0 && nextOpenIndex < nextCloseIndex) {
      depth += 1;
      const nextOpenEnd = html.indexOf(">", nextOpenIndex);
      if (nextOpenEnd < 0) break;
      cursor = nextOpenEnd + 1;
      continue;
    }
    depth -= 1;
    if (depth === 0) {
      return {
        blockStart: startIndex,
        contentStart: startIndex + startNeedle.length,
        blockEnd: nextCloseIndex + "</template>".length
      };
    }
    cursor = nextCloseIndex + "</template>".length;
  }
  throw new Error(`failed to resolve complete admin template block: ${normalizedTemplateId}`);
}

function readAdminTemplateBlock(templateSource = "", templateId = "") {
  const range = locateAdminTemplateBlockRange(templateSource, templateId);
  return String(templateSource || "").slice(range.contentStart, range.blockEnd - "</template>".length);
}

function stripAdminTemplateBlock(templateSource = "", templateId = "") {
  const html = String(templateSource || "");
  const range = locateAdminTemplateBlockRange(html, templateId);
  return `${html.slice(0, range.blockStart)}${html.slice(range.blockEnd)}`;
}

function closeAdminTemplateTailIfNeeded(templateBody = "") {
  const source = String(templateBody || "");
  const openStack = [];
  const tagPattern = /<\/?([A-Za-z][A-Za-z0-9-]*)\b[^>]*>/g;
  for (const match of source.matchAll(tagPattern)) {
    const fullTag = String(match[0] || "");
    const tagName = String(match[1] || "").trim().toLowerCase();
    if (!tagName) continue;
    const isClosingTag = fullTag.startsWith("</");
    const isSelfClosingTag = fullTag.endsWith("/>") || HTML_VOID_TAG_NAMES.has(tagName);
    if (isClosingTag) {
      const lastIndex = openStack.map((entry) => entry.tagName).lastIndexOf(tagName);
      if (lastIndex >= 0) openStack.splice(lastIndex, 1);
      continue;
    }
    if (!isSelfClosingTag) openStack.push({ tagName });
  }
  if (!openStack.length) return source;
  return `${source}${openStack.reverse().map((entry) => `</${entry.tagName}>`).join("")}`;
}

function compileAdminTemplateRenderSource(templateId = "", templateBody = "") {
  const renderConstName = ADMIN_TEMPLATE_ID_TO_RENDER_NAME[templateId];
  if (!renderConstName) throw new Error(`unsupported admin template precompile target: ${templateId}`);
  /** @type {import("@vue/compiler-dom").CompilerOptions} */
  const compileOptions = {
    mode: "function",
    whitespace: "condense",
    hoistStatic: false,
    cacheHandlers: false
  };
  let normalizedTemplateBody = String(templateBody || "");
  let compiled;
  try {
    compiled = compile(normalizedTemplateBody, compileOptions);
  } catch (error) {
    if (!String(error?.message || "").includes("Element is missing end tag.")) throw error;
    normalizedTemplateBody = closeAdminTemplateTailIfNeeded(normalizedTemplateBody);
    compiled = compile(normalizedTemplateBody, compileOptions);
  }
  const renderFactorySource = String(compiled?.code || "").trim();
  if (!renderFactorySource) throw new Error(`vue compiler returned empty render code for ${templateId}`);
  return `const ${renderConstName}=(()=>{${renderFactorySource}})();`;
}

function buildAdminPrecompiledTemplateBundle(templateSource = "") {
  let nextTemplate = String(templateSource || "");
  const expectedTemplateIds = Object.keys(ADMIN_TEMPLATE_ID_TO_RENDER_NAME);
  const embeddedTemplateCount = expectedTemplateIds.filter((templateId) => nextTemplate.includes(`<template id="${templateId}">`)).length;
  if (embeddedTemplateCount === 0) {
    return {
      templateSource: nextTemplate,
      renderPreludeSource: ""
    };
  }
  if (embeddedTemplateCount !== expectedTemplateIds.length) {
    throw new Error("admin template blocks are partially embedded; refusing to precompile inconsistent UI template");
  }
  const renderSources = [];
  for (const templateId of expectedTemplateIds) {
    const templateBody = readAdminTemplateBlock(nextTemplate, templateId);
    renderSources.push(compileAdminTemplateRenderSource(templateId, templateBody));
    nextTemplate = stripAdminTemplateBlock(nextTemplate, templateId);
  }
  return {
    templateSource: nextTemplate,
    renderPreludeSource: renderSources.join("")
  };
}

function replaceInlineStyle(templateSource, options = {}) {
  const isMaterializedHtml = options?.materialized === true;
  return String(templateSource || "").replace(INLINE_STYLE_REGEX, (_, rawStyle) => {
    const { decoded: decodedStyle, expressions } = isMaterializedHtml
      ? { decoded: decodeMaterializedInlineSource(rawStyle), expressions: [] }
      : decodeTemplateLiteral(rawStyle);
    if (expressions.length) throw new Error("unexpected template interpolation inside inline style block");
    const styleWithAliases = decodedStyle.includes(".ui-section-title{")
      ? decodedStyle
      : `${CLASS_ALIAS_CSS}${decodedStyle}`;
    const minifiedStyle = styleWithAliases
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\s+/g, " ")
      .replace(/\s*([{}:;,>])\s*/g, "$1")
      .replace(/;}/g, "}")
      .trim();
    return `<style>${escapeTemplateLiteral(minifiedStyle)}</style>`;
  });
}

async function replaceInlineScripts(templateSource, options = {}) {
  const isMaterializedHtml = options?.materialized === true;
  const matches = Array.from(String(templateSource || "").matchAll(INLINE_SCRIPT_REGEX));
  if (!matches.length) return String(templateSource || "");
  let next = "";
  let lastIndex = 0;
  for (const match of matches) {
    const [fullMatch, attrs = "", rawScript = ""] = match;
    const matchIndex = match.index || 0;
    next += templateSource.slice(lastIndex, matchIndex);
    if (/\bdata-admin-preserve=/.test(attrs) || /\btype\s*=\s*["']application\/json["']/i.test(attrs)) {
      next += fullMatch;
      lastIndex = matchIndex + fullMatch.length;
      continue;
    }
    const { decoded: decodedScript, expressions } = isMaterializedHtml
      ? { decoded: decodeMaterializedInlineSource(rawScript), expressions: [] }
      : decodeTemplateLiteral(rawScript);
    const patchedScript = patchAdminInlineScript(decodedScript, options);
    const minified = await minify(patchedScript, {
      ecma: 2020,
      compress: {
        defaults: true,
        keep_fnames: TEMPLATE_SAFE_FN_NAME,
        passes: 2
      },
      mangle: {
        keep_fnames: TEMPLATE_SAFE_FN_NAME,
        reserved: [ ...SCRIPT_MANGLE_RESERVED, ...expressions.map((expression) => expression.token) ]
      },
      format: {
        ascii_only: true,
        comments: false
      }
    });
    if (typeof minified.code !== "string" || !minified.code.length) {
      throw new Error("terser returned empty inline script output");
    }
    // 这里保持脚本源码为“原始 HTML 形态”，最终再由 buildUiHtmlSection 统一做模板转义，
    // 避免已物化 HTML 走回写链路时把模板字符串二次转义成 \` / \${...}。
    const encodedScript = appendAdminInlineBootstrapSentinels(
      restoreTemplateInterpolations(minified.code, expressions)
    );
    next += `<script${attrs}>${encodedScript}</script>`;
    lastIndex = matchIndex + fullMatch.length;
  }
  return next + templateSource.slice(lastIndex);
}

function replaceAdminDependencyTimeoutMessage(source = "") {
  return String(source || "").replace(
    ADMIN_DEPENDENCY_TIMEOUT_CALL_PATTERN,
    (_, title) => `window.__ADMIN_UI_RENDER_BOOT_ERROR__("${title}","${EMBEDDED_ADMIN_DEPENDENCY_TIMEOUT_MESSAGE}")`
  );
}

function replaceAdminEmbeddedDependencies(templateSource = "", assetBundle = {}) {
  const headHtml = String(assetBundle?.headHtml || "");
  let next = replaceAdminDependencyTimeoutMessage(String(templateSource || ""));
  next = next
    .replace(LEGACY_ADMIN_TAILWIND_PLAY_SCRIPT_PATTERN, "")
    .replace(LEGACY_ADMIN_VUE_SCRIPT_PATTERN, "")
    .replace(LEGACY_ADMIN_LUCIDE_SCRIPT_PATTERN, "")
    .replace(LEGACY_ADMIN_CHART_SCRIPT_PATTERN, "")
    .replace(LEGACY_ADMIN_TAILWIND_CONFIG_SCRIPT_PATTERN, "")
    .replace(SAME_ORIGIN_ADMIN_STYLE_LINK_PATTERN, "")
    .replace(SAME_ORIGIN_ADMIN_VUE_LINK_PATTERN, "")
    .replace(SAME_ORIGIN_ADMIN_LUCIDE_SCRIPT_PATTERN, "")
    .replace(SAME_ORIGIN_ADMIN_CHART_SCRIPT_PATTERN, "")
    .replace(EMBEDDED_ADMIN_INLINE_STYLE_PATTERN, "")
    .replace(EMBEDDED_ADMIN_INLINE_VENDOR_SCRIPT_PATTERN, "");
  if (!headHtml) return next;
  let index = next.indexOf("<style>");
  if (index < 0) index = next.indexOf('<script data-admin-preserve="1">');
  if (index < 0) index = next.indexOf("</head>");
  if (index < 0) throw new Error("failed to locate <head> insertion point for inline admin dependency injection");
  return `${next.slice(0, index)}${headHtml}${next.slice(index)}`;
}

function buildAdminInlineLucideHelperSource(registrySource = "{}") {
  return [
    `const ADMIN_LUCIDE_ICON_NODES=Object.freeze(${registrySource});`,
    "function normalizeAdminInlineIconName(value=\"\"){return String(value||\"\").trim().toLowerCase()}",
    "function createAdminInlineIconElement(sourceElement,name=\"\"){const normalizedName=normalizeAdminInlineIconName(name),iconNodes=ADMIN_LUCIDE_ICON_NODES[normalizedName];if(!sourceElement||!Array.isArray(iconNodes)||!iconNodes.length||typeof document?.createElementNS!==\"function\")return null;const svg=document.createElementNS(\"http://www.w3.org/2000/svg\",\"svg\");svg.setAttribute(\"xmlns\",\"http://www.w3.org/2000/svg\"),svg.setAttribute(\"viewBox\",\"0 0 24 24\"),svg.setAttribute(\"fill\",\"none\"),svg.setAttribute(\"stroke\",\"currentColor\"),svg.setAttribute(\"stroke-width\",\"2\"),svg.setAttribute(\"stroke-linecap\",\"round\"),svg.setAttribute(\"stroke-linejoin\",\"round\");const className=String(sourceElement.getAttribute(\"class\")||\"\").trim(),styleText=String(sourceElement.getAttribute(\"style\")||\"\").trim(),roleText=String(sourceElement.getAttribute(\"role\")||\"\").trim(),ariaHidden=sourceElement.getAttribute(\"aria-hidden\"),ariaLabel=String(sourceElement.getAttribute(\"aria-label\")||\"\").trim(),titleText=String(sourceElement.getAttribute(\"title\")||\"\").trim();className&&svg.setAttribute(\"class\",className),styleText&&svg.setAttribute(\"style\",styleText),roleText&&svg.setAttribute(\"role\",roleText),svg.setAttribute(\"aria-hidden\",null===ariaHidden?\"true\":ariaHidden),ariaLabel&&svg.setAttribute(\"aria-label\",ariaLabel),titleText&&svg.setAttribute(\"title\",titleText);for(const entry of iconNodes){if(!Array.isArray(entry)||!entry.length)continue;const[tagName,rawAttrs={}]=entry;if(!tagName)continue;const child=document.createElementNS(\"http://www.w3.org/2000/svg\",String(tagName));for(const[attrName,attrValue]of Object.entries(rawAttrs||{}))null!=attrValue&&child.setAttribute(String(attrName),String(attrValue));svg.appendChild(child)}return svg}",
    "function renderAdminInlineIcons(options={}){const root=options&&\"object\"==typeof options&&options.root?options.root:document,nodes=[];if(!root)return;root?.matches?.(\"[data-lucide]\")&&nodes.push(root);if(\"function\"==typeof root.querySelectorAll)for(const node of root.querySelectorAll(\"[data-lucide]\"))nodes.push(node);for(const sourceElement of nodes){const iconName=String(sourceElement?.getAttribute?.(\"data-lucide\")||\"\").trim(),replacement=createAdminInlineIconElement(sourceElement,iconName);if(!replacement)continue;\"function\"==typeof sourceElement.replaceWith?sourceElement.replaceWith(replacement):sourceElement.parentNode?.replaceChild?.(replacement,sourceElement)}}"
  ].join("");
}

function replaceScriptFragmentIfPresent(source, from, to) {
  const scriptText = String(source || "");
  return scriptText.includes(from) ? scriptText.replace(from, to) : scriptText;
}

function stripAdminInlineLucideHelperSource(scriptSource = "") {
  return String(scriptSource || "").replace(
    /const ADMIN_LUCIDE_ICON_NODES=Object\.freeze\([\s\S]*?(?=function scheduleLucideIconsRender)/,
    ""
  );
}

function normalizeAdminVendorRuntimeForCdn(scriptSource = "") {
  let next = stripAdminInlineLucideHelperSource(scriptSource);
  next = next.replace(
    /renderLucideIcons\(([A-Za-z_$][\w$]*)=\{\}\)\{try\{incrementAdminUiDebugCounter\("lucideRenderCount"\),renderAdminInlineIcons\(\1\)\}catch\(([A-Za-z_$][\w$]*)\)\{console\.error\("renderAdminInlineIcons failed",\2\)\}\}/,
    'renderLucideIcons($1={}){if(void 0!==window?.lucide)try{incrementAdminUiDebugCounter("lucideRenderCount"),window.lucide.createIcons($1)}catch($2){console.error("lucide.createIcons failed",$2)}}'
  );
  next = replaceScriptFragmentIfPresent(
    next,
    'const{createApp,defineComponent,reactive,onMounted,onBeforeUnmount,nextTick}=Vue,CHART_VENDOR_SCRIPT_ID="admin-inline-chart-vendor",AUTO_ANIMATE_CDN_URL="https://cdn.jsdelivr.net/npm/@formkit/auto-animate@0.9.0/index.mjs";',
    'const{createApp,defineComponent,reactive,onMounted,onBeforeUnmount,nextTick}=Vue,AUTO_ANIMATE_CDN_URL="https://cdn.jsdelivr.net/npm/@formkit/auto-animate@0.9.0/index.mjs";'
  );
  next = replaceScriptFragmentIfPresent(
    next,
    "const DEFAULT_LOG_DATE_RANGE=getDefaultLogDateRange();let autoAnimateLoader=null,chartLibraryLoader=null;",
    "const DEFAULT_LOG_DATE_RANGE=getDefaultLogDateRange();let autoAnimateLoader=null;"
  );
  next = next.replace(
    /,ensureChartConstructor\(\)\{[\s\S]*?\},supportsBackdropEffects\(\)\{/,
    ",supportsBackdropEffects(){"
  );
  next = next.replace(
    /async function syncTrafficChart\(([A-Za-z_$][\w$]*),([A-Za-z_$][\w$]*)\)\{if\(!\1\)return;let ([A-Za-z_$][\w$]*)=uiBrowserBridge\.resolveChartConstructor\(\);if\(!\3\)try\{\3=await uiBrowserBridge\.ensureChartConstructor\(\)\}catch\(([A-Za-z_$][\w$]*)\)\{return console\.error\("chart vendor load failed",\4\),void scheduleTrafficChartRetry\(\1,\2\)\}if\(!\1\.isConnected\)return void scheduleTrafficChartRetry\(\1,\2\);clearTrafficChartRetry\(\1\);/,
    "function syncTrafficChart($1,$2){if(!$1)return;const $3=uiBrowserBridge.resolveChartConstructor();if(!$3)return void scheduleTrafficChartRetry($1,$2);clearTrafficChartRetry($1);"
  );
  return next;
}

function replaceScriptFragment(source, from, to, label) {
  const scriptText = String(source || "");
  if (scriptText.includes(to)) return scriptText;
  if (!scriptText.includes(from)) {
    throw new Error(`failed to locate inline script fragment for ${label}`);
  }
  return scriptText.replace(from, to);
}

function isAdminRuntimePerfPatched(scriptSource = "") {
  const scriptText = String(scriptSource || "");
  return scriptText.includes("createAdminMountedViewState")
    && scriptText.includes("createAdminMountedSettingsTabState")
    && scriptText.includes("ensureSettingsTabMounted(")
    && scriptText.includes("nodeMicroMotionEnabled");
}

function applyAdminRuntimePerfPatches(scriptSource = "") {
  let next = String(scriptSource || "");
  next = replaceScriptFragment(
    next,
    'function createUiFoundationStore(){return{navItems:NAV_ITEMS,currentHash:"#dashboard",pageTitle:"\\u52a0\\u8f7d\\u4e2d...",sidebarOpen:!1,desktopSidebarCollapsed:!1,isDarkTheme:!1,prefersReducedMotion:!1,isCoarsePointer:!1,isLowPerformanceDevice:!1,disableBackdropEffects:!1,isDesktopViewport:!1,isDesktopSettingsLayout:!1,contentScrollResetKey:0,settingsScrollResetKey:0,settingsExperienceMode:"novice",uiRadiusCssValue:"10px",activeSettingsTab:"ui",nodeSearchKeyword:"",nodeFilterSyncTimer:null,',
    'function createAdminMountedViewState(){return{"#dashboard":!0,"#nodes":!1,"#logs":!1,"#dns":!1,"#settings":!1}}function createAdminMountedSettingsTabState(){return{ui:!0,proxy:!1,dns:!1,cache:!1,security:!1,logs:!1,monitoring:!1,account:!1,backup:!1}}function createUiFoundationStore(){return{navItems:NAV_ITEMS,currentHash:"#dashboard",pageTitle:"\\u52a0\\u8f7d\\u4e2d...",sidebarOpen:!1,desktopSidebarCollapsed:!1,isDarkTheme:!1,prefersReducedMotion:!1,isCoarsePointer:!1,isLowPerformanceDevice:!1,disableBackdropEffects:!1,isDesktopViewport:!1,isDesktopSettingsLayout:!1,contentScrollResetKey:0,settingsScrollResetKey:0,settingsExperienceMode:"novice",uiRadiusCssValue:"10px",activeSettingsTab:"ui",mountedViews:createAdminMountedViewState(),mountedSettingsTabs:createAdminMountedSettingsTabState(),nodeSearchKeyword:"",nodeFilterSyncTimer:null,',
    "mounted state seed"
  );
  next = replaceScriptFragment(
    next,
    'switchSetTab(e){const t=String(e||"").trim();this.isSettingsTabVisible(t)&&t&&this.activeSettingsTab!==t&&(this.activeSettingsTab=t,this.settingsScrollResetKey+=1,("proxy"===t||"backup"===t)&&this.ensureWorkerPlacementLoaded(),"dns"===t&&this.ensureDnsSettingsSourceDataLoaded().catch(e=>{console.warn("load dns settings sources failed",e)}))}',
    'switchSetTab(e){const t=String(e||"").trim();this.isSettingsTabVisible(t)&&t&&this.activeSettingsTab!==t&&(this.ensureSettingsTabMounted(t),this.activeSettingsTab=t,this.settingsScrollResetKey+=1,("proxy"===t||"backup"===t)&&this.ensureWorkerPlacementLoaded(),"dns"===t&&this.ensureDnsSettingsSourceDataLoaded().catch(e=>{console.warn("load dns settings sources failed",e)}))}',
    "settings tab mount hook"
  );
  next = replaceScriptFragment(
    next,
    'openLogsSettings(){return this.activeSettingsTab="logs",this.navigate("#settings")},route(e=""){const t=normalizeViewHash(e||this.getCurrentRouteHash(),"#dashboard"),r=normalizeViewHash(this.currentHash||"#dashboard","#dashboard");',
    'openLogsSettings(){return this.ensureSettingsTabMounted("logs"),this.activeSettingsTab="logs",this.navigate("#settings")},normalizeMountedViewKey(e=""){const t=normalizeViewHash(String(e||""),"#dashboard");return VIEW_TITLES[t]?t:"#dashboard"},ensureViewMounted(e=""){const t=this.normalizeMountedViewKey(e),r=this.mountedViews&&"object"==typeof this.mountedViews?this.mountedViews:createAdminMountedViewState();return!!r[t]||(this.mountedViews={...r,[t]:!0},!0)},isViewMounted(e=""){const t=this.normalizeMountedViewKey(e),r=this.mountedViews&&"object"==typeof this.mountedViews?this.mountedViews:createAdminMountedViewState();return!!r[t]},normalizeSettingsTabMountKey(e=""){return String(e||"").trim()||"ui"},ensureSettingsTabMounted(e=""){const t=this.normalizeSettingsTabMountKey(e),r=this.mountedSettingsTabs&&"object"==typeof this.mountedSettingsTabs?this.mountedSettingsTabs:createAdminMountedSettingsTabState();return!!r[t]||(this.mountedSettingsTabs={...r,[t]:!0},!0)},isSettingsTabMounted(e=""){const t=this.normalizeSettingsTabMountKey(e),r=this.mountedSettingsTabs&&"object"==typeof this.mountedSettingsTabs?this.mountedSettingsTabs:createAdminMountedSettingsTabState();return!!r[t]},route(e=""){const t=normalizeViewHash(e||this.getCurrentRouteHash(),"#dashboard"),r=normalizeViewHash(this.currentHash||"#dashboard","#dashboard");this.ensureViewMounted(t),"#settings"===t&&this.ensureSettingsTabMounted(this.activeSettingsTab||"ui");',
    "view lazy mount helpers"
  );
  next = replaceScriptFragment(
    next,
    "this.syncRenderCompatibilityState(),this.syncFilteredNodes(),this.route(this.getCurrentRouteHash())",
    'this.syncRenderCompatibilityState(),this.ensureViewMounted(this.getCurrentRouteHash()),"#settings"===normalizeViewHash(this.getCurrentRouteHash(),"#dashboard")&&this.ensureSettingsTabMounted(this.activeSettingsTab||"ui"),this.route(this.getCurrentRouteHash())',
    "init lazy mount bootstrap"
  );
  next = replaceScriptFragment(
    next,
    'queueTask(r){"function"==typeof r&&("function"!=typeof queueMicrotask?Promise.resolve().then(r):queueMicrotask(r))},queueAnimationFrame(r){"function"==typeof r&&("function"!=typeof window?.requestAnimationFrame?this.queueTask(r):window.requestAnimationFrame(()=>r()))},startTimer:(r,o=0)=>setTimeout(r,Math.max(0,Number(o)||0)),',
    'queueTask(r){"function"==typeof r&&("function"!=typeof queueMicrotask?Promise.resolve().then(r):queueMicrotask(r))},queueAnimationFrame(r){"function"==typeof r&&("function"!=typeof window?.requestAnimationFrame?this.queueTask(r):window.requestAnimationFrame(()=>r()))},queueIdleTask(r,o=64){if("function"!=typeof r)return;const a=Math.max(16,Number(o)||64);if("function"==typeof window?.requestIdleCallback){window.requestIdleCallback(()=>r(),{timeout:a});return}this.startTimer(()=>this.queueAnimationFrame(r),a)},queueIdleAfterPaint(r,o=64){"function"==typeof r&&this.queueAnimationFrame(()=>this.queueIdleTask(r,o))},startTimer:(r,o=0)=>setTimeout(r,Math.max(0,Number(o)||0)),',
    "idle task bridge"
  );
  next = replaceScriptFragment(
    next,
    'function scheduleLucideIconsRender(r,o){if(!r)return;const a=normalizeLucideDirectiveOptions(o),n=lucideDirectiveStates.get(r)||{queued:!1,timerId:null,lastRunAt:0};if(lucideDirectiveStates.set(r,n),n.queued)return;n.queued=!0;const s=()=>{n.queued=!1,n.timerId=null,n.lastRunAt=Date.now(),uiBrowserBridge.queueAnimationFrame(()=>{!1!==r.isConnected&&uiBrowserBridge.renderLucideIcons({root:r})})},i=Date.now()-n.lastRunAt,l=Math.max(0,a.throttleMs-i);if(l>0)return n.timerId&&uiBrowserBridge.clearTimer(n.timerId),void(n.timerId=uiBrowserBridge.startTimer(s,l));s()}',
    'function scheduleLucideIconsRender(r,o){if(!r)return;const a=normalizeLucideDirectiveOptions(o),n=lucideDirectiveStates.get(r)||{queued:!1,timerId:null,lastRunAt:0};if(lucideDirectiveStates.set(r,n),n.queued)return;n.queued=!0;const s=()=>{n.queued=!1,n.timerId=null,n.lastRunAt=Date.now();const o=()=>{!1!==r.isConnected&&uiBrowserBridge.renderLucideIcons({root:r})};n.lastRunAt>0?uiBrowserBridge.queueAnimationFrame(o):uiBrowserBridge.queueIdleAfterPaint(o,96)},i=Date.now()-n.lastRunAt,l=Math.max(0,a.throttleMs-i);if(l>0)return n.timerId&&uiBrowserBridge.clearTimer(n.timerId),void(n.timerId=uiBrowserBridge.startTimer(s,l));s()}',
    "lucide idle after paint"
  );
  next = replaceScriptFragment(
    next,
    'syncFilteredNodes(){this.clearNodeFilterSyncTimer();const r=String(this.nodeSearchKeyword||"").trim().toLowerCase();return incrementAdminUiDebugCounter("nodeFilterSyncCount"),this.filteredNodes=(Array.isArray(this.nodes)?this.nodes:[]).filter(r=>r&&"object"==typeof r).filter(o=>{if(!this.doesNodeMatchActiveTagFilter(o))return!1;const a=String(o.name||"").trim(),n=String(o.displayName||o.name||"").trim();return!(!a&&!n)&&(!r||String(o._searchIndexText||"").includes(r))}),setAdminUiDebugValue("nodeMicroMotionEnabled",this.shouldEnableNodeMicroMotion()),this.filteredNodes}',
    'syncFilteredNodes(){this.clearNodeFilterSyncTimer();const r=String(this.nodeSearchKeyword||"").trim().toLowerCase(),o=(Array.isArray(this.nodes)?this.nodes:[]).filter(r=>r&&"object"==typeof r).filter(o=>{if(!this.doesNodeMatchActiveTagFilter(o))return!1;const a=String(o.name||"").trim(),n=String(o.displayName||o.name||"").trim();return!(!a&&!n)&&(!r||String(o._searchIndexText||"").includes(r))}),a=Array.isArray(this.filteredNodes)?this.filteredNodes:[],n=a.length===o.length&&a.every((r,a)=>{const n=o[a];return r===n||this.normalizeNodeKey(r?.name)===this.normalizeNodeKey(n?.name)});return incrementAdminUiDebugCounter("nodeFilterSyncCount"),n||(this.filteredNodes=o),setAdminUiDebugValue("nodeMicroMotionEnabled",this.shouldEnableNodeMicroMotion()),this.filteredNodes}',
    "stable filtered nodes assignment"
  );
  next = replaceScriptFragment(
    next,
    'setNodeLineRuntimeLatency(r,o,a,n=""){const s=this.buildNodePingRuntimeKey(r,o);if(!s)return null;const i=this.parseLatencyMs(a),l=this.normalizeNodePingRuntimeTimestamp(n)||(new Date).toISOString(),d={...this.nodePingRuntimeMap&&"object"==typeof this.nodePingRuntimeMap?this.nodePingRuntimeMap:{},[s]:{latencyMs:null===i?9999:i,latencyUpdatedAt:l}};return this.nodePingRuntimeMap=d,d[s]}',
    'setNodeLineRuntimeLatency(r,o,a,n=""){const s=this.buildNodePingRuntimeKey(r,o);if(!s)return null;const i=this.parseLatencyMs(a),l=this.normalizeNodePingRuntimeTimestamp(n)||(new Date).toISOString(),d=this.nodePingRuntimeMap&&"object"==typeof this.nodePingRuntimeMap?this.nodePingRuntimeMap:this.nodePingRuntimeMap={};return d[s]={latencyMs:null===i?9999:i,latencyUpdatedAt:l},d[s]}',
    "stable node ping runtime map writes"
  );
  return next;
}

function patchAdminInlineScript(scriptSource, options = {}) {
  const useInlineLucide = Boolean(String(options?.lucideRegistrySource || "").trim());
  let next = replaceAdminDependencyTimeoutMessage(scriptSource);
  if (!next.includes("uiBrowserBridge={renderLucideIcons")) return next;
  next = normalizeAdminVendorRuntimeForCdn(next);
  if (!isAdminRuntimePerfPatched(next)) next = applyAdminRuntimePerfPatches(next);
  if (useInlineLucide && !next.includes("const ADMIN_LUCIDE_ICON_NODES=")) {
    next = next.replace(
      "function scheduleLucideIconsRender",
      `${buildAdminInlineLucideHelperSource(String(options?.lucideRegistrySource || "{}"))}function scheduleLucideIconsRender`
    );
  }
  if (options?.renderPreludeSource && !next.includes(String(options.renderPreludeSource))) {
    next = replaceScriptFragment(
      next,
      "uiBrowserBridge={renderLucideIcons",
      `${String(options.renderPreludeSource)}uiBrowserBridge={renderLucideIcons`,
      "precompiled render prelude"
    );
  }
  if (useInlineLucide) {
    next = next.replace(
      'renderLucideIcons(e={}){if(void 0!==window?.lucide)try{incrementAdminUiDebugCounter("lucideRenderCount"),window.lucide.createIcons(e)}catch(e){console.error("lucide.createIcons failed",e)}}',
      'renderLucideIcons(e={}){try{incrementAdminUiDebugCounter("lucideRenderCount"),renderAdminInlineIcons(e)}catch(e){console.error("renderAdminInlineIcons failed",e)}}'
    );
  }
  next = replaceScriptFragment(
    next,
    'template:"#tpl-copy-button"',
    `render:${ADMIN_TEMPLATE_ID_TO_RENDER_NAME["tpl-copy-button"]}`,
    "copy button precompiled render"
  );
  next = replaceScriptFragment(
    next,
    'template:"#tpl-node-card"',
    `render:${ADMIN_TEMPLATE_ID_TO_RENDER_NAME["tpl-node-card"]}`,
    "node card precompiled render"
  );
  next = replaceScriptFragment(
    next,
    'template:"#tpl-app"',
    `render:${ADMIN_TEMPLATE_ID_TO_RENDER_NAME["tpl-app"]}`,
    "root app precompiled render"
  );
  return next;
}

function injectPreservedAdminHelpers(templateSource) {
  const next = String(templateSource || "");
  const insertion = PRESERVED_ADMIN_HELPER_SCRIPT_HTML;
  if (next.includes("data-admin-preserve=\"1\"")) {
    return next.replace(/<script data-admin-preserve="1">[\s\S]*?<\/script>/, insertion);
  }
  const needle = "</head>";
  const index = next.indexOf(needle);
  if (index < 0) throw new Error("failed to locate </head> for preserved admin helper injection");
  return `${next.slice(0, index)}${insertion}${next.slice(index)}`;
}

function stashHtmlSectionRange(templateSource, section, stash) {
  const html = String(templateSource || "");
  const startIndex = html.indexOf(String(section?.start || ""));
  if (startIndex < 0) return html;
  const endNeedle = String(section?.end || "");
  if (!endNeedle) return html;
  const endIndex = html.indexOf(endNeedle, startIndex);
  if (endIndex < 0) return html;
  const token = `__UI_HTML_BLOCK_${stash.length}__`;
  stash.push(html.slice(startIndex, endIndex + endNeedle.length));
  return `${html.slice(0, startIndex)}${token}${html.slice(endIndex + endNeedle.length)}`;
}

function stashPreservedHtmlSections(templateSource, stash) {
  let next = String(templateSource || "");
  for (const section of PRESERVED_HTML_SECTION_MARKERS) {
    next = stashHtmlSectionRange(next, section, stash);
  }
  return next;
}

function collapseHtmlWhitespace(templateSource) {
  const stash = [];
  const preservedSections = stashPreservedHtmlSections(templateSource, stash);
  const shielded = String(preservedSections || "").replace(/<(script|style)\b[\s\S]*?<\/\1>/g, (block) => {
    const token = `__UI_HTML_BLOCK_${stash.length}__`;
    stash.push(block);
    return token;
  });
  const compact = shielded
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/[ \t]+$/gm, "")
    .replace(/^[ \t]+(?=(?:<|__))/gm, "")
    .replace(/>\s+</g, "><")
    .replace(/>(\s+)(__[A-Z0-9_]+__)/g, ">$2")
    .replace(/(__[A-Z0-9_]+__)(\s+)</g, "$1<")
    .replace(/(__[A-Z0-9_]+__)(\s+)(__[A-Z0-9_]+__)/g, "$1$3")
    .trim();
  return stash.reduce((output, block, index) => output.replace(`__UI_HTML_BLOCK_${index}__`, block), compact);
}

function normalizeTrailingHtmlClose(templateSource) {
  return String(templateSource || "").replace(/(?:<\/html>\s*){2,}$/i, "</html>");
}

function splitAdminHtmlTemplate(templateSource) {
  const source = String(templateSource || "");
  const parts = [];
  let cursor = 0;
  for (const placeholder of ADMIN_HTML_DYNAMIC_PLACEHOLDERS) {
    const index = source.indexOf(placeholder, cursor);
    if (index < 0) throw new Error(`missing admin html placeholder: ${placeholder}`);
    parts.push(source.slice(cursor, index));
    cursor = index + placeholder.length;
  }
  parts.push(source.slice(cursor));
  return parts;
}

function buildAdminHtmlVariants(templateSource) {
  const template = String(templateSource || "");
  const plainParts = splitAdminHtmlTemplate(template);
  const etag = createHash("sha256").update(template).digest("hex").slice(0, 16);
  return { plainParts, etag };
}

function replaceSourceRange(source, start, end, replacement) {
  return `${source.slice(0, start)}${replacement}${source.slice(end)}`;
}

function replaceRequiredSnippet(source, searchValue, replacement, label) {
  if (!String(source || "").includes(searchValue)) {
    throw new Error(`failed to locate ${label}`);
  }
  return String(source || "").replace(searchValue, replacement);
}

function buildDeploySource(source, templateSource) {
  const variants = buildAdminHtmlVariants(templateSource);
  const uiHtml = locateUiHtml(source);
  let deploySource = replaceSourceRange(source, uiHtml.start, uiHtml.blockEnd, buildUiHtmlSection(""));
  deploySource = replaceRequiredSnippet(deploySource, FINAL_UI_HTML_MARKER, FINAL_UI_HTML_MARKER, "deploy FINAL_UI_HTML marker");
  deploySource = replaceRequiredSnippet(
    deploySource,
    ADMIN_HTML_VARIANT_ETAG_MARKER,
    `const ADMIN_HTML_VARIANT_ETAG = ${JSON.stringify(variants.etag)};`,
    "deploy etag marker"
  );
  deploySource = replaceRequiredSnippet(
    deploySource,
    ADMIN_HTML_PARTS_PLAIN_MARKER,
    `const ADMIN_HTML_PARTS_PLAIN = Object.freeze(${JSON.stringify(variants.plainParts)});`,
    "deploy plain parts marker"
  );
  return { deploySource, variants };
}

async function buildNextSource(workerPath) {
  const source = await readFile(workerPath, "utf8");
  const uiHtml = locateUiHtml(source);
  const materializedUiHtml = decodeTemplateLiteral(uiHtml.value).decoded;
  let nextTemplate = ensureAdminSentinels(String(materializedUiHtml || ""));
  nextTemplate = applyClassAliases(nextTemplate);
  nextTemplate = applyAdminTemplatePerfPatches(nextTemplate);
  const precompiledTemplates = buildAdminPrecompiledTemplateBundle(nextTemplate);
  nextTemplate = precompiledTemplates.templateSource;
  const inlineAssetBundle = await buildAdminInlineAssetBundle();
  nextTemplate = replaceAdminEmbeddedDependencies(nextTemplate, inlineAssetBundle);
  nextTemplate = replaceInlineStyle(nextTemplate, { materialized: true });
  nextTemplate = await replaceInlineScripts(nextTemplate, {
    materialized: true,
    lucideRegistrySource: inlineAssetBundle.lucideRegistrySource,
    renderPreludeSource: precompiledTemplates.renderPreludeSource
  });
  nextTemplate = injectPreservedAdminHelpers(nextTemplate);
  nextTemplate = applyAdminChartRuntimeDeferralPatches(nextTemplate);
  nextTemplate = collapseHtmlWhitespace(nextTemplate);
  nextTemplate = normalizeTrailingHtmlClose(nextTemplate);

  const nextUiSection = buildUiHtmlSection(nextTemplate);
  return {
    nextSource: `${source.slice(0, uiHtml.start)}${nextUiSection}${source.slice(uiHtml.blockEnd)}`,
    nextTemplate,
    source
  };
}

async function main() {
  const workerPath = WORKER_PATH;
  const { nextSource, nextTemplate, source } = await buildNextSource(workerPath);
  if (CHECK_MODE) {
    if (nextSource !== source) {
      console.error(`admin UI build drift detected in ${workerPath}`);
      process.exit(1);
    }
    console.log("admin UI build output is in sync");
    return;
  }

  if (nextSource === source && !DEPLOY_OUTPUT_PATH) {
    console.log("admin UI already compressed");
    return;
  }

  if (nextSource !== source) {
    await writeFile(workerPath, nextSource, "utf8");
    console.log(`rewrote final admin UI template in ${workerPath}`);
  } else {
    console.log("admin UI already compressed");
  }

  if (DEPLOY_OUTPUT_PATH) {
    const { deploySource, variants } = buildDeploySource(nextSource, nextTemplate);
    await writeFile(DEPLOY_OUTPUT_PATH, deploySource, "utf8");
    console.log(
      `wrote deploy worker source in ${DEPLOY_OUTPUT_PATH} `
      + `(plain parts: ${variants.plainParts.length})`
    );
  }
}

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exit(1);
});
