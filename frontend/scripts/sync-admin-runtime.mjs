import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
  ADMIN_RUNTIME_ENHANCEMENT_STYLE,
} from "./admin-runtime-enhancements.mjs";
import { applyAdminTailwindPrecompile } from "./build-admin-tailwind.mjs";
import { findAdminModuleScriptTags, inspectRuntimeAssets } from "./check-cdn-paths.mjs";
import { APP_VERSION } from "../../worker/core/build-info.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..", "..");
const sourceHtmlPath = path.resolve(repoRoot, "frontend/admin-runtime.template.html");
const targetHtmlPath = path.resolve(repoRoot, "frontend/index.html");
const targetMetaPath = path.resolve(repoRoot, "frontend/.admin-runtime-sync.json");

const ADMIN_BOOTSTRAP_PLACEHOLDER = "__ADMIN_BOOTSTRAP_JSON__";
const ADMIN_APP_ROOT_PLACEHOLDER = "__ADMIN_APP_ROOT__";
const ADMIN_APP_VERSION_PLACEHOLDER = "__APP_VERSION__";
const ADMIN_APP_ROOT_HTML = '<div id="app" v-cloak></div>';

function sha256(text = "") {
  return createHash("sha256")
    .update(String(text || ""), "utf8")
    .digest("hex");
}

function serializeInlineJson(payload) {
  return JSON.stringify(payload).replace(/</g, "\\u003c");
}

function buildFallbackBootstrap(adminPath = "/admin") {
  return {
    adminPath,
    loginPath: `${adminPath.replace(/\/+$/, "") || "/admin"}/login`,
  };
}

// frontend/src 是保留的源世代（勿删，见 frontend/src/README.md）：管理端 HTML 一旦出现 module script 就是半接通状态。
function assertNoModuleScriptEntry(html = "", label = "") {
  const moduleScripts = findAdminModuleScriptTags(html);
  if (moduleScripts.length > 0) {
    throw new Error(
      `${label} 含有 ${moduleScripts.length} 个 module script：管理端 HTML 必须保持原生 script 交付，组件化迁移未启用（见 frontend/src/README.md）`,
    );
  }
}

function validateSourceTemplate(templateHtml = "") {
  const source = String(templateHtml || "");
  assertNoModuleScriptEntry(source, "admin runtime template");
  const missing = [
    ADMIN_BOOTSTRAP_PLACEHOLDER,
    ADMIN_APP_ROOT_PLACEHOLDER,
    ADMIN_APP_VERSION_PLACEHOLDER,
  ].filter((token) => !source.includes(token));

  if (missing.length) {
    throw new Error(`admin runtime template 缺少占位符：${missing.join(", ")}`);
  }

  if (!/<script(?=[^>]*\bid="admin-bootstrap-loader")[^>]*>/i.test(source)) {
    throw new Error("admin runtime template 缺少 admin-bootstrap-loader 脚本");
  }

  if (/(?:dnsAutoUpload|DNS_AUTO_UPLOAD)[A-Za-z_]*/.test(source)) {
    throw new Error("admin runtime template 仍包含未受 Worker 支持的 dnsAutoUpload 配置");
  }

  const runtimeInspection = inspectRuntimeAssets(source);
  if (runtimeInspection.inlineDynamicImports.length) {
    throw new Error("admin runtime template 不得包含任何 inline 动态 import");
  }
}

async function materializeFrontendIndex(templateHtml = "") {
  validateSourceTemplate(templateHtml);

  const output = String(templateHtml || "")
    .replace(ADMIN_BOOTSTRAP_PLACEHOLDER, serializeInlineJson(buildFallbackBootstrap()))
    .replace(ADMIN_APP_ROOT_PLACEHOLDER, ADMIN_APP_ROOT_HTML)
    .replaceAll(ADMIN_APP_VERSION_PLACEHOLDER, `V${APP_VERSION}`);

  const unresolvedTokens = [
    ADMIN_BOOTSTRAP_PLACEHOLDER,
    ADMIN_APP_ROOT_PLACEHOLDER,
    ADMIN_APP_VERSION_PLACEHOLDER,
  ].filter((token) => output.includes(token));

  if (unresolvedTokens.length) {
    throw new Error(`frontend/index.html 仍残留占位符：${unresolvedTokens.join(", ")}`);
  }

  if (
    !/<script(?=[^>]*\bid="admin-bootstrap")(?=[^>]*\btype="application\/json")[^>]*>\s*\{[\s\S]*?\}\s*<\/script>/i.test(
      output,
    )
  ) {
    throw new Error("frontend/index.html 缺少可解析的 admin-bootstrap JSON 脚本");
  }

  if (!output.includes(ADMIN_APP_ROOT_HTML)) {
    throw new Error("frontend/index.html 缺少 #app 根节点");
  }

  const composed = composeAdminRuntimeEnhancements(output);
  // Tailwind 预编译放在增强层之后：候选集要覆盖增强脚本注入的 class，所以扫描对象是
  // 组合后的壳（编译产物只替换主题块本身，不移动层叠位置）。
  const tailwind = await applyAdminTailwindPrecompile(composed);
  assertNoModuleScriptEntry(tailwind.html, "frontend/index.html");
  console.log(
    `[sync:admin-runtime] 预编译 Tailwind CSS ${Buffer.byteLength(tailwind.css, "utf8")} B（候选 ${tailwind.candidateCount} 个）`,
  );
  return tailwind.html;
}

function replaceRequired(source, search, replacement, label) {
  if (!source.includes(search)) {
    throw new Error(`admin runtime template 缺少契约片段：${label}`);
  }
  return source.replace(search, replacement);
}

function replaceAllRequired(source, search, replacement, label) {
  if (!source.includes(search)) {
    throw new Error(`admin runtime template 缺少契约片段：${label}`);
  }
  return source.replaceAll(search, replacement);
}

function applyHeadProbeContract(outputHtml = "") {
  let output = String(outputHtml || "");
  output = replaceAllRequired(output, "pingTimeout:5e3", "pingTimeout:1e4", "GET 默认超时");
  output = replaceRequired(
    output,
    "pingTimeout:{fallback:5e3,min:1e3,max:18e4}",
    "pingTimeout:{fallback:1e4,min:1e3,max:18e4}",
    "GET 超时配置边界",
  );
  output = replaceAllRequired(
    output,
    "Ping \\u8d85\\u65f6",
    "GET \\u8d85\\u65f6",
    "GET 超时显示名",
  );
  output = replaceAllRequired(
    output,
    "HEAD \\u6d4b\\u8bd5",
    "GET \\u6d4b\\u8bd5",
    "GET 测试显示名",
  );
  output = replaceAllRequired(
    output,
    "HEAD \\u5ef6\\u8fdf",
    "GET \\u5ef6\\u8fdf",
    "GET 卡片延迟显示名",
  );
  output = replaceAllRequired(
    output,
    "\\u4e00\\u952e GET \\u6d4b\\u8bd5",
    "\\u5168\\u5c40 GET \\u6d4b\\u8bd5",
    "节点线路 GET 测试按钮",
  );
  output = replaceRequired(
    output,
    'nodeModalProbePath:"/emby/system/info/public",',
    "",
    "移除节点探测路径状态",
  );
  output = replaceRequired(
    output,
    's="/emby/system/ping"===this.nodeModalProbePath?"/emby/system/ping":"/emby/system/info/public";',
    's="/emby/system/info/public";',
    "固定节点 GET 探测路径",
  );
  output = replaceAllRequired(
    output,
    "hedgeFailoverEnabled:!1,hedgeProbePath:",
    "hedgeFailoverEnabled:!1,hedgeProbePreferGet:!0,hedgeProbePath:",
    "故障转移 GET 优先默认值",
  );
  output = replaceRequired(
    output,
    '"hedgeFailoverEnabled","hedgeProbePath"',
    '"hedgeFailoverEnabled","hedgeProbePreferGet","hedgeProbePath"',
    "故障转移 GET 优先允许字段",
  );
  output = replaceRequired(
    output,
    '"playbackInfoCacheEnabled","videoProgressForwardEnabled","logEnabled"',
    '"playbackInfoCacheEnabled","videoProgressForwardEnabled","hedgeProbePreferGet","logEnabled"',
    "故障转移 GET 优先默认真布尔字段",
  );
  output = replaceRequired(
    output,
    '{key:"hedgeFailoverEnabled",id:"cfg-hedge-failover-enabled",kind:"checkbox",checkboxMode:"strictTrue"},{key:"hedgeProbePath"',
    '{key:"hedgeFailoverEnabled",id:"cfg-hedge-failover-enabled",kind:"checkbox",checkboxMode:"strictTrue"},{key:"hedgeProbePreferGet",id:"cfg-hedge-probe-prefer-get",kind:"checkbox",checkboxMode:"defaultTrue"},{key:"hedgeProbePath"',
    "故障转移 GET 优先表单绑定",
  );
  output = replaceRequired(
    output,
    'hedgeFailoverEnabled:"\\u7ebf\\u8def\\u6545\\u969c\\u8f6c\\u79fb",hedgeProbePath:',
    'hedgeFailoverEnabled:"\\u7ebf\\u8def\\u6545\\u969c\\u8f6c\\u79fb",hedgeProbePreferGet:"\\u6545\\u969c\\u8f6c\\u79fb GET \\u4f18\\u5148",hedgeProbePath:',
    "故障转移 GET 优先字段名",
  );
  output = replaceRequired(
    output,
    "statusMeta(){return this.app.getNodeLatencyMeta(this.activeLine?.latencyMs,this.app.getNodeHealthCount(this.node?.name))}",
    "statusMeta(){return this.app.getNodeProbeMeta(this.activeLine,this.app.getNodeHealthCount(this.node?.name))}",
    "节点卡片 GET 探测状态",
  );
  output = replaceAllRequired(
    output,
    "App.formatLatency(r.latencyMs)",
    "App.formatNodeProbeResult(r)",
    "节点线路 GET 探测状态",
  );
  output = replaceRequired(
    output,
    '_withDirectives(_createElementVNode("select",{"onUpdate:modelValue":r=>App.nodeModalProbePath=r,"aria-label":"HEAD \\u63a2\\u6d4b\\u8def\\u5f84",disabled:App.nodeModalPingAllPending,class:"w-full min-w-0 max-w-full rounded-xl sm:w-auto sm:min-w-[220px] border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 outline-none focus:border-brand-400 disabled:opacity-60"},[_createElementVNode("option",{value:"/emby/system/info/public"},"/emby/system/info/public"),_createElementVNode("option",{value:"/emby/system/ping"},"/emby/system/ping")],40,["onUpdate:modelValue","disabled"]),[[_vModelSelect,App.nodeModalProbePath]]),',
    "",
    "移除节点 GET 探测路径下拉框",
  );
  output = replaceRequired(
    output,
    '_createElementVNode("span",null,"\\u5f00\\u542f\\u7ebf\\u8def\\u6545\\u969c\\u8f6c\\u79fb\\u3002")]),_createElementVNode("div",{class:"grid gap-3 lg:grid-cols-2"}',
    '_createElementVNode("span",null,"\\u5f00\\u542f\\u7ebf\\u8def\\u6545\\u969c\\u8f6c\\u79fb\\u3002")]),_createElementVNode("label",{class:"flex items-start gap-3 text-sm font-medium cursor-pointer text-slate-900 dark:text-white"},[_withDirectives(_createElementVNode("input",{type:"checkbox",id:"cfg-hedge-probe-prefer-get","onUpdate:modelValue":r=>App.settingsForm.hedgeProbePreferGet=r,class:"mt-0.5 w-4 h-4 rounded"},null,8,["onUpdate:modelValue"]),[[_vModelCheckbox,App.settingsForm.hedgeProbePreferGet]]),_createElementVNode("span",null,"\\u4f18\\u5148\\u4f7f\\u7528 GET \\u8bf7\\u6c42\\u65b9\\u5f0f")]),_createElementVNode("div",{class:"grid gap-3 lg:grid-cols-2"}',
    "故障转移 GET 优先复选框",
  );
  return output;
}

function composeAdminRuntimeEnhancements(outputHtml = "") {
  // 模板只保留 2 处 syncReleaseSourcePreviewInSettingsForm 调用，方法体由这里补齐。
  const output = replaceRequired(
    applyHeadProbeContract(outputHtml),
    "},syncSettingsFormFromRuntimeConfig",
    "},syncReleaseSourcePreviewInSettingsForm(){const r=this.settingsForm&&typeof this.settingsForm==='object'?this.settingsForm:{};const o=String(r.githubRepo||r.releaseRepo||r.repo||'').trim();if(o&&r.githubRepo!==o)r.githubRepo=o;return o},syncSettingsFormFromRuntimeConfig",
    "发布源预览设置方法",
  );
  if (!output.includes("</head>")) {
    throw new Error("frontend/index.html 缺少 </head>，无法组合 runtime enhancements");
  }
  if (output.includes('data-admin-runtime-enhancements="1"')) {
    throw new Error("admin runtime template 不得内嵌重复的 runtime enhancements");
  }

  const composed = output.replace(
    "</head>",
    `${ADMIN_RUNTIME_ENHANCEMENT_STYLE}${ADMIN_RUNTIME_ENHANCEMENT_SCRIPT}</head>`,
  );
  const enhancementMarkerCount =
    composed.match(/data-admin-runtime-enhancements="1"/g)?.length || 0;
  if (enhancementMarkerCount !== 2) {
    throw new Error(`frontend/index.html runtime enhancements 数量异常：${enhancementMarkerCount}`);
  }
  if (!composed.includes("syncReleaseSourcePreviewInSettingsForm(){")) {
    throw new Error("frontend/index.html 缺少发布源预览设置方法定义");
  }
  // 并发编辑保护由模板自带；它若随模板重新编译消失，保存会静默退化为后写覆盖。
  if (!composed.includes("expectedConfigRevision:")) {
    throw new Error("frontend/index.html 缺少设置保存并发保护（expectedConfigRevision）");
  }
  return composed;
}

async function readText(filePath) {
  return readFile(filePath, "utf8");
}

async function main() {
  const sourceHtml = await readText(sourceHtmlPath);
  const nextIndexHtml = await materializeFrontendIndex(sourceHtml);
  const metadata = {
    source: "frontend/admin-runtime.template.html",
    enhancements: "frontend/scripts/admin-runtime-enhancements.mjs",
    target: "frontend/index.html",
    sourceSha256: sha256(sourceHtml),
    enhancementsSha256: sha256(
      `${ADMIN_RUNTIME_ENHANCEMENT_STYLE}${ADMIN_RUNTIME_ENHANCEMENT_SCRIPT}`,
    ),
    targetSha256: sha256(nextIndexHtml),
    generatedAt: new Date().toISOString(),
  };

  if (process.argv.includes("--check")) {
    const currentHtml = await readText(targetHtmlPath).catch(() => "");
    if (currentHtml !== nextIndexHtml) {
      console.error(
        "[sync:admin-runtime] frontend/index.html 与模板及 runtime enhancements 不同步。",
      );
      process.exit(1);
    }
    console.log(
      `[sync:admin-runtime] 已确认 frontend/index.html 同步完成 (${metadata.targetSha256})`,
    );
    return;
  }

  await writeFile(targetHtmlPath, nextIndexHtml, "utf8");
  await writeFile(targetMetaPath, `${JSON.stringify(metadata, null, 2)}\n`, "utf8");
  console.log(
    `[sync:admin-runtime] 已组合 frontend/index.html <- admin runtime template + enhancements (${metadata.targetSha256})`,
  );
}

await main();
