import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

// 与 Worker 的 ADMIN_REMOTE_SHELL_MAX_BYTES 对齐：壳在请求期会被这个上限拒绝。
const MAX_ADMIN_SHELL_BYTES = 2 * 1024 * 1024;

function isMutableJsdelivrGithubAssetUrl(assetUrl = "") {
  let parsedUrl = null;
  try {
    parsedUrl = new URL(String(assetUrl || "").trim(), "https://release.invalid/");
  } catch {
    return false;
  }

  const hostname = parsedUrl.hostname.replace(/\.+$/, "");
  if (!/(^|\.)jsdelivr\.net$/i.test(hostname)) return false;

  if (!/^\/gh\/[^/]+\/[^/]+\//i.test(parsedUrl.pathname)) return false;
  const matchedRef = parsedUrl.pathname.match(/^\/gh\/[^/]+\/[^@/]+@([^/]+)\//i);
  if (!matchedRef) return true;

  const ref = decodeURIComponent(String(matchedRef[1] || "").trim());
  if (!ref) return true;
  if (/^[0-9a-f]{7,40}$/i.test(ref)) return false;
  if (/^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/i.test(ref)) return false;
  return true;
}

function isForbiddenRuntimeAsset(assetUrl = "") {
  const normalized = String(assetUrl || "").trim();
  if (!normalized) return true;
  if (!/^(?:https?:)?\/\//i.test(normalized)) return true;
  let parsedUrl = null;
  try {
    parsedUrl = new URL(normalized, "https://release.invalid/");
  } catch {
    return true;
  }
  const hostname = parsedUrl.hostname.replace(/\.+$/, "").toLowerCase();
  if (hostname === "esm.sh" || hostname.endsWith(".esm.sh")) return true;
  if (hostname === "raw.githubusercontent.com") return true;
  if (
    hostname === "github.com" &&
    /^\/[^/]+\/[^/]+\/releases\/download\//i.test(parsedUrl.pathname)
  )
    return true;
  if (isMutableJsdelivrGithubAssetUrl(normalized)) return true;
  return false;
}

const SKIPPED_CONTENT_TAGS = new Set([
  "script",
  "style",
  "template",
  "textarea",
  "title",
  "noscript",
]);

function isHtmlSpace(character = "") {
  return (
    character === " " ||
    character === "\t" ||
    character === "\n" ||
    character === "\f" ||
    character === "\r"
  );
}

function findHtmlTagEnd(sourceHtml, startIndex) {
  let quote = "";
  for (let index = startIndex; index < sourceHtml.length; index += 1) {
    const character = sourceHtml[index];
    if (quote) {
      if (character === quote) quote = "";
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (character === ">") {
      return index;
    }
  }
  return -1;
}

function parseHtmlOpeningTag(sourceHtml, tagStart) {
  let cursor = tagStart + 1;
  if (!/[A-Za-z]/.test(sourceHtml[cursor] || "")) return null;
  const tagEnd = findHtmlTagEnd(sourceHtml, cursor);
  if (tagEnd < 0) return null;

  const tagNameStart = cursor;
  while (cursor < tagEnd && !isHtmlSpace(sourceHtml[cursor]) && sourceHtml[cursor] !== "/")
    cursor += 1;
  const tagName = sourceHtml.slice(tagNameStart, cursor).toLowerCase();
  const attributes = new Map();
  while (cursor < tagEnd) {
    while (cursor < tagEnd && isHtmlSpace(sourceHtml[cursor])) cursor += 1;
    if (cursor >= tagEnd) break;
    if (sourceHtml[cursor] === "/") {
      cursor += 1;
      continue;
    }
    const nameStart = cursor;
    while (
      cursor < tagEnd &&
      !isHtmlSpace(sourceHtml[cursor]) &&
      sourceHtml[cursor] !== "=" &&
      sourceHtml[cursor] !== "/"
    )
      cursor += 1;
    if (cursor === nameStart) {
      cursor += 1;
      continue;
    }
    const name = sourceHtml.slice(nameStart, cursor).toLowerCase();
    while (cursor < tagEnd && isHtmlSpace(sourceHtml[cursor])) cursor += 1;
    let value = "";
    if (sourceHtml[cursor] === "=") {
      cursor += 1;
      while (cursor < tagEnd && isHtmlSpace(sourceHtml[cursor])) cursor += 1;
      const quote = sourceHtml[cursor];
      if (quote === '"' || quote === "'") {
        cursor += 1;
        const valueStart = cursor;
        while (cursor < tagEnd && sourceHtml[cursor] !== quote) cursor += 1;
        value = sourceHtml.slice(valueStart, cursor);
        if (cursor < tagEnd) cursor += 1;
      } else {
        const valueStart = cursor;
        while (cursor < tagEnd && !isHtmlSpace(sourceHtml[cursor])) cursor += 1;
        value = sourceHtml.slice(valueStart, cursor);
      }
    }
    if (!attributes.has(name)) attributes.set(name, value);
  }
  return { tagName, attributes, tagEnd };
}

function* iterateHtmlOpeningTags(html = "") {
  const sourceHtml = String(html || "");
  const lowerHtml = sourceHtml.toLowerCase();
  let cursor = 0;
  while (cursor < sourceHtml.length) {
    const tagStart = sourceHtml.indexOf("<", cursor);
    if (tagStart < 0) return;
    if (sourceHtml.startsWith("<!--", tagStart)) {
      const commentEnd = sourceHtml.indexOf("-->", tagStart + 4);
      cursor = commentEnd < 0 ? sourceHtml.length : commentEnd + 3;
      continue;
    }
    const openingTag = parseHtmlOpeningTag(sourceHtml, tagStart);
    if (!openingTag) {
      cursor = tagStart + 1;
      continue;
    }
    const contentStart = openingTag.tagEnd + 1;
    cursor = contentStart;
    if (!SKIPPED_CONTENT_TAGS.has(openingTag.tagName)) {
      yield { ...openingTag, content: "" };
      continue;
    }
    const closingStart = lowerHtml.indexOf(`</${openingTag.tagName}`, contentStart);
    if (closingStart < 0) {
      yield { ...openingTag, content: sourceHtml.slice(contentStart) };
      return;
    }
    const closingEnd = findHtmlTagEnd(sourceHtml, closingStart + openingTag.tagName.length + 2);
    if (closingEnd < 0) {
      yield { ...openingTag, content: sourceHtml.slice(contentStart, closingStart) };
      return;
    }
    yield { ...openingTag, content: sourceHtml.slice(contentStart, closingStart) };
    cursor = closingEnd + 1;
  }
}

function collectInlineDynamicImports(scriptBody = "") {
  const source = String(scriptBody || "");
  const imports = [];

  function isIdentifierStart(character = "") {
    return /[A-Za-z_$]/.test(character);
  }

  function isIdentifierPart(character = "") {
    return /[A-Za-z0-9_$]/.test(character);
  }

  function skipQuotedString(startIndex, quote) {
    let cursor = startIndex + 1;
    while (cursor < source.length) {
      if (source[cursor] === "\\") cursor += 2;
      else if (source[cursor] === quote) return cursor + 1;
      else cursor += 1;
    }
    return source.length;
  }

  function skipLineComment(startIndex) {
    const lineEnd = source.indexOf("\n", startIndex + 2);
    return lineEnd < 0 ? source.length : lineEnd + 1;
  }

  function skipBlockComment(startIndex) {
    const commentEnd = source.indexOf("*/", startIndex + 2);
    return commentEnd < 0 ? source.length : commentEnd + 2;
  }

  function skipRegexLiteral(startIndex) {
    let cursor = startIndex + 1;
    let inCharacterClass = false;
    while (cursor < source.length) {
      const character = source[cursor];
      if (character === "\\") cursor += 2;
      else if (character === "[") {
        inCharacterClass = true;
        cursor += 1;
      } else if (character === "]" && inCharacterClass) {
        inCharacterClass = false;
        cursor += 1;
      } else if (character === "/" && !inCharacterClass) {
        cursor += 1;
        while (/[A-Za-z]/.test(source[cursor] || "")) cursor += 1;
        return cursor;
      } else {
        cursor += 1;
      }
    }
    return source.length;
  }

  function skipTrivia(startIndex) {
    let cursor = startIndex;
    while (cursor < source.length) {
      if (/\s/.test(source[cursor])) {
        cursor += 1;
        continue;
      }
      if (source.startsWith("//", cursor)) {
        cursor = skipLineComment(cursor);
        continue;
      }
      if (source.startsWith("/*", cursor)) {
        cursor = skipBlockComment(cursor);
        continue;
      }
      break;
    }
    return cursor;
  }

  function scanTemplateLiteral(startIndex) {
    let cursor = startIndex + 1;
    while (cursor < source.length) {
      if (source[cursor] === "\\") {
        cursor += 2;
      } else if (source[cursor] === "`") {
        return cursor + 1;
      } else if (source[cursor] === "$" && source[cursor + 1] === "{") {
        cursor = scanCode(cursor + 2, "}");
      } else {
        cursor += 1;
      }
    }
    return source.length;
  }

  function scanCode(startIndex = 0, closingCharacter = "") {
    let cursor = startIndex;
    let previousToken = "";
    let canStartRegex = true;
    const regexPrefixKeywords = new Set([
      "await",
      "case",
      "delete",
      "do",
      "else",
      "in",
      "instanceof",
      "new",
      "return",
      "throw",
      "typeof",
      "void",
      "yield",
    ]);

    while (cursor < source.length) {
      const character = source[cursor];
      if (closingCharacter && character === closingCharacter) return cursor + 1;
      if (/\s/.test(character)) {
        cursor += 1;
        continue;
      }
      if (source.startsWith("//", cursor)) {
        cursor = skipLineComment(cursor);
        continue;
      }
      if (source.startsWith("/*", cursor)) {
        cursor = skipBlockComment(cursor);
        continue;
      }
      if (character === '"' || character === "'") {
        cursor = skipQuotedString(cursor, character);
        previousToken = "literal";
        canStartRegex = false;
        continue;
      }
      if (character === "`") {
        cursor = scanTemplateLiteral(cursor);
        previousToken = "literal";
        canStartRegex = false;
        continue;
      }
      if (isIdentifierStart(character)) {
        const identifierStart = cursor;
        cursor += 1;
        while (isIdentifierPart(source[cursor] || "")) cursor += 1;
        const identifier = source.slice(identifierStart, cursor);
        if (identifier === "import" && previousToken !== ".") {
          const callStart = skipTrivia(cursor);
          if (source[callStart] === "(") {
            imports.push({
              index: identifierStart,
              reference: source.slice(identifierStart, callStart + 1),
            });
          }
        }
        previousToken = identifier;
        canStartRegex = regexPrefixKeywords.has(identifier);
        continue;
      }
      if (/[0-9]/.test(character)) {
        cursor += 1;
        while (/[A-Za-z0-9._]/.test(source[cursor] || "")) cursor += 1;
        previousToken = "number";
        canStartRegex = false;
        continue;
      }
      if (character === "/" && canStartRegex) {
        cursor = skipRegexLiteral(cursor);
        previousToken = "literal";
        canStartRegex = false;
        continue;
      }
      if (character === "{") {
        cursor = scanCode(cursor + 1, "}");
        previousToken = "}";
        canStartRegex = false;
        continue;
      }
      previousToken = character;
      cursor += 1;
      canStartRegex = ![")", "]", "}"].includes(character);
    }
    return cursor;
  }

  scanCode();
  return imports;
}

function isExecutableInlineScriptType(rawType = "") {
  const type = String(rawType || "")
    .trim()
    .toLowerCase()
    .split(";")[0];
  return (
    !type ||
    type === "module" ||
    type === "text/javascript" ||
    type === "application/javascript" ||
    type === "text/ecmascript" ||
    type === "application/ecmascript"
  );
}

// frontend/src 是保留的源世代（勿删，见 frontend/src/README.md）：出现 module script 就说明有人把组件化迁移做了一半。
function findAdminModuleScriptTags(html = "") {
  const moduleScripts = [];
  for (const tag of iterateHtmlOpeningTags(html)) {
    if (tag.tagName !== "script") continue;
    const scriptType = String(tag.attributes.get("type") || "")
      .trim()
      .toLowerCase()
      .split(";")[0];
    if (scriptType === "module") moduleScripts.push(tag);
  }
  return moduleScripts;
}

function inspectRuntimeAssets(html = "") {
  const assets = [];
  let importMapCount = 0;
  const inlineDynamicImports = [];
  for (const tag of iterateHtmlOpeningTags(html)) {
    if (tag.tagName === "script") {
      const scriptType = String(tag.attributes.get("type") || "")
        .trim()
        .toLowerCase();
      if (scriptType === "importmap") importMapCount += 1;
      const src = String(tag.attributes.get("src") || "").trim();
      if (src) assets.push(src);
      else if (isExecutableInlineScriptType(scriptType))
        inlineDynamicImports.push(...collectInlineDynamicImports(tag.content));
      continue;
    }
    if (tag.tagName !== "link") continue;
    const href = String(tag.attributes.get("href") || "").trim();
    if (!href) continue;
    const relTokens = new Set(
      String(tag.attributes.get("rel") || "")
        .trim()
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean),
    );
    const preloadKind = String(tag.attributes.get("as") || "")
      .trim()
      .toLowerCase();
    if (relTokens.has("stylesheet") || relTokens.has("modulepreload")) assets.push(href);
    else if (
      (relTokens.has("preload") || relTokens.has("prefetch")) &&
      (preloadKind === "script" || preloadKind === "style")
    )
      assets.push(href);
  }
  return { assets, importMapCount, inlineDynamicImports };
}

// 模板里的 CDN pin（当前 3 个）会被 Worker 改写成 /ADMIN_PATH/__release/<rev>/vendor/<assetKey>，由本
// Worker 同源返回。这些 assetKey 对应的摇树产物必须随 dist 一起发出去，少一个就是白屏。
async function checkAdminVendorStore() {
  const { ADMIN_VENDOR_PINS, buildAdminVendorAssetKey } = await import("./build-admin-vendor.mjs");
  const vendorDirectory = path.resolve(process.cwd(), "dist/vendor");
  const problems = [];
  for (const pin of ADMIN_VENDOR_PINS) {
    const assetKey = buildAdminVendorAssetKey(pin.upstreamUrl, "script");
    let size = 0;
    try {
      size = (await readFile(path.join(vendorDirectory, assetKey))).length;
    } catch {
      size = 0;
    }
    if (size <= 0) problems.push(`${pin.key}: 缺少 dist/vendor/${assetKey}`);
  }
  return problems;
}

async function main() {
  const distHtmlPath = path.resolve(process.cwd(), "dist/index.html");
  const sourceHtmlPath = path.resolve(process.cwd(), "index.html");
  const assetsDir = path.resolve(process.cwd(), "dist/assets");
  const html = await readFile(distHtmlPath, "utf8");
  const sourceHtml = await readFile(sourceHtmlPath, "utf8");

  const shellBytes = Buffer.byteLength(html, "utf8");
  if (shellBytes > MAX_ADMIN_SHELL_BYTES) {
    console.error(
      `[check:release] dist/index.html 为 ${shellBytes} 字节，超过 Worker 壳层上限 ${MAX_ADMIN_SHELL_BYTES} 字节。`,
    );
    process.exit(1);
  }

  let builtAssetFiles = [];
  try {
    builtAssetFiles = await readdir(assetsDir);
  } catch {
    builtAssetFiles = [];
  }

  if (builtAssetFiles.length) {
    console.error(
      "[check:release] 单文件管理台禁止输出 dist/assets 运行时文件，但检测到了以下文件：",
    );
    for (const filename of builtAssetFiles) {
      console.error(`- ${filename}`);
    }
    process.exit(1);
  }

  if (!/\bid=(['"])app\1/i.test(html)) {
    console.error(
      "[check:release] dist/index.html 缺少 #app 根节点，Worker 无法注入远端壳 bootstrap。",
    );
    process.exit(1);
  }

  if (html.includes("__ADMIN_BOOTSTRAP_JSON__") || html.includes("__ADMIN_APP_ROOT__")) {
    console.error(
      "[check:release] dist/index.html 仍残留 admin runtime 占位符，说明同步脚本未正确落盘。",
    );
    process.exit(1);
  }

  const bootstrapMatch = html.match(
    /<script(?=[^>]*\bid="admin-bootstrap")(?=[^>]*\btype="application\/json")[^>]*>([\s\S]*?)<\/script>/i,
  );
  if (!bootstrapMatch) {
    console.error("[check:release] dist/index.html 缺少 admin-bootstrap JSON 脚本。");
    process.exit(1);
  }

  try {
    JSON.parse(bootstrapMatch[1]);
  } catch (error) {
    console.error(
      `[check:release] admin-bootstrap JSON 解析失败：${error?.message || String(error)}`,
    );
    process.exit(1);
  }

  if (!/<script(?=[^>]*\bid="admin-bootstrap-loader")[^>]*>/i.test(html)) {
    console.error("[check:release] dist/index.html 缺少 admin-bootstrap-loader 脚本。");
    process.exit(1);
  }

  if (html !== sourceHtml) {
    console.error(
      "[check:release] dist/index.html 与同步后的 frontend/index.html 不一致，请重新运行 CDN 构建。",
    );
    process.exit(1);
  }

  const runtimeInspection = inspectRuntimeAssets(html);
  if (runtimeInspection.importMapCount > 0) {
    console.error(
      "[check:release] 正式入口禁止 importmap；运行时依赖必须使用可由 Worker 改写的显式 script/link 标签。",
    );
    process.exit(1);
  }
  if (runtimeInspection.inlineDynamicImports.length > 0) {
    console.error(
      "[check:release] 正式入口禁止 inline 动态 import；运行时依赖必须使用可由 Worker 改写的显式 script/link 标签：",
    );
    for (const inlineImport of runtimeInspection.inlineDynamicImports) {
      console.error(`- ${inlineImport.reference}`);
    }
    process.exit(1);
  }

  const assetMatches = runtimeInspection.assets;

  if (!assetMatches.length) {
    console.error("[check:release] dist/index.html 中没有找到待校验的 JS/CSS 资源。");
    process.exit(1);
  }

  const vendorProblems = await checkAdminVendorStore();
  if (vendorProblems.length) {
    console.error("[check:release] 首屏 vendor 摇树产物不完整：");
    for (const problem of vendorProblems) console.error(`- ${problem}`);
    process.exit(1);
  }

  const invalidAssets = assetMatches.filter((url) => isForbiddenRuntimeAsset(url));
  if (invalidAssets.length) {
    console.error("[check:release] 发现不符合外部资源 + Worker 同源代理策略的资源：");
    for (const assetUrl of invalidAssets) {
      console.error(`- ${assetUrl}`);
    }
    process.exit(1);
  }

  console.log(
    `[check:release] 已确认 ${assetMatches.length} 个 JS/CSS 资源为可代理的外部绝对 URL。`,
  );
  console.log(
    `[check:release] dist/index.html 满足单文件管理台 + Worker 同源代理约束（壳 ${shellBytes} B / 上限 ${MAX_ADMIN_SHELL_BYTES} B）。`,
  );
  console.log(
    `[check:release] dist/vendor 下的摇树产物与 ${assetMatches.length} 个 pin 的 assetKey 对齐。`,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}

export {
  MAX_ADMIN_SHELL_BYTES,
  findAdminModuleScriptTags,
  inspectRuntimeAssets,
  isForbiddenRuntimeAsset,
};
