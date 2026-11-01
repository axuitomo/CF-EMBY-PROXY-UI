#!/usr/bin/env node
// 管理端 vendor 摇树构建。
//
// 线上壳（frontend/dist/index.html）里 3 个绝对 URL 是"生产 pin"：Worker 在投递时把它们
// 改写成 /ADMIN_PATH/__release/<rev>/vendor/<assetKey>，再由 Worker 同源代理。这个脚本负责
// 把代理的**内容**换成本地摇树后的产物，文件名就是 Worker 计算的 assetKey，因此不需要改
// 模板、不需要改 pins 测试，也不需要浏览器再碰 CDN。
//
// 第 4 个样式依赖（Tailwind）不再走这条链路：它在构建期被编译成静态 CSS 内联进壳，
// 浏览器侧没有可下载的编译器产物了，见 frontend/scripts/build-admin-tailwind.mjs。
//
// 摇树结论（详见 docs/tech-stack.md §1.1）：
//   lucide  397 KB → ~12 KB   只保留壳里真实用到的图标（含别名）
//   chart.js 206 KB → ~169 KB 只注册 line 图用到的 controller/element/scale/plugin
//   vue     105 KB → 105 KB   runtime-only global build，无树可摇（只做同源搬运）
//
// 用法：
//   node frontend/scripts/build-admin-vendor.mjs            # 构建（缺缓存时联网）
//   node frontend/scripts/build-admin-vendor.mjs --offline  # 只允许用本地缓存
//   node frontend/scripts/build-admin-vendor.mjs --check    # 只校验落盘产物，不联网
//   node frontend/scripts/build-admin-vendor.mjs --force    # 忽略缓存重新下载
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";

import { build as esbuild } from "esbuild";

import { hashStableText } from "../../worker/core/hashing.js";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const frontendDirectory = path.resolve(scriptDirectory, "..");
const repositoryRoot = path.resolve(frontendDirectory, "..");
const cacheDirectory = path.join(repositoryRoot, ".cache", "admin-vendor");
const outputDirectory = path.join(frontendDirectory, "vendor");
const manifestPath = path.join(outputDirectory, "manifest.json");
const lockPath = path.join(frontendDirectory, "vendor.lock.json");

const REGISTRY_ORIGIN = "https://registry.npmjs.org";

// 与 tests/tech-stack-pins.test.mjs 里的 3 个 pin 一一对应；upstreamUrl 必须逐字一致，
// 因为 Worker 的 assetKey 是对这个 URL 做 hashStableText 得到的。
export const ADMIN_VENDOR_PINS = Object.freeze([
  {
    key: "vue",
    packageName: "vue",
    version: "3.5.32",
    upstreamUrl: "https://cdn.jsdelivr.net/npm/vue@3.5.32/dist/vue.runtime.global.prod.js",
    distPath: "dist/vue.runtime.global.prod.js",
    strategy: "copy",
    note: "runtime-only global prod build，已是最小可用的全局 API，再摇会打掉模板 render 函数依赖的 helper",
  },
  {
    key: "chart",
    packageName: "chart.js",
    version: "4.4.7",
    upstreamUrl: "https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js",
    distPath: "dist/chart.js",
    upstreamDistPath: "dist/chart.umd.js",
    strategy: "chart-subset",
    note: "只注册仪表盘折线图用到的 controller/element/scale/plugin",
  },
  {
    key: "lucide",
    packageName: "lucide",
    version: "1.8.0",
    upstreamUrl: "https://cdn.jsdelivr.net/npm/lucide@1.8.0/dist/umd/lucide.min.js",
    distPath: "dist/umd/lucide.min.js",
    strategy: "lucide-subset",
    note: "只保留壳里出现过的图标名（含 lucide 的废弃别名）",
  },
]);

// 折线图实际用到的 Chart.js 部件。改这里之前先看仪表盘 buildTrafficChartConfig：
// type:"line" + fill:true + monotone 插值 + linear/category 双轴 + legend/tooltip。
const CHART_REGISTRATIONS = Object.freeze([
  "LineController",
  "LineElement",
  "PointElement",
  "LinearScale",
  "CategoryScale",
  "Filler",
  "Tooltip",
  "Legend",
]);

const SHELL_SCAN_SOURCES = Object.freeze([
  "frontend/admin-runtime.template.html",
  "frontend/scripts/admin-runtime-enhancements.mjs",
  "frontend/index.html",
]);

const ICON_LITERAL_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function parseFlags(argv = []) {
  return {
    check: argv.includes("--check"),
    offline: argv.includes("--offline"),
    force: argv.includes("--force"),
  };
}

function toPascalIconName(kebabName = "") {
  return String(kebabName || "").replace(/(^|-)([a-z0-9])/g, (_match, _dash, character) =>
    character.toUpperCase(),
  );
}

export function buildAdminVendorAssetKey(upstreamUrl = "", assetKind = "script") {
  const normalizedKind = String(assetKind || "script").toLowerCase() === "css" ? "css" : "js";
  const normalizedUrl = String(upstreamUrl || "").trim();
  if (!normalizedUrl) return "";
  return `${hashStableText(normalizedUrl)}.${normalizedKind}`;
}

async function readOptionalFile(filePath) {
  try {
    return await fs.readFile(filePath, "utf8");
  } catch {
    return "";
  }
}

async function readJsonFile(filePath) {
  const text = await readOptionalFile(filePath);
  if (!text.trim()) return null;
  return JSON.parse(text);
}

async function writeJsonFile(filePath, value) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

// lucide 的 dist/esm/iconsAndAliases.js 把"别名 → 图标文件"写成一串具名再导出，
// 直接解析比 import 1695 个模块快得多，也不会在 Windows 上被路径大小写坑到。
function parseLucideIconIndex(aliasSource = "") {
  const nameToFile = new Map();
  const pattern = /export \{([^}]+)\} from '\.\/icons\/([^']+)\.js'/g;
  for (const match of String(aliasSource || "").matchAll(pattern)) {
    const file = String(match[2] || "").trim();
    if (!file) continue;
    for (const nameMatch of match[1].matchAll(/default as ([A-Za-z0-9_$]+)/g)) {
      const name = String(nameMatch[1] || "").trim();
      if (name) nameToFile.set(name, file);
    }
  }
  return nameToFile;
}

async function collectShellIconCandidates() {
  const literals = new Set();
  // 显式写出来的图标名（data-lucide="x" / icon: "x"）：这些必须 100% 命中，
  // 而且不依赖 .cache 里的 lucide 包就能校验，所以 --check 在干净克隆上也有意义。
  const explicitIconNames = new Set();
  const scannedSources = [];
  for (const relativePath of SHELL_SCAN_SOURCES) {
    const source = await readOptionalFile(path.join(repositoryRoot, relativePath));
    if (!source) continue;
    scannedSources.push(relativePath);
    for (const match of source.matchAll(/"([a-z0-9][a-z0-9-]{0,40})"/g)) literals.add(match[1]);
    for (const match of source.matchAll(/'([a-z0-9][a-z0-9-]{0,40})'/g)) literals.add(match[1]);
    // data-lucide 的三种写法：属性字面量、render 函数里的 "data-lucide":"x"、模板字符串拼接
    for (const match of source.matchAll(/data-lucide\\?"\s*:\s*\\?"([a-z0-9-]+)/g)) {
      literals.add(match[1]);
      explicitIconNames.add(match[1]);
    }
    for (const match of source.matchAll(/data-lucide(?:=\\?")+\s*([a-z0-9-]+)/g)) {
      literals.add(match[1]);
      explicitIconNames.add(match[1]);
    }
    for (const match of source.matchAll(/\bicon:\s*\\?["']([a-z0-9-]+)/g)) {
      literals.add(match[1]);
      explicitIconNames.add(match[1]);
    }
  }
  return { literals, explicitIconNames, scannedSources };
}

function resolveLucideSubset(literals = new Set(), nameToFile = new Map()) {
  const fileToNames = new Map();
  for (const candidate of literals) {
    if (!ICON_LITERAL_PATTERN.test(candidate)) continue;
    const pascalName = toPascalIconName(candidate);
    const file = nameToFile.get(pascalName);
    if (!file) continue;
    if (!fileToNames.has(file)) fileToNames.set(file, new Set());
    fileToNames.get(file).add(candidate);
  }
  return { fileToNames };
}

function buildLucideEntrySource({ lucideDistDirectory, fileToNames }) {
  const importLines = [];
  const mapLines = [];
  const includedNames = [];
  let index = 0;
  for (const [file, names] of [...fileToNames.entries()].sort(([left], [right]) =>
    left.localeCompare(right),
  )) {
    const identifier = `Icon${index++}`;
    importLines.push(
      `import ${identifier} from ${JSON.stringify(path.join(lucideDistDirectory, "icons", `${file}.js`))};`,
    );
    for (const name of [...names].sort()) {
      mapLines.push(`  ${JSON.stringify(name)}: ${identifier},`);
      includedNames.push(name);
    }
  }
  // createIcons 的语义与 lucide 1.8.0 dist/esm/lucide.js 的实现保持一致（同名同参数同行为），
  // 只把 icons 换成摇树后的子集，并允许调用方显式传 icons 覆盖。
  return {
    includedNames,
    source: `import replaceElement from ${JSON.stringify(path.join(lucideDistDirectory, "replaceElement.js"))};
import { toPascalCase } from ${JSON.stringify(path.join(lucideDistDirectory, "shared", "src", "utils", "toPascalCase.js"))};
${importLines.join("\n")}
const subsetIcons = {
${mapLines.join("\n")}
};
const icons = {};
for (const [iconName, iconNode] of Object.entries(subsetIcons)) icons[toPascalCase(iconName)] = iconNode;
const createIcons = ({ icons: providedIcons = {}, nameAttr = "data-lucide", attrs = {}, root = document, inTemplates } = {}) => {
  const activeIcons = providedIcons && Object.keys(providedIcons).length ? providedIcons : icons;
  if (!Object.values(activeIcons).length) throw new Error("lucide: no icons bundled in this build");
  if (typeof root === "undefined") throw new Error("\`createIcons()\` only works in a browser environment.");
  const elementsToReplace = Array.from(root.querySelectorAll(\`[\${nameAttr}]\`));
  elementsToReplace.forEach((element) => replaceElement(element, { nameAttr, icons: activeIcons, attrs }));
  if (inTemplates) {
    const templates = Array.from(root.querySelectorAll("template"));
    templates.forEach((template) => createIcons({ icons: activeIcons, nameAttr, attrs, root: template.content, inTemplates }));
  }
  if (nameAttr === "data-lucide") {
    const deprecatedElements = root.querySelectorAll("[icon-name]");
    if (deprecatedElements.length > 0) {
      console.warn("[Lucide] Some icons were found with the now deprecated icon-name attribute.");
      Array.from(deprecatedElements).forEach((element) => replaceElement(element, { nameAttr: "icon-name", icons: activeIcons, attrs }));
    }
  }
};
export { createIcons, icons };
`,
  };
}

function buildChartEntrySource(chartEntryPath) {
  const names = CHART_REGISTRATIONS.join(", ");
  return `import { Chart, ${names} } from ${JSON.stringify(chartEntryPath)};
Chart.register(${names});
globalThis.Chart = Chart;
`;
}

async function runEsbuild({ entrySource, entryFileName, outfile, globalName }) {
  const entryPath = path.join(cacheDirectory, "build", entryFileName);
  await fs.mkdir(path.dirname(entryPath), { recursive: true });
  await fs.writeFile(entryPath, entrySource, "utf8");
  await esbuild({
    entryPoints: [entryPath],
    outfile,
    bundle: true,
    minify: true,
    format: "iife",
    globalName,
    target: ["es2020"],
    legalComments: "none",
    charset: "utf8",
    // chart.js 的 dist/chart.js 里有一条 `import '@kurkle/color'`（纯副作用导入），
    // @kurkle/color 的 package.json 标了 sideEffects:false，esbuild 会丢掉它并打一条
    // ignored-bare-import 警告。这条警告是预期的：真正的颜色解析走 chunks/helpers.segment.js
    // 里的 `import { Color } from '@kurkle/color'`，具名导入会被保留（见 verifyArtifacts
    // 里对 @kurkle/color 代码存在的断言）。这里不能开 ignoreAnnotations，否则 chart.js
    // 自己的 sideEffects 标记也会失效，整包 403 KB 全被搬进来（实测 201 KB vs 169 KB）。
    logOverride: { "ignored-bare-import": "silent" },
    logLevel: "warning",
  });
  return fs.readFile(outfile);
}

async function sha512Base64(fileBuffer) {
  return createHash("sha512").update(fileBuffer).digest("base64");
}

async function downloadToBuffer(url) {
  const response = await fetch(url, { headers: { Accept: "application/octet-stream" } });
  if (!response.ok) throw new Error(`下载失败（HTTP ${response.status}）：${url}`);
  return Buffer.from(await response.arrayBuffer());
}

async function ensurePinnedTarball(pin, { lock, offline, force }) {
  const tarballName = `${pin.packageName.replace(/[@/]/g, "-")}-${pin.version}.tgz`;
  const tarballPath = path.join(cacheDirectory, "tarballs", tarballName);
  const recorded = lock?.packages?.[`${pin.packageName}@${pin.version}`] || null;
  const cached = await fs.readFile(tarballPath).catch(() => null);
  if (cached && !force) {
    if (!recorded?.integrity)
      return { tarballPath, integrity: `sha512-${await sha512Base64(cached)}` };
    const cachedIntegrity = `sha512-${await sha512Base64(cached)}`;
    if (cachedIntegrity === recorded.integrity) return { tarballPath, integrity: cachedIntegrity };
    if (offline)
      throw new Error(
        `缓存校验失败且处于 --offline：${tarballName}（期望 ${recorded.integrity}，实际 ${cachedIntegrity}）`,
      );
  }
  if (offline) throw new Error(`缺少缓存且处于 --offline：${tarballName}`);
  const registryUrl = `${REGISTRY_ORIGIN}/${pin.packageName.replace("/", "%2F")}`;
  const metadata = await fetch(registryUrl).then((response) => {
    if (!response.ok)
      throw new Error(`读取 npm 元数据失败（HTTP ${response.status}）：${pin.packageName}`);
    return response.json();
  });
  const versionMetadata = metadata?.versions?.[pin.version];
  if (!versionMetadata?.dist?.tarball)
    throw new Error(`npm 元数据里没有 ${pin.packageName}@${pin.version} 的 tarball`);
  const buffer = await downloadToBuffer(versionMetadata.dist.tarball);
  const integrity = `sha512-${await sha512Base64(buffer)}`;
  if (recorded?.integrity && recorded.integrity !== integrity)
    throw new Error(
      `上游 tarball 与 vendor.lock.json 不一致：${pin.packageName}@${pin.version}（锁 ${recorded.integrity}，实际 ${integrity}）`,
    );
  await fs.mkdir(path.dirname(tarballPath), { recursive: true });
  await fs.writeFile(tarballPath, buffer);
  return { tarballPath, integrity };
}

// 自带的 tar 解包：Windows 上 bsdtar 会把 `C:\...` 当成远端主机（"Cannot connect to C:"），
// 而这里只需要 ustar + pax 长路径两种记录，自己解 50 行比依赖平台 tar 行为更稳。
function readTarString(block, offset, length) {
  const slice = block.subarray(offset, offset + length);
  const end = slice.indexOf(0);
  return slice
    .subarray(0, end < 0 ? slice.length : end)
    .toString("utf8")
    .trim();
}

function parsePaxRecords(buffer) {
  const records = {};
  let cursor = 0;
  while (cursor < buffer.length) {
    const spaceIndex = buffer.indexOf(0x20, cursor);
    if (spaceIndex < 0) break;
    const length = Number.parseInt(buffer.subarray(cursor, spaceIndex).toString("utf8"), 10);
    if (!Number.isFinite(length) || length <= 0) break;
    const record = buffer.subarray(spaceIndex + 1, cursor + length - 1).toString("utf8");
    const separator = record.indexOf("=");
    if (separator > 0) records[record.slice(0, separator)] = record.slice(separator + 1);
    cursor += length;
  }
  return records;
}

async function extractTarGz(tarballPath, destinationDirectory) {
  const archive = await fs.readFile(tarballPath);
  const buffer = gunzipSync(archive);
  let cursor = 0;
  let pendingPax = {};
  while (cursor + 512 <= buffer.length) {
    const header = buffer.subarray(cursor, cursor + 512);
    cursor += 512;
    if (header.every((byte) => byte === 0)) break;
    const size = Number.parseInt(readTarString(header, 124, 12), 8) || 0;
    const typeFlag = String.fromCharCode(header[156] || 0);
    const dataStart = cursor;
    cursor += Math.ceil(size / 512) * 512;
    const data = buffer.subarray(dataStart, dataStart + size);
    if (typeFlag === "x" || typeFlag === "g") {
      pendingPax = { ...pendingPax, ...parsePaxRecords(data) };
      continue;
    }
    const prefix = readTarString(header, 345, 155);
    const rawName = pendingPax.path || readTarString(header, 0, 100);
    const entryName = prefix && !pendingPax.path ? `${prefix}/${rawName}` : rawName;
    pendingPax = {};
    if (!entryName || entryName.includes("..")) continue;
    const targetPath = path.join(destinationDirectory, entryName);
    if (typeFlag === "5" || entryName.endsWith("/")) {
      await fs.mkdir(targetPath, { recursive: true });
      continue;
    }
    if (typeFlag !== "0" && typeFlag !== "\0" && typeFlag !== "7") continue;
    await fs.mkdir(path.dirname(targetPath), { recursive: true });
    await fs.writeFile(targetPath, data);
  }
}

async function extractTarball(pin, tarballPath, { force }) {
  const extractDirectory = path.join(
    cacheDirectory,
    `${pin.packageName.replace(/[@/]/g, "-")}-${pin.version}`,
  );
  const packageDirectory = path.join(extractDirectory, "package");
  const markerPath = path.join(extractDirectory, ".extracted");
  const marker = await readOptionalFile(markerPath);
  if (marker.trim() === pin.version && !force) return packageDirectory;
  await fs.rm(extractDirectory, { recursive: true, force: true });
  await fs.mkdir(extractDirectory, { recursive: true });
  await extractTarGz(tarballPath, extractDirectory);
  await fs.writeFile(markerPath, `${pin.version}\n`, "utf8");
  return packageDirectory;
}

function gzipBytes(buffer) {
  return gzipSync(buffer, { level: 9 }).length;
}

async function buildVendorArtifacts({ offline, force }) {
  const previousLock = await readJsonFile(lockPath);
  const lock = previousLock?.packages ? previousLock : { version: 1, packages: {} };
  const { literals, scannedSources } = await collectShellIconCandidates();
  const results = [];
  // 只记录当前 pins 的完整记录：pin 被删掉时，锁文件里的旧记录要跟着消失，
  // 否则 vendor.lock.json 会长期留着一个线上早就不加载的包。
  const nextPackages = {};

  for (const pin of ADMIN_VENDOR_PINS) {
    const assetKey = buildAdminVendorAssetKey(pin.upstreamUrl, "script");
    const { tarballPath, integrity } = await ensurePinnedTarball(pin, { lock, offline, force });
    nextPackages[`${pin.packageName}@${pin.version}`] = {
      integrity,
      tarball: path.relative(repositoryRoot, tarballPath).replace(/\\/g, "/"),
    };
    const packageDirectory = await extractTarball(pin, tarballPath, { force });
    const upstreamBytes = (
      await fs.stat(path.join(packageDirectory, pin.upstreamDistPath || pin.distPath))
    ).size;
    const outfile = path.join(outputDirectory, assetKey);
    await fs.mkdir(outputDirectory, { recursive: true });

    let buffer = null;
    let iconNames = null;
    if (pin.strategy === "copy") {
      buffer = await fs.readFile(path.join(packageDirectory, pin.distPath));
      await fs.writeFile(outfile, buffer);
    } else if (pin.strategy === "lucide-subset") {
      const aliasSource = await fs.readFile(
        path.join(packageDirectory, "dist", "esm", "iconsAndAliases.js"),
        "utf8",
      );
      const nameToFile = parseLucideIconIndex(aliasSource);
      const { fileToNames } = resolveLucideSubset(literals, nameToFile);
      if (fileToNames.size === 0)
        throw new Error("[build-admin-vendor] 没有从壳里识别出任何 lucide 图标，拒绝生成空子集");
      const entry = buildLucideEntrySource({
        lucideDistDirectory: path.join(packageDirectory, "dist", "esm"),
        fileToNames,
      });
      iconNames = entry.includedNames.sort();
      buffer = await runEsbuild({
        entrySource: entry.source,
        entryFileName: "lucide-entry.js",
        outfile,
        globalName: "lucide",
      });
    } else if (pin.strategy === "chart-subset") {
      buffer = await runEsbuild({
        entrySource: buildChartEntrySource(path.join(packageDirectory, "dist", "chart.js")),
        entryFileName: "chart-entry.js",
        outfile,
        globalName: "ChartBundle",
      });
    } else throw new Error(`[build-admin-vendor] 未知策略：${pin.strategy}`);

    results.push({
      key: pin.key,
      packageName: pin.packageName,
      version: pin.version,
      upstreamUrl: pin.upstreamUrl,
      assetKey,
      strategy: pin.strategy,
      treeShaken: pin.strategy !== "copy",
      note: pin.note,
      upstreamBytes,
      bytes: buffer.length,
      gzipBytes: gzipBytes(buffer),
      upstreamGzipBytes: await readUpstreamGzipBytes(packageDirectory, pin),
      ...(iconNames ? { iconNames, iconCount: iconNames.length } : {}),
    });
    console.log(
      `[build-admin-vendor] ${pin.key.padEnd(8)} ${String(upstreamBytes).padStart(7)} B → ${String(
        buffer.length,
      ).padStart(7)} B  (${assetKey})`,
    );
  }

  const manifest = {
    version: 1,
    generatedBy: "frontend/scripts/build-admin-vendor.mjs",
    shellScanSources: scannedSources,
    chartRegistrations: [...CHART_REGISTRATIONS],
    assets: results,
  };
  await writeJsonFile(manifestPath, manifest);
  await writeJsonFile(lockPath, { version: 1, packages: nextPackages });
  return { manifest };
}

async function readUpstreamGzipBytes(packageDirectory, pin) {
  try {
    const buffer = await fs.readFile(
      path.join(packageDirectory, pin.upstreamDistPath || pin.distPath),
    );
    return gzipBytes(buffer);
  } catch {
    return 0;
  }
}

async function verifyArtifacts() {
  const manifest = await readJsonFile(manifestPath);
  if (!manifest)
    throw new Error(
      `[build-admin-vendor] 缺少 ${path.relative(repositoryRoot, manifestPath)}，请先运行构建`,
    );
  const problems = [];
  const expectedKeys = new Set();
  for (const pin of ADMIN_VENDOR_PINS) {
    const assetKey = buildAdminVendorAssetKey(pin.upstreamUrl, "script");
    expectedKeys.add(assetKey);
    const asset = (manifest.assets || []).find((item) => item.key === pin.key);
    if (!asset) {
      problems.push(`manifest 缺少 ${pin.key}`);
      continue;
    }
    if (asset.assetKey !== assetKey)
      problems.push(
        `${pin.key} 的 assetKey 与 Worker 计算值不一致：${asset.assetKey} ≠ ${assetKey}`,
      );
    if (asset.upstreamUrl !== pin.upstreamUrl)
      problems.push(`${pin.key} 的 upstreamUrl 与 pin 不一致：${asset.upstreamUrl}`);
    const buffer = await fs.readFile(path.join(outputDirectory, assetKey)).catch(() => null);
    if (!buffer) {
      problems.push(`缺少产物 ${assetKey}（${pin.key}）`);
      continue;
    }
    if (buffer.length !== asset.bytes)
      problems.push(`${pin.key} 产物大小与 manifest 不一致：${buffer.length} ≠ ${asset.bytes}`);
    if (asset.treeShaken && buffer.length >= asset.upstreamBytes)
      problems.push(`${pin.key} 摇树后反而变大：${buffer.length} ≥ ${asset.upstreamBytes}`);
  }

  // chart.js 的 UMD 构建内置 @kurkle/color（CSS 具名色表 + hwb/hsv 解析）。摇树后的产物
  // 如果把它丢了，折线图会画不出颜色（borderColor 全退化成透明），而这类问题在没有浏览器
  // 的环境里不会报错。这里用 @kurkle/color 独有的具名色表做哨兵。
  const chartAsset = (manifest.assets || []).find((item) => item.key === "chart");
  if (chartAsset) {
    const chartBuffer = (
      await fs.readFile(path.join(outputDirectory, chartAsset.assetKey))
    ).toString("utf8");
    if (!chartBuffer.includes("d3d3d3") || !chartBuffer.includes("hwb"))
      problems.push("chart 子集里没有 @kurkle/color 的颜色表，颜色解析会被摇掉");
  }

  const { literals, explicitIconNames } = await collectShellIconCandidates();
  const lucideAsset = (manifest.assets || []).find((item) => item.key === "lucide");
  if (!lucideAsset?.iconNames?.length) problems.push("manifest 缺少 lucide 图标清单");
  else {
    const bundled = new Set(lucideAsset.iconNames);
    // 显式图标名不依赖 .cache 里的 lucide 包，所以这条校验在干净克隆上同样有效。
    for (const name of [...explicitIconNames].sort())
      if (!bundled.has(name)) problems.push(`lucide 子集缺少壳里显式引用的图标：${name}`);
    const aliasSource = await readOptionalFile(
      path.join(cacheDirectory, "lucide-1.8.0", "package", "dist", "esm", "iconsAndAliases.js"),
    );
    const nameToFile = parseLucideIconIndex(aliasSource);
    const missing = [...literals]
      .filter((candidate) => ICON_LITERAL_PATTERN.test(candidate))
      .filter((candidate) => nameToFile.has(toPascalIconName(candidate)))
      .filter((candidate) => !bundled.has(candidate));
    for (const name of missing.sort()) problems.push(`lucide 子集缺少壳里用到的图标：${name}`);
  }

  const staleFiles = (await fs.readdir(outputDirectory).catch(() => [])).filter(
    (name) => name.endsWith(".js") && !expectedKeys.has(name),
  );
  for (const name of staleFiles) problems.push(`vendor/ 里有与当前 pins 无关的残留产物：${name}`);

  if (problems.length > 0) {
    for (const problem of problems) console.error(`[build-admin-vendor] ✗ ${problem}`);
    throw new Error(`[build-admin-vendor] 校验失败（${problems.length} 项）`);
  }
  console.log(
    `[build-admin-vendor] ✓ 产物与 manifest 一致：${[...expectedKeys].join(", ")}（lucide 子集 ${lucideAsset.iconCount} 个图标）`,
  );
  return manifest;
}

function printSummary(manifest) {
  const totalUpstream = manifest.assets.reduce((sum, asset) => sum + asset.upstreamBytes, 0);
  const totalBytes = manifest.assets.reduce((sum, asset) => sum + asset.bytes, 0);
  const totalGzip = manifest.assets.reduce((sum, asset) => sum + asset.gzipBytes, 0);
  const totalUpstreamGzip = manifest.assets.reduce(
    (sum, asset) => sum + asset.upstreamGzipBytes,
    0,
  );
  const saved = totalUpstream - totalBytes;
  const savedGzip = totalUpstreamGzip - totalGzip;
  console.log(
    `[build-admin-vendor] 首屏 vendor 总计 ${totalUpstream} B → ${totalBytes} B（省 ${saved} B / ${(
      (saved / Math.max(1, totalUpstream)) *
      100
    ).toFixed(1)}%）；gzip ${totalUpstreamGzip} B → ${totalGzip} B（省 ${savedGzip} B）`,
  );
  console.log(
    `[build-admin-vendor] 产物目录 ${path.relative(repositoryRoot, outputDirectory)}（文件名 = Worker 的 vendor assetKey）`,
  );
}

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  if (flags.check) {
    await verifyArtifacts();
    return;
  }
  const { manifest } = await buildVendorArtifacts(flags);
  await verifyArtifacts();
  printSummary(manifest);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
