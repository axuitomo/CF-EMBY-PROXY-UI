import { copyFile, cp, mkdir, readdir, rm } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendDirectory = path.resolve(__dirname, "..");
const sourcePath = path.join(frontendDirectory, "index.html");
const vendorSourceDirectory = path.join(frontendDirectory, "vendor");
const outFlagIndex = process.argv.indexOf("--out");
const outDirectory =
  outFlagIndex > 0 && process.argv[outFlagIndex + 1]
    ? path.resolve(process.argv[outFlagIndex + 1])
    : path.join(frontendDirectory, "dist");

// 管理端仍是单文件交付：dist 里只有 index.html + vendor/（Worker 同源代理用的摇树产物）。
// 模板没有 module script，走打包器只会原样搬运，所以这里直接覆盖输出目录，并清掉历史残留。
if (
  outDirectory === frontendDirectory ||
  frontendDirectory.startsWith(`${outDirectory}${path.sep}`)
) {
  throw new Error(`[publish-dist] 拒绝写入 ${outDirectory}：会覆盖管理端源码目录`);
}

// 只清空目录内容、不删目录本身：Windows 上别的进程（wrangler dev 的 assets 监听）会把
// dist 目录句柄占住，rmdir 直接 EBUSY，而逐项清理没有这个问题。
await mkdir(outDirectory, { recursive: true });
for (const entry of await readdir(outDirectory))
  await rm(path.join(outDirectory, entry), { recursive: true, force: true });
await copyFile(sourcePath, path.join(outDirectory, "index.html"));
console.log(
  `[publish-dist] ${path.relative(frontendDirectory, outDirectory)}/index.html <- index.html`,
);

// vendor/ 由 build-admin-vendor.mjs 生成（文件名 = Worker 计算的 vendor assetKey）。
// 缺失时直接失败：壳里的 3 个 CDN 脚本会被 Worker 改写到这些文件上，少一个就是白屏。
let vendorFiles = [];
try {
  vendorFiles = (await readdir(vendorSourceDirectory)).filter((name) => name.endsWith(".js"));
} catch {
  vendorFiles = [];
}
if (vendorFiles.length === 0) {
  throw new Error(
    "[publish-dist] 缺少 frontend/vendor/ 产物，请先运行 node frontend/scripts/build-admin-vendor.mjs",
  );
}
await cp(vendorSourceDirectory, path.join(outDirectory, "vendor"), { recursive: true });
console.log(
  `[publish-dist] ${path.relative(frontendDirectory, outDirectory)}/vendor/ <- vendor/（${vendorFiles.length} 个文件）`,
);
