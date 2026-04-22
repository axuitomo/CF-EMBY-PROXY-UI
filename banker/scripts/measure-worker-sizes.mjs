#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { brotliCompressSync, constants as zlibConstants, gzipSync } from "node:zlib";

function formatBytes(value = 0) {
  return `${Number(value || 0).toLocaleString("en-US")} B`;
}

function formatPercent(value = 0) {
  const rounded = Math.abs(value) < 0.005 ? 0 : value;
  return `${rounded >= 0 ? "+" : ""}${rounded.toFixed(2)}%`;
}

function diffPercent(base = 0, next = 0) {
  if (!Number.isFinite(base) || base <= 0 || !Number.isFinite(next)) return 0;
  return ((next - base) / base) * 100;
}

async function readMetrics(filePath) {
  const absolutePath = path.resolve(filePath);
  const buffer = await readFile(absolutePath);
  return {
    filePath: absolutePath,
    raw: buffer.byteLength,
    gzip: gzipSync(buffer, { level: 9 }).byteLength,
    brotli: brotliCompressSync(buffer, {
      params: {
        [zlibConstants.BROTLI_PARAM_QUALITY]: 11
      }
    }).byteLength
  };
}

function printMetric(metric) {
  console.log(`file:   ${metric.filePath}`);
  console.log(`raw:    ${formatBytes(metric.raw)}`);
  console.log(`gzip:   ${formatBytes(metric.gzip)}`);
  console.log(`brotli: ${formatBytes(metric.brotli)}`);
}

function printComparison(baseMetric, nextMetric) {
  printMetric(baseMetric);
  console.log("");
  printMetric(nextMetric);
  console.log("");
  console.log("delta:");
  console.log(`raw:    ${formatBytes(nextMetric.raw - baseMetric.raw)} (${formatPercent(diffPercent(baseMetric.raw, nextMetric.raw))})`);
  console.log(`gzip:   ${formatBytes(nextMetric.gzip - baseMetric.gzip)} (${formatPercent(diffPercent(baseMetric.gzip, nextMetric.gzip))})`);
  console.log(`brotli: ${formatBytes(nextMetric.brotli - baseMetric.brotli)} (${formatPercent(diffPercent(baseMetric.brotli, nextMetric.brotli))})`);
}

async function main() {
  const args = process.argv.slice(2);
  const compareMode = args[0] === "--compare";
  const fileArgs = compareMode ? args.slice(1) : args;
  const files = fileArgs.length ? fileArgs : ["worker.js", "_worker.js"];

  if (compareMode) {
    if (files.length !== 2) {
      throw new Error("measure-worker-sizes --compare expects exactly two file paths");
    }
    const [baseMetric, nextMetric] = await Promise.all(files.map(readMetrics));
    printComparison(baseMetric, nextMetric);
    return;
  }

  const metrics = await Promise.all(files.map(readMetrics));
  for (let index = 0; index < metrics.length; index += 1) {
    if (index > 0) console.log("");
    printMetric(metrics[index]);
  }
}

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exit(1);
});
