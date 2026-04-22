#!/usr/bin/env node

import { copyFile, mkdtemp, rm } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

const DEFAULT_FILES = ["worker.js", "_worker.js"];
const DEFAULT_ROUNDS = 7;
const DEFAULT_ADMIN_PATH = "/admin";

function median(values = []) {
  const sorted = [...values].sort((left, right) => left - right);
  if (!sorted.length) return 0;
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? sorted[middle]
    : (sorted[middle - 1] + sorted[middle]) / 2;
}

function formatMs(value = 0) {
  return `${value.toFixed(2)} ms`;
}

function formatPercent(value = 0) {
  const rounded = Math.abs(value) < 0.005 ? 0 : value;
  return `${rounded >= 0 ? "+" : ""}${rounded.toFixed(2)}%`;
}

function percentDelta(base = 0, next = 0) {
  if (!Number.isFinite(base) || base <= 0 || !Number.isFinite(next)) return 0;
  return ((next - base) / base) * 100;
}

function createExecutionContext() {
  const waitUntilQueue = [];
  return {
    waitUntil(promise) {
      waitUntilQueue.push(Promise.resolve(promise).catch(() => null));
    },
    async drain() {
      while (waitUntilQueue.length) {
        const batch = waitUntilQueue.splice(0, waitUntilQueue.length);
        await Promise.allSettled(batch);
      }
    }
  };
}

function buildBenchmarkEnv() {
  return {
    JWT_SECRET: "benchmark-secret",
    ADMIN_PASS: "benchmark-pass"
  };
}

async function loadWorkerModule(filePath, roundIndex) {
  const absolutePath = path.resolve(filePath);
  const tempDir = await mkdtemp(path.join(tmpdir(), "worker-startup-bench-"));
  const tempModulePath = path.join(tempDir, "worker-under-benchmark.mjs");
  await copyFile(absolutePath, tempModulePath);
  const importStartedAt = performance.now();
  const mod = await import(pathToFileURL(tempModulePath).href + `?round=${roundIndex}-${Date.now()}`);
  const importElapsedMs = performance.now() - importStartedAt;
  return {
    worker: mod.default,
    importElapsedMs,
    async dispose() {
      try { delete globalThis.__EMBY_PROXY_NODE_TEST_HOOKS__; } catch {}
      await rm(tempDir, { recursive: true, force: true });
    }
  };
}

function ensureAdminShellHtml(html = "") {
  const text = String(html || "");
  const bootstrapMatch = text.match(/<script(?=[^>]*\bid="admin-bootstrap")(?=[^>]*\btype="application\/json")[^>]*>([\s\S]*?)<\/script>/i);
  if (!bootstrapMatch) {
    throw new Error("rendered admin html is missing admin-bootstrap json script");
  }
  try {
    JSON.parse(String(bootstrapMatch[1] || ""));
  } catch (error) {
    throw new Error(`rendered admin html has invalid admin-bootstrap json: ${error?.message || error}`);
  }
  if (!text.includes('<div id="app" v-cloak></div>')) {
    throw new Error("rendered admin html is missing admin app root placeholder");
  }
}

async function measureFile(filePath, rounds = DEFAULT_ROUNDS) {
  const importSamples = [];
  const renderSamples = [];
  const htmlSizes = [];

  for (let roundIndex = 0; roundIndex < rounds; roundIndex += 1) {
    const runtime = await loadWorkerModule(filePath, roundIndex);
    const ctx = createExecutionContext();
    try {
      importSamples.push(runtime.importElapsedMs);
      const request = new Request(`https://demo.example.com${DEFAULT_ADMIN_PATH}`);
      const renderStartedAt = performance.now();
      const response = await runtime.worker.fetch(request, buildBenchmarkEnv(), ctx);
      const html = await response.text();
      const renderElapsedMs = performance.now() - renderStartedAt;
      if (response.status !== 200) {
        throw new Error(`expected admin shell to return 200, got ${response.status}`);
      }
      ensureAdminShellHtml(html);
      renderSamples.push(renderElapsedMs);
      htmlSizes.push(Buffer.byteLength(html));
      await ctx.drain();
    } finally {
      await runtime.dispose();
    }
  }

  return {
    filePath: path.resolve(filePath),
    rounds,
    importMedianMs: median(importSamples),
    renderMedianMs: median(renderSamples),
    htmlSizeBytes: median(htmlSizes)
  };
}

function printMetric(metric) {
  console.log(`file:         ${metric.filePath}`);
  console.log(`rounds:       ${metric.rounds}`);
  console.log(`import:       ${formatMs(metric.importMedianMs)}`);
  console.log(`admin render: ${formatMs(metric.renderMedianMs)}`);
  console.log(`html size:    ${metric.htmlSizeBytes.toLocaleString("en-US")} B`);
}

function printComparison(baseMetric, nextMetric) {
  printMetric(baseMetric);
  console.log("");
  printMetric(nextMetric);
  console.log("");
  console.log("delta:");
  console.log(`import:       ${formatMs(nextMetric.importMedianMs - baseMetric.importMedianMs)} (${formatPercent(percentDelta(baseMetric.importMedianMs, nextMetric.importMedianMs))})`);
  console.log(`admin render: ${formatMs(nextMetric.renderMedianMs - baseMetric.renderMedianMs)} (${formatPercent(percentDelta(baseMetric.renderMedianMs, nextMetric.renderMedianMs))})`);
  console.log(`html size:    ${(nextMetric.htmlSizeBytes - baseMetric.htmlSizeBytes).toLocaleString("en-US")} B (${formatPercent(percentDelta(baseMetric.htmlSizeBytes, nextMetric.htmlSizeBytes))})`);
}

async function main() {
  const args = process.argv.slice(2);
  const compareMode = args[0] === "--compare";
  const fileArgs = compareMode ? args.slice(1) : args;
  const files = fileArgs.length ? fileArgs : DEFAULT_FILES;

  if (compareMode) {
    if (files.length !== 2) {
      throw new Error("benchmark-worker-startup --compare expects exactly two file paths");
    }
    // Run the two samples sequentially so import/render timings do not contend
    // for the same CPU/IO budget and skew the comparison.
    const baseMetric = await measureFile(files[0]);
    const nextMetric = await measureFile(files[1]);
    printComparison(baseMetric, nextMetric);
    return;
  }

  const metrics = [];
  for (const filePath of files) {
    metrics.push(await measureFile(filePath));
  }
  for (let index = 0; index < metrics.length; index += 1) {
    if (index > 0) console.log("");
    printMetric(metrics[index]);
  }
}

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exit(1);
});
