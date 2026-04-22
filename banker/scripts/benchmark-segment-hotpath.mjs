#!/usr/bin/env node

import { copyFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const BENCHMARK_CASES = [
  {
    name: "root target",
    target: "https://origin.example.com",
    proxyPath: "/Videos/100/segment-00001.ts",
    search: "?MediaSourceId=root"
  },
  {
    name: "subpath target",
    target: "https://origin.example.com/emby",
    proxyPath: "/Videos/200/segment-00002.ts",
    search: "?MediaSourceId=subpath"
  },
  {
    name: "explicit port target",
    target: "https://origin.example.com:8443/root/",
    proxyPath: "/Videos/300/segment-00003.ts",
    search: ""
  },
  {
    name: "query-heavy segment",
    target: "https://origin.example.com/root/nested",
    proxyPath: "/Videos/400/segment-00004.ts",
    search: "?MediaSourceId=query&DeviceId=abc&Tag=etag-value"
  }
];

const BENCHMARK_ITERATIONS = 60000;
const BENCHMARK_ROUNDS = 7;

function median(values = []) {
  const sorted = [...values].sort((left, right) => left - right);
  if (!sorted.length) return 0;
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? sorted[middle]
    : (sorted[middle - 1] + sorted[middle]) / 2;
}

function percentDelta(base, next) {
  if (!Number.isFinite(base) || base <= 0 || !Number.isFinite(next)) return 0;
  return ((base - next) / base) * 100;
}

function formatNsPerOp(value) {
  return `${value.toFixed(2)} ns/op`;
}

async function loadWorkerHooks(rootDir) {
  const tempDir = await mkdtemp(join(tmpdir(), "worker-segment-bench-"));
  const tempModulePath = join(tempDir, "worker-under-benchmark.mjs");
  await copyFile(join(rootDir, "worker.js"), tempModulePath);
  await import(pathToFileURL(tempModulePath).href + `?t=${Date.now()}-${Math.random().toString(36).slice(2)}`);
  const hooks = globalThis.__EMBY_PROXY_NODE_TEST_HOOKS__ || null;
  return {
    hooks,
    async dispose() {
      try { delete globalThis.__EMBY_PROXY_NODE_TEST_HOOKS__; } catch {}
      await rm(tempDir, { recursive: true, force: true });
    }
  };
}

function runBenchmark(label, fn) {
  const rounds = [];
  for (let round = 0; round < BENCHMARK_ROUNDS; round += 1) {
    let sink = 0;
    const startedAt = process.hrtime.bigint();
    for (let iteration = 0; iteration < BENCHMARK_ITERATIONS; iteration += 1) {
      sink ^= fn().length;
    }
    const elapsedNs = Number(process.hrtime.bigint() - startedAt);
    rounds.push(elapsedNs / BENCHMARK_ITERATIONS);
    if (sink === Number.MIN_SAFE_INTEGER) {
      console.error(`${label}: unreachable sink`);
    }
  }
  return {
    medianNsPerOp: median(rounds),
    rounds
  };
}

async function main() {
  const scriptDir = dirname(fileURLToPath(import.meta.url));
  const rootDir = dirname(scriptDir);
  const { hooks, dispose } = await loadWorkerHooks(rootDir);
  if (!hooks?.buildUpstreamProxyUrl || !hooks?.buildFastSegmentUpstreamUrlText || typeof hooks.createTargetRecord !== "function") {
    throw new Error("worker benchmark hooks are unavailable");
  }

  let gateFailed = false;
  try {
    const results = [];
    for (const scenario of BENCHMARK_CASES) {
      const record = hooks.createTargetRecord(scenario.target);
      if (!hooks.isTargetRecord(record)) {
        throw new Error(`failed to create targetRecord for ${scenario.name}`);
      }

      const legacyBuilder = () => {
        const url = hooks.buildUpstreamProxyUrl(record, scenario.proxyPath);
        url.search = scenario.search;
        return url.toString();
      };
      const fastBuilder = () => hooks.buildFastSegmentUpstreamUrlText(record, scenario.proxyPath, scenario.search);

      const legacySample = legacyBuilder();
      const fastSample = fastBuilder();
      if (legacySample !== fastSample) {
        throw new Error(`equivalence failed for ${scenario.name}: ${JSON.stringify({ legacySample, fastSample })}`);
      }

      // Warm up both paths before measuring.
      for (let index = 0; index < 2000; index += 1) {
        legacyBuilder();
        fastBuilder();
      }

      const legacyBench = runBenchmark(`${scenario.name}:legacy`, legacyBuilder);
      const fastBench = runBenchmark(`${scenario.name}:fast`, fastBuilder);
      const improvementPct = percentDelta(legacyBench.medianNsPerOp, fastBench.medianNsPerOp);
      results.push({
        name: scenario.name,
        legacy: legacyBench.medianNsPerOp,
        fast: fastBench.medianNsPerOp,
        improvementPct
      });
    }

    console.log("Segment hotpath benchmark results");
    for (const result of results) {
      console.log(
        `${result.name}: legacy=${formatNsPerOp(result.legacy)} fast=${formatNsPerOp(result.fast)} improvement=${result.improvementPct.toFixed(2)}%`
      );
    }

    const rootCase = results.find(result => result.name === "root target");
    const subpathCase = results.find(result => result.name === "subpath target");
    if ((rootCase?.improvementPct || 0) < 10) {
      gateFailed = true;
      console.log(`Gate failed: root target improvement ${(rootCase?.improvementPct || 0).toFixed(2)}% is below 10%`);
    }
    if ((subpathCase?.improvementPct || 0) < 10) {
      gateFailed = true;
      console.log(`Gate failed: subpath target improvement ${(subpathCase?.improvementPct || 0).toFixed(2)}% is below 10%`);
    }
    for (const result of results) {
      if (result.improvementPct < -5) {
        gateFailed = true;
        console.log(`Gate failed: ${result.name} regressed by ${Math.abs(result.improvementPct).toFixed(2)}%`);
      }
    }

    if (gateFailed) {
      process.exitCode = 1;
      return;
    }

    console.log("Gate passed: fast segment builder meets benchmark thresholds.");
  } finally {
    await dispose();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
