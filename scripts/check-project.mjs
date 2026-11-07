import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "..");
const frontendDirectory = path.join(repositoryRoot, "frontend");
const relayDirectory = path.join(repositoryRoot, "relay");

const requiredChecks = [
  {
    name: "Worker source syntax",
    command: process.execPath,
    args: ["./scripts/check-worker-syntax.mjs"],
    cwd: repositoryRoot,
  },
  {
    name: "Oxlint",
    command: process.execPath,
    args: [
      path.join(repositoryRoot, "node_modules", "oxlint", "bin", "oxlint"),
      "--deny-warnings",
      ".",
    ],
    cwd: repositoryRoot,
  },
  {
    name: "Oxfmt",
    command: process.execPath,
    args: [path.join(repositoryRoot, "node_modules", "oxfmt", "bin", "oxfmt"), "--check", "."],
    cwd: repositoryRoot,
  },
  {
    name: "Worker ESM architecture",
    command: process.execPath,
    args: ["./scripts/check-worker-architecture.mjs"],
    cwd: repositoryRoot,
  },
  {
    name: "Worker bundle freshness",
    command: process.execPath,
    args: ["./scripts/check-worker-bundle.mjs"],
    cwd: repositoryRoot,
  },
  {
    name: "Version consistency",
    command: process.execPath,
    args: ["./scripts/check-version-consistency.mjs"],
    cwd: repositoryRoot,
  },
  {
    name: "Worker, KV safety, and current D1 schema",
    command: process.execPath,
    args: [
      "--test",
      "tests/worker-defensive-boundaries.test.mjs",
      "tests/config-kv-safety.test.mjs",
      "tests/d1-schema.test.mjs",
      "tests/worker-bundle-smoke.test.mjs",
      "tests/frontend-runtime-enhancements.test.mjs",
      "tests/admin-contract-parity.test.mjs",
      "tests/version-consistency.test.mjs",
      "tests/tech-stack-pins.test.mjs",
      "tests/frontend-color-tokens.test.mjs",
      "tests/admin-vendor-bundle.test.mjs",
      "tests/relay-signing.test.mjs",
      "tests/relay-control-endpoint.test.mjs",
      "tests/direct-media-ticket.test.mjs",
    ],
    cwd: repositoryRoot,
  },
  {
    name: "Go relay tests",
    command: "go",
    args: ["test", "./..."],
    cwd: relayDirectory,
  },
  {
    name: "Admin runtime composition",
    command: process.execPath,
    args: ["./scripts/sync-admin-runtime.mjs", "--check"],
    cwd: frontendDirectory,
  },
  {
    name: "Frontend Vue source syntax",
    command: process.execPath,
    args: ["./scripts/check-frontend-sources.mjs"],
    cwd: repositoryRoot,
  },
  {
    name: "Admin vendor tree-shaking artifacts",
    command: process.execPath,
    args: ["./scripts/build-admin-vendor.mjs", "--check"],
    cwd: frontendDirectory,
  },
  {
    name: "Release CDN paths",
    command: process.execPath,
    args: ["./scripts/check-cdn-paths.mjs"],
    cwd: frontendDirectory,
  },
  {
    name: "Git diff whitespace",
    command: "git",
    args: ["diff", "--check"],
    cwd: repositoryRoot,
  },
];

for (const check of requiredChecks) {
  console.log(`\n[check-project] ${check.name}`);
  const completed = spawnSync(check.command, check.args, {
    cwd: check.cwd,
    stdio: "inherit",
    shell: false,
  });
  if (completed.error) throw completed.error;
  if (completed.status !== 0) {
    process.exit(completed.status || 1);
  }
}

console.log("\n[check-project] all checks passed");
