#!/usr/bin/env python3
"""仓库统一 Python 工具入口。

目标：
1. 让仓库对外暴露的常用工具入口统一收敛到 Python。
2. 纯文件型工具尽量直接使用 Python 实现。
3. 对必须执行 JavaScript/TypeScript 运行时的任务，由 Python 统一编排并显式说明依赖。
"""

from __future__ import annotations

import argparse
import gzip
from html.parser import HTMLParser
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from statistics import median
from typing import Sequence

import brotli


ROOT_DIR = Path(__file__).resolve().parent.parent
NODE_MODULES_DIR = ROOT_DIR / "node_modules"
DEFAULT_WORKER_PATH = ROOT_DIR / "worker.js"
DEFAULT_ADMIN_UI_PATH = ROOT_DIR / ".admin-ui.html"
REQUIRED_JS_DEPS = [
    ROOT_DIR / "node_modules" / "terser" / "bin" / "terser",
    ROOT_DIR / "node_modules" / "tailwindcss" / "lib" / "cli.js",
    ROOT_DIR / "node_modules" / "typescript" / "bin" / "tsc",
    ROOT_DIR / "node_modules" / "@cloudflare" / "workers-types" / "index.d.ts",
    ROOT_DIR / "node_modules" / "vue" / "dist" / "vue.runtime.global.prod.js",
    ROOT_DIR / "node_modules" / "lucide" / "dist" / "umd" / "lucide.min.js",
    ROOT_DIR / "node_modules" / "chart.js" / "dist" / "chart.umd.js",
]
UI_HTML_START_MARKER = "const UI_HTML = `"
UI_HTML_END_MARKER = "</html>`;"
UI_HTML_TEMPLATE_SUFFIX = "`;"
FINAL_UI_HTML_MARKER = "const FINAL_UI_HTML = UI_HTML;"
SITE_FAVICON_MARKER = "const SITE_FAVICON_SVG = `"
ADMIN_UI_REQUIRED_PLACEHOLDERS = ("__ADMIN_BOOTSTRAP_JSON__",)
ADMIN_UI_OPTIONAL_ROOT_SENTINELS = (
    "__ADMIN_APP_ROOT__",
    "__INIT_HEALTH_BANNER__",
    '<div id="app" v-cloak></div>',
)
ADMIN_UI_SINGLETON_SNIPPETS = {
    '<dialog id="node-modal"': 1,
    '<dialog id="node-link-copy-modal"': 1,
    '<div v-if="App.toastState.visible"': 1,
    '<div v-if="App.messageDialog.open"': 1,
    '<div v-if="App.confirmDialog.open"': 1,
    '<div v-if="App.promptDialog.open"': 1,
    '<div v-if="App.dnsIpImportModalOpen"': 1,
    '<div v-if="App.dnsIpSourceModalOpen"': 1,
}
HTML_VOID_TAGS = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
)


class ToolingError(RuntimeError):
    """统一的人类可读错误。"""


class AdminUiStructureParser(HTMLParser):
    """对管理台 HTML 做轻量标签栈校验，尽早发现重复片段或闭合失衡。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.stack: list[tuple[str, int]] = []
        self.issues: list[str] = []
        self.template_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[override]
        if tag == "template":
            self.template_depth += 1
            return
        if self.template_depth > 0:
            return
        if tag not in HTML_VOID_TAGS:
            self.stack.append((tag, self.getpos()[0]))

    def handle_endtag(self, tag: str) -> None:  # type: ignore[override]
        if tag == "template":
            if self.template_depth > 0:
                self.template_depth -= 1
            return
        if self.template_depth > 0:
            return
        if tag in HTML_VOID_TAGS:
            return
        line_no = self.getpos()[0]
        if not self.stack:
            self.issues.append(f"第 {line_no} 行出现多余的 </{tag}>")
            return
        if self.stack[-1][0] == tag:
            self.stack.pop()
            return
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] != tag:
                continue
            dangling = self.stack[index + 1 :]
            if dangling:
                preview = " -> ".join(f"<{name}>@{opened_line}" for name, opened_line in dangling[-3:])
                self.issues.append(f"第 {line_no} 行在 </{tag}> 前仍有未闭合标签: {preview}")
            self.stack = self.stack[:index]
            if self.stack and self.stack[-1][0] == tag:
                self.stack.pop()
            return
        self.issues.append(f"第 {line_no} 行出现无法匹配的 </{tag}>")


def resolve_path(value: str | Path | None, *, default: Path | None = None) -> Path:
    raw_value = value if value not in (None, "") else default
    if raw_value is None:
        raise ToolingError("缺少路径参数")
    path = Path(raw_value).expanduser()
    if not path.is_absolute():
        path = (ROOT_DIR / path).resolve()
    return path


def escape_template_literal(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${")


def decode_template_literal(value: str) -> str:
    source = str(value)
    result: list[str] = []
    index = 0
    while index < len(source):
        current = source[index]
        if current == "\\" and index + 1 < len(source):
            next_char = source[index + 1]
            if next_char in {"\\", "`"}:
                result.append(next_char)
                index += 2
                continue
            if next_char == "$" and source[index + 2 : index + 3] == "{":
                result.append("${")
                index += 3
                continue
        result.append(current)
        index += 1
    return "".join(result)


def locate_ui_html(source: str) -> dict[str, int | str]:
    start = source.find(UI_HTML_START_MARKER)
    end = source.find(UI_HTML_END_MARKER, start)
    if start < 0 or end < 0:
        raise ToolingError("无法在 worker.js 中定位 const UI_HTML 模板")
    return {
        "start": start,
        "end": end,
        "block_end": end + len(UI_HTML_END_MARKER),
        "value": source[start + len(UI_HTML_START_MARKER) : end + len("</html>")],
    }


def build_ui_html_section(template_source: str) -> str:
    return f"{UI_HTML_START_MARKER}{escape_template_literal(template_source)}{UI_HTML_TEMPLATE_SUFFIX}"


def replace_ui_html(source: str, template_source: str) -> str:
    ui_html = locate_ui_html(source)
    return f"{source[: int(ui_html['start'])]}{build_ui_html_section(template_source)}{source[int(ui_html['block_end']) :]}"


def read_runtime_admin_ui_template(worker_path: Path) -> str:
    require_binary("node")
    node_script = """
const { mkdtemp, readFile, rm, writeFile } = require("node:fs/promises");
const path = require("node:path");
const { tmpdir } = require("node:os");
const { pathToFileURL } = require("node:url");

(async () => {
  const workerPath = path.resolve(process.argv[1]);
  const source = await readFile(workerPath, "utf8");
  const tempDir = await mkdtemp(path.join(tmpdir(), "tooling-export-admin-ui-"));
  const tempModulePath = path.join(tempDir, "worker-ui-export.mjs");
  try {
    await writeFile(tempModulePath, `${source}\\nexport { UI_HTML, FINAL_UI_HTML };\\n`, "utf8");
    const mod = await import(pathToFileURL(tempModulePath).href + `?t=${Date.now()}-${Math.random().toString(36).slice(2)}`);
    const html = typeof mod.FINAL_UI_HTML === "string" && mod.FINAL_UI_HTML
      ? mod.FINAL_UI_HTML
      : (typeof mod.UI_HTML === "string" ? mod.UI_HTML : "");
    if (!html) throw new Error("failed to resolve FINAL_UI_HTML");
    process.stdout.write(html);
  } finally {
    try { delete globalThis.__EMBY_PROXY_NODE_TEST_HOOKS__; } catch {}
    await rm(tempDir, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exit(1);
});
""".strip()
    result = subprocess.run(
        ["node", "-e", node_script, str(worker_path)],
        cwd=str(ROOT_DIR),
        check=True,
        capture_output=True,
        text=True,
    )
    return str(result.stdout or "")


def read_admin_ui_template(worker_path: Path) -> str:
    worker_source = worker_path.read_text(encoding="utf-8")
    if FINAL_UI_HTML_MARKER not in worker_source:
        return read_runtime_admin_ui_template(worker_path)
    ui_html = locate_ui_html(worker_source)
    return decode_template_literal(str(ui_html["value"]))


def validate_admin_ui_singletons(template_source: str, *, source_label: Path) -> None:
    for snippet, expected_count in ADMIN_UI_SINGLETON_SNIPPETS.items():
        actual_count = template_source.count(snippet)
        if actual_count > expected_count:
            raise ToolingError(
                f"管理台 HTML 片段数量异常 {snippet!r}，最多允许 {expected_count} 次，实际 {actual_count} 次: {source_label}"
            )


def validate_admin_ui_structure(template_source: str, *, source_label: Path) -> None:
    parser = AdminUiStructureParser()
    parser.feed(template_source)
    parser.close()
    if parser.stack:
        remaining = " -> ".join(f"<{tag}>@{line_no}" for tag, line_no in parser.stack[-3:])
        parser.issues.append(f"文件结束时仍有未闭合标签: {remaining}")
    if parser.issues:
        summary = "；".join(parser.issues[:3])
        raise ToolingError(f"管理台 HTML 结构异常: {source_label} -> {summary}")


def validate_admin_ui_template(template_source: str, *, source_label: Path) -> str:
    next_template = str(template_source).strip()
    if not next_template:
        raise ToolingError(f"管理台 HTML 为空: {source_label}")
    if "</html>" not in next_template.lower():
        raise ToolingError(f"管理台 HTML 缺少 </html> 结束标签: {source_label}")
    for placeholder in ADMIN_UI_REQUIRED_PLACEHOLDERS:
        if placeholder not in next_template:
            raise ToolingError(f"管理台 HTML 缺少必需占位符 {placeholder}: {source_label}")
    if not any(sentinel in next_template for sentinel in ADMIN_UI_OPTIONAL_ROOT_SENTINELS):
        raise ToolingError(
            "管理台 HTML 缺少根挂载占位符，至少应包含 __ADMIN_APP_ROOT__ / __INIT_HEALTH_BANNER__ "
            f"或 <div id=\"app\" v-cloak></div>: {source_label}"
        )
    validate_admin_ui_singletons(next_template, source_label=source_label)
    validate_admin_ui_structure(next_template, source_label=source_label)
    return next_template


def print_command(command: Sequence[str]) -> None:
    rendered = " ".join(str(part) for part in command)
    print(f"$ {rendered}")


def run_command(
    command: Sequence[str],
    *,
    cwd: Path = ROOT_DIR,
    check: bool = True,
    capture_output: bool = False,
    text: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    print_command(command)
    return subprocess.run(
        [str(part) for part in command],
        cwd=str(cwd),
        check=check,
        capture_output=capture_output,
        text=text,
        env={**os.environ, **(env or {})},
    )


def require_binary(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise ToolingError(f"缺少可执行文件: {name}")
    return resolved


def ensure_js_deps() -> None:
    if all(path.exists() for path in REQUIRED_JS_DEPS):
        return
    require_binary("npm")
    print("[0/4] Installing JavaScript dev dependencies...")
    run_command(["npm", "install", "--ignore-scripts"])


def format_bytes(value: int) -> str:
    return f"{int(value):,} B"


def format_percent(value: float) -> str:
    rounded = 0 if abs(value) < 0.005 else value
    return f"{'+' if rounded >= 0 else ''}{rounded:.2f}%"


def diff_percent(base: int | float, next_value: int | float) -> float:
    if not isinstance(base, (int, float)) or base <= 0 or not isinstance(next_value, (int, float)):
        return 0.0
    return ((next_value - base) / base) * 100


def read_metrics(file_path: str | Path) -> dict[str, int | str]:
    absolute_path = Path(file_path).resolve()
    payload = absolute_path.read_bytes()
    return {
        "file_path": str(absolute_path),
        "raw": len(payload),
        "gzip": len(gzip.compress(payload, compresslevel=9)),
        "brotli": len(brotli.compress(payload, quality=11)),
    }


def print_metric(metric: dict[str, int | str]) -> None:
    print(f"file:   {metric['file_path']}")
    print(f"raw:    {format_bytes(int(metric['raw']))}")
    print(f"gzip:   {format_bytes(int(metric['gzip']))}")
    print(f"brotli: {format_bytes(int(metric['brotli']))}")


def print_metric_comparison(base_metric: dict[str, int | str], next_metric: dict[str, int | str]) -> None:
    print_metric(base_metric)
    print("")
    print_metric(next_metric)
    print("")
    print("delta:")
    print(
        f"raw:    {format_bytes(int(next_metric['raw']) - int(base_metric['raw']))} "
        f"({format_percent(diff_percent(int(base_metric['raw']), int(next_metric['raw'])))})"
    )
    print(
        f"gzip:   {format_bytes(int(next_metric['gzip']) - int(base_metric['gzip']))} "
        f"({format_percent(diff_percent(int(base_metric['gzip']), int(next_metric['gzip'])))})"
    )
    print(
        f"brotli: {format_bytes(int(next_metric['brotli']) - int(base_metric['brotli']))} "
        f"({format_percent(diff_percent(int(base_metric['brotli']), int(next_metric['brotli'])))})"
    )


def run_measure_worker_size(args: argparse.Namespace) -> int:
    files = args.files or ["worker.js", "_worker.js"]
    if args.compare:
        if len(files) != 2:
            raise ToolingError("measure-worker-size --compare 需要且只需要两个文件路径")
        base_metric, next_metric = [read_metrics(file_path) for file_path in files]
        print_metric_comparison(base_metric, next_metric)
        return 0

    for index, file_path in enumerate(files):
        if index > 0:
            print("")
        print_metric(read_metrics(file_path))
    return 0


def run_legacy_js_entrypoint(
    label: str,
    relative_path: str,
    extra_args: Sequence[str] | None = None,
    *,
    env: dict[str, str] | None = None,
) -> int:
    require_binary("node")
    command = ["node", str(ROOT_DIR / relative_path)]
    if extra_args:
        command.extend(extra_args)
    print(f"[python-wrapper] {label}: 该任务仍需 JS 运行时以加载仓库现有 JavaScript 模块。")
    run_command(command, env=env)
    return 0


def run_compress_admin_ui(args: argparse.Namespace) -> int:
    worker_path = resolve_path(getattr(args, "worker", None), default=DEFAULT_WORKER_PATH)
    template_source = read_admin_ui_template(worker_path)
    validate_admin_ui_template(template_source, source_label=worker_path)
    extra_args = ["--worker", str(worker_path)]
    deploy_output = getattr(args, "deploy_output", None)
    if deploy_output:
        extra_args.extend(["--deploy-output", str(resolve_path(deploy_output))])
    if args.check:
        extra_args.append("--check")
    return run_legacy_js_entrypoint(
        "compress-admin-ui",
        "scripts/compress-admin-ui.mjs",
        extra_args,
    )


def run_export_admin_ui(args: argparse.Namespace) -> int:
    worker_path = resolve_path(getattr(args, "worker", None), default=DEFAULT_WORKER_PATH)
    output_path = resolve_path(getattr(args, "output", None), default=DEFAULT_ADMIN_UI_PATH)
    template_source = validate_admin_ui_template(
        read_admin_ui_template(worker_path),
        source_label=worker_path,
    )
    output_path.write_text(template_source, encoding="utf-8")
    print(f"[python-native] export-admin-ui: 已导出 {worker_path} 当前管理台模板 -> {output_path}")
    return 0


def run_replace_admin_ui(args: argparse.Namespace) -> int:
    worker_path = resolve_path(getattr(args, "worker", None), default=DEFAULT_WORKER_PATH)
    source_path = resolve_path(getattr(args, "source", None), default=DEFAULT_ADMIN_UI_PATH)

    if not source_path.exists():
        raise ToolingError(f"待替换的管理台 HTML 文件不存在: {source_path}")
    if not worker_path.exists():
        raise ToolingError(f"目标 worker 文件不存在: {worker_path}")

    template_source = validate_admin_ui_template(
        source_path.read_text(encoding="utf-8"),
        source_label=source_path,
    )
    original_source = worker_path.read_text(encoding="utf-8")
    next_source = replace_ui_html(original_source, template_source)
    worker_path.write_text(next_source, encoding="utf-8")
    print(f"[python-native] replace-admin-ui: 已将 {source_path} 写回 {worker_path}")

    try:
        run_compress_admin_ui(argparse.Namespace(check=False, worker=str(worker_path)))
        run_compress_admin_ui(argparse.Namespace(check=True, worker=str(worker_path)))
    except Exception:
        worker_path.write_text(original_source, encoding="utf-8")
        print(f"[python-native] replace-admin-ui: 压缩/校验失败，已回滚 {worker_path}")
        raise

    print("[python-native] replace-admin-ui: 已完成回写、压缩与同步校验")
    return 0


def run_benchmark_worker_startup(args: argparse.Namespace) -> int:
    extra_args = []
    if args.compare:
        extra_args.append("--compare")
    extra_args.extend(args.files or ["worker.js", "_worker.js"])
    return run_legacy_js_entrypoint("benchmark-worker-startup", "scripts/benchmark-worker-startup.mjs", extra_args)


def run_benchmark_worker_segment(_: argparse.Namespace) -> int:
    return run_legacy_js_entrypoint("benchmark-worker-segment", "scripts/benchmark-segment-hotpath.mjs")


def run_worker_smoke(args: argparse.Namespace) -> int:
    if args.base_url:
        command = [sys.executable, str(ROOT_DIR / "scripts" / "worker_smoke.py"), "--base-url", args.base_url]
        if args.admin_pass:
            command.extend(["--admin-pass", args.admin_pass])
        if args.admin_path:
            command.extend(["--admin-path", args.admin_path])
        if args.as_json:
            command.append("--json")
        command.append("smoke")
        print("[python-native] worker-smoke: 走 Python 黑盒 Worker smoke 工具。")
        run_command(command)
        return 0
    worker_file = str(getattr(args, "worker_file", "") or "").strip()
    env = {}
    if worker_file:
        env["EMBY_PROXY_WORKER_FILE"] = worker_file
    return run_legacy_js_entrypoint("worker-smoke", "tests/worker-smoke.mjs", env=env or None)


def resolve_tsc_path() -> Path:
    tsc_path = ROOT_DIR / "node_modules" / "typescript" / "bin" / "tsc"
    if not tsc_path.exists():
        ensure_js_deps()
    return tsc_path


def run_typecheck(args: argparse.Namespace) -> int:
    require_binary("node")
    tsc_path = resolve_tsc_path()
    configs = args.configs or ["tsconfig.cloudflare.json"]
    for config_name in configs:
        print(f"[python-wrapper] typecheck: {config_name}")
        run_command(["node", str(tsc_path), "-p", str(ROOT_DIR / config_name), "--pretty", "false"])
    return 0


def minify_worker(worker_path: Path, output_path: Path) -> None:
    require_binary("node")
    ensure_js_deps()
    source = worker_path.read_text(encoding="utf-8")
    first_line, separator, remainder = source.partition("\n")
    if not separator:
        first_line = source
        remainder = ""

    terser_entry = ROOT_DIR / "node_modules" / "terser" / "bin" / "terser"
    # Keep the terser temp input on the repo filesystem so Windows-hosted Node can
    # still read it when the Python wrapper is launched from WSL.
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".js", prefix=".worker-minify-", dir=ROOT_DIR, delete=False) as handle:
        handle.write(remainder)
        temp_input = Path(handle.name)
    try:
        result = run_command(
            [
                "node",
                str(terser_entry),
                str(temp_input),
                "--ecma",
                "2022",
                "--compress",
                "passes=2",
                "--mangle",
                "--format",
                "comments=false,ascii_only=true",
            ],
            capture_output=True,
        )
        minified = result.stdout.strip()
        if not minified:
            raise ToolingError("terser 返回了空内容")
        output_path.write_text(f"{first_line}\n{minified}\n", encoding="utf-8")
    finally:
        temp_input.unlink(missing_ok=True)


def node_syntax_check(file_path: Path) -> None:
    require_binary("node")
    run_command(["node", "--check", str(file_path)])


def optional_wrangler_dry_run() -> None:
    wrangler_path = ROOT_DIR / "node_modules" / ".bin" / "wrangler"
    if not wrangler_path.exists():
        print("")
        print("[optional] Skipping wrangler dry-run packaging check (wrangler not installed).")
        return
    bundled_dir = ROOT_DIR / "bundled"
    if bundled_dir.exists():
        shutil.rmtree(bundled_dir)
    print("")
    print("[optional] Running wrangler dry-run packaging check")
    wrangler_source = (ROOT_DIR / "wrangler.toml").read_text(encoding="utf-8")
    main_pattern = r'^(main\s*=\s*)"(.*?)"(\s*(?:#.*)?)$'
    if not re.search(main_pattern, wrangler_source, flags=re.MULTILINE):
        raise ToolingError("无法在 wrangler.toml 中定位 main 配置")
    deploy_config_source = re.sub(
        main_pattern,
        r'\1"_worker.js"\3',
        wrangler_source,
        count=1,
        flags=re.MULTILINE,
    )
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        suffix=".toml",
        prefix=".wrangler-deploy-",
        dir=ROOT_DIR,
        delete=False,
    ) as handle:
        handle.write(deploy_config_source)
        deploy_config_path = Path(handle.name)
    try:
        run_command([str(wrangler_path), "deploy", "--dry-run", "--outdir", "bundled", "--config", str(deploy_config_path)])
    finally:
        deploy_config_path.unlink(missing_ok=True)


def print_size_report() -> None:
    print("")
    print("Size report.")
    print_metric_comparison(read_metrics("worker.js"), read_metrics("_worker.js"))


def run_build_worker(args: argparse.Namespace) -> int:
    mode = args.mode
    if mode not in {"build", "verify"}:
        raise ToolingError("build-worker 模式只支持 build 或 verify")

    ensure_js_deps()
    temp_deploy_source: Path | None = None
    try:
        print("[1/9] Materializing final admin UI template at build time")
        run_compress_admin_ui(argparse.Namespace(check=False, worker=str(DEFAULT_WORKER_PATH), deploy_output=""))

        print("[2/9] Verifying admin UI template is in sync")
        run_compress_admin_ui(argparse.Namespace(check=True, worker=str(DEFAULT_WORKER_PATH), deploy_output=""))

        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".js",
            prefix=".worker-deploy-source-",
            dir=ROOT_DIR,
            delete=False,
        ) as handle:
            temp_deploy_source = Path(handle.name)

        print("[3/9] Generating deploy worker source with precomputed admin UI variants")
        run_compress_admin_ui(
            argparse.Namespace(check=False, worker=str(DEFAULT_WORKER_PATH), deploy_output=str(temp_deploy_source))
        )

        print("[4/9] Minifying deploy worker source -> _worker.js")
        minify_worker(temp_deploy_source, ROOT_DIR / "_worker.js")

        print("[5/9] Running JavaScript syntax check")
        node_syntax_check(ROOT_DIR / "_worker.js")

        if mode == "verify":
            print("[6/9] Running worker smoke regression")
            run_worker_smoke(
                argparse.Namespace(
                    base_url="",
                    admin_pass="",
                    admin_path="",
                    as_json=False,
                    worker_file="_worker.js",
                )
            )
        else:
            print("[6/9] Skipping worker smoke regression in build mode")

        print("[7/9] Running Cloudflare TypeScript check (@cloudflare/workers-types)")
        run_typecheck(argparse.Namespace(configs=["tsconfig.cloudflare.json"]))

        print("[8/9] Running scripts TypeScript / JSDoc check")
        run_typecheck(argparse.Namespace(configs=["tsconfig.scripts.json"]))

        if mode == "verify":
            print("[9/9] Running segment hotpath benchmark")
            run_benchmark_worker_segment(argparse.Namespace())
        else:
            print("[9/9] Skipping segment hotpath benchmark in build mode")

        print("[post] Measuring startup and render benchmarks")
        run_benchmark_worker_startup(argparse.Namespace(compare=True, files=["worker.js", "_worker.js"]))
    finally:
        if temp_deploy_source is not None:
            temp_deploy_source.unlink(missing_ok=True)

    print_size_report()

    if mode == "verify":
        optional_wrangler_dry_run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="统一 Python 工具入口")
    subparsers = parser.add_subparsers(dest="command", required=True)

    compress_parser = subparsers.add_parser("compress-admin-ui", help="压缩并物化管理台内联模板")
    compress_parser.add_argument("--worker", default=str(DEFAULT_WORKER_PATH), help="待处理的 worker.js 路径")
    compress_parser.add_argument("--deploy-output", default="", help="可选：额外输出 deploy worker 临时源码")
    compress_parser.add_argument("--check", action="store_true", help="只校验同步状态，不落盘")
    compress_parser.set_defaults(handler=run_compress_admin_ui)

    verify_parser = subparsers.add_parser("verify-admin-ui", help="校验管理台内联模板是否同步")
    verify_parser.add_argument("--worker", default=str(DEFAULT_WORKER_PATH), help="待处理的 worker.js 路径")
    verify_parser.set_defaults(handler=lambda args: run_compress_admin_ui(argparse.Namespace(check=True, worker=args.worker)))

    export_ui_parser = subparsers.add_parser("export-admin-ui", help="从 worker.js 导出当前管理台 HTML")
    export_ui_parser.add_argument("output", nargs="?", default=str(DEFAULT_ADMIN_UI_PATH), help="导出目标文件，默认 .admin-ui.html")
    export_ui_parser.add_argument("--worker", default=str(DEFAULT_WORKER_PATH), help="待读取的 worker.js 路径")
    export_ui_parser.set_defaults(handler=run_export_admin_ui)

    replace_ui_parser = subparsers.add_parser("replace-admin-ui", help="从外部 HTML 回写并压缩管理台模板")
    replace_ui_parser.add_argument("source", nargs="?", default=str(DEFAULT_ADMIN_UI_PATH), help="待写回的 HTML 文件，默认 .admin-ui.html")
    replace_ui_parser.add_argument("--worker", default=str(DEFAULT_WORKER_PATH), help="待更新的 worker.js 路径")
    replace_ui_parser.set_defaults(handler=run_replace_admin_ui)

    measure_parser = subparsers.add_parser("measure-worker-size", help="测量 worker 文件体积")
    measure_parser.add_argument("--compare", action="store_true", help="比较两个文件的体积差异")
    measure_parser.add_argument("files", nargs="*", help="待测文件，默认 worker.js 和 _worker.js")
    measure_parser.set_defaults(handler=run_measure_worker_size)

    startup_parser = subparsers.add_parser("benchmark-worker-startup", help="执行启动与首屏渲染基准")
    startup_parser.add_argument("--compare", action="store_true", help="比较两个文件")
    startup_parser.add_argument("files", nargs="*", help="基准文件，默认 worker.js 和 _worker.js")
    startup_parser.set_defaults(handler=run_benchmark_worker_startup)

    segment_parser = subparsers.add_parser("benchmark-worker-segment", help="执行 segment 热路径基准")
    segment_parser.set_defaults(handler=run_benchmark_worker_segment)

    worker_smoke_parser = subparsers.add_parser("test-worker-smoke", help="执行 Worker smoke 测试")
    worker_smoke_parser.add_argument("--base-url", default="", help="若提供，则改用 Python live smoke 工具访问运行中的 Worker")
    worker_smoke_parser.add_argument("--admin-pass", default="", help="live smoke 时使用的管理员密码")
    worker_smoke_parser.add_argument("--admin-path", default="", help="live smoke 时使用的管理路径")
    worker_smoke_parser.add_argument("--json", action="store_true", dest="as_json", help="live smoke 输出 JSON")
    worker_smoke_parser.add_argument("--worker-file", default="", help="本地 smoke 时指定要加载的 worker 文件，默认 worker.js")
    worker_smoke_parser.set_defaults(handler=run_worker_smoke)

    typecheck_parser = subparsers.add_parser("typecheck", help="运行 TypeScript/JSDoc 类型检查")
    typecheck_parser.add_argument("configs", nargs="*", help="一个或多个 tsconfig 路径")
    typecheck_parser.set_defaults(handler=run_typecheck)

    build_parser = subparsers.add_parser("build-worker", help="执行 worker build/verify 流程")
    build_parser.add_argument("mode", nargs="?", default="verify", choices=["build", "verify"])
    build_parser.set_defaults(handler=run_build_worker)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except ToolingError as error:
        print(f"ERROR | {error}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as error:
        return int(error.returncode or 1)


if __name__ == "__main__":
    raise SystemExit(main())
