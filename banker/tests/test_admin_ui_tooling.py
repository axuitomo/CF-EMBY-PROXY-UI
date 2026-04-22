from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path

import pytest


ROOT_DIR = Path(__file__).resolve().parent.parent
TOOLING_PATH = ROOT_DIR / "scripts" / "tooling.py"
SPEC = importlib.util.spec_from_file_location("tooling", TOOLING_PATH)
assert SPEC and SPEC.loader
tooling = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tooling)


def build_worker_source(template_html: str) -> str:
    escaped_html = tooling.escape_template_literal(template_html)
    return (
        f"{tooling.UI_HTML_START_MARKER}{escaped_html}{tooling.UI_HTML_TEMPLATE_SUFFIX}\n"
        f"{tooling.FINAL_UI_HTML_MARKER}\n"
        f'{tooling.SITE_FAVICON_MARKER}<svg viewBox="0 0 1 1"></svg>`;\n'
    )


def create_admin_ui_html(title: str) -> str:
    return (
        "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\">"
        f"<title>{title}</title>"
        "<script>window.__ADMIN_BOOTSTRAP__=__ADMIN_BOOTSTRAP_JSON__;</script>"
        "</head><body>__INIT_HEALTH_BANNER__\n  __ADMIN_APP_ROOT__</body></html>"
    )


def test_validate_admin_ui_template_rejects_duplicate_singleton_fragments(tmp_path: Path) -> None:
    source_path = tmp_path / "admin-ui.html"
    broken_html = create_admin_ui_html("重复片段").replace(
        "</body></html>",
        (
            '<div v-if="App.toastState.visible"></div>'
            '<div v-if="App.toastState.visible"></div>'
            '<dialog id="node-modal"></dialog>'
            '<dialog id="node-link-copy-modal"></dialog>'
            '<div v-if="App.messageDialog.open"></div>'
            '<div v-if="App.confirmDialog.open"></div>'
            '<div v-if="App.promptDialog.open"></div>'
            '<div v-if="App.dnsIpImportModalOpen"></div>'
            '<div v-if="App.dnsIpSourceModalOpen"></div>'
            "</body></html>"
        ),
    )

    with pytest.raises(tooling.ToolingError, match="片段数量异常"):
        tooling.validate_admin_ui_template(broken_html, source_label=source_path)


def test_validate_admin_ui_template_rejects_unmatched_closing_tags(tmp_path: Path) -> None:
    source_path = tmp_path / "admin-ui.html"
    broken_html = create_admin_ui_html("结构异常").replace("</body></html>", "</div></body></html>")

    with pytest.raises(tooling.ToolingError, match="结构异常"):
        tooling.validate_admin_ui_template(broken_html, source_label=source_path)


def test_export_admin_ui_reads_embedded_template(tmp_path: Path) -> None:
    worker_path = tmp_path / "worker.js"
    output_path = tmp_path / "admin-ui.html"
    expected_html = create_admin_ui_html("导出测试")
    worker_path.write_text(build_worker_source(expected_html), encoding="utf-8")

    result = tooling.run_export_admin_ui(
        argparse.Namespace(worker=str(worker_path), output=str(output_path))
    )

    assert result == 0
    assert output_path.read_text(encoding="utf-8") == expected_html


def test_compress_admin_ui_passes_deploy_output_to_js_entrypoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker_path = tmp_path / "worker.js"
    deploy_path = tmp_path / "deploy-worker.js"
    calls: list[tuple[str, str, list[str]]] = []
    worker_path.write_text(build_worker_source(create_admin_ui_html("压缩测试")), encoding="utf-8")

    def fake_entrypoint(label: str, relative_path: str, extra_args: list[str] | None = None, *, env=None) -> int:
        calls.append((label, relative_path, list(extra_args or [])))
        return 0

    monkeypatch.setattr(tooling, "run_legacy_js_entrypoint", fake_entrypoint)

    result = tooling.run_compress_admin_ui(
        argparse.Namespace(worker=str(worker_path), check=False, deploy_output=str(deploy_path))
    )

    assert result == 0
    assert calls == [
        (
            "compress-admin-ui",
            "scripts/compress-admin-ui.mjs",
            ["--worker", str(worker_path), "--deploy-output", str(deploy_path)],
        )
    ]


def test_compress_admin_ui_rejects_invalid_embedded_template_before_js_entrypoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker_path = tmp_path / "worker.js"
    broken_html = create_admin_ui_html("坏模板").replace("</body></html>", "</div></body></html>")
    worker_path.write_text(build_worker_source(broken_html), encoding="utf-8")
    called = False

    def fake_entrypoint(label: str, relative_path: str, extra_args: list[str] | None = None, *, env=None) -> int:
        nonlocal called
        called = True
        return 0

    monkeypatch.setattr(tooling, "run_legacy_js_entrypoint", fake_entrypoint)

    with pytest.raises(tooling.ToolingError, match="结构异常"):
        tooling.run_compress_admin_ui(
            argparse.Namespace(worker=str(worker_path), check=True, deploy_output="")
        )

    assert called is False


def test_export_admin_ui_rejects_invalid_embedded_template(tmp_path: Path) -> None:
    worker_path = tmp_path / "worker.js"
    output_path = tmp_path / "admin-ui.html"
    broken_html = create_admin_ui_html("坏模板").replace("</body></html>", "</div></body></html>")
    worker_path.write_text(build_worker_source(broken_html), encoding="utf-8")

    with pytest.raises(tooling.ToolingError, match="结构异常"):
        tooling.run_export_admin_ui(
            argparse.Namespace(worker=str(worker_path), output=str(output_path))
        )

    assert output_path.exists() is False


def test_replace_admin_ui_writes_template_then_runs_compress_and_verify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker_path = tmp_path / "worker.js"
    source_path = tmp_path / "admin-ui.html"
    original_html = create_admin_ui_html("旧管理台")
    replacement_html = create_admin_ui_html("新管理台")
    worker_path.write_text(build_worker_source(original_html), encoding="utf-8")
    source_path.write_text(replacement_html, encoding="utf-8")
    compress_calls: list[tuple[bool, str]] = []

    def fake_compress(args: argparse.Namespace) -> int:
        compress_calls.append((bool(args.check), str(args.worker)))
        assert Path(args.worker).read_text(encoding="utf-8").count("新管理台") == 1
        return 0

    monkeypatch.setattr(tooling, "run_compress_admin_ui", fake_compress)

    result = tooling.run_replace_admin_ui(
        argparse.Namespace(worker=str(worker_path), source=str(source_path))
    )

    assert result == 0
    assert compress_calls == [(False, str(worker_path)), (True, str(worker_path))]
    worker_source = worker_path.read_text(encoding="utf-8")
    assert "新管理台" in worker_source
    assert tooling.FINAL_UI_HTML_MARKER in worker_source


def test_build_worker_source_keeps_direct_final_ui_marker_without_legacy_runtime_traces() -> None:
    worker_source = build_worker_source(create_admin_ui_html("当前标记"))

    assert tooling.FINAL_UI_HTML_MARKER in worker_source
    assert "materializeAdminUiHtmlLegacy" not in worker_source
    assert 'template:"#tpl-' not in worker_source
    assert "HTMLRewriter" not in worker_source


def test_replace_admin_ui_rolls_back_when_compress_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker_path = tmp_path / "worker.js"
    source_path = tmp_path / "admin-ui.html"
    original_html = create_admin_ui_html("回滚前")
    replacement_html = create_admin_ui_html("回滚后")
    original_source = build_worker_source(original_html)
    worker_path.write_text(original_source, encoding="utf-8")
    source_path.write_text(replacement_html, encoding="utf-8")

    def fake_compress(_: argparse.Namespace) -> int:
        raise tooling.ToolingError("mock compress failure")

    monkeypatch.setattr(tooling, "run_compress_admin_ui", fake_compress)

    with pytest.raises(tooling.ToolingError, match="mock compress failure"):
        tooling.run_replace_admin_ui(
            argparse.Namespace(worker=str(worker_path), source=str(source_path))
        )

    assert worker_path.read_text(encoding="utf-8") == original_source
