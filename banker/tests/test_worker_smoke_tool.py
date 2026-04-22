from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT_DIR / "scripts" / "worker_smoke.py"


class WorkerStubHandler(BaseHTTPRequestHandler):
    server_version = "WorkerStub/1.0"

    def log_message(self, format, *args):  # noqa: A003
        return

    def _write_json(self, status: int, payload: dict, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _write_html(self, status: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/":
            self._write_html(200, "<html><body>landing</body></html>")
            return
        if self.path == "/admin":
            self._write_html(200, "<!doctype html><html><body><script>getAdminBootstrap()</script></body></html>")
            return
        self._write_json(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        content_length = int(self.headers.get("content-length", "0") or 0)
        raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        payload = json.loads(raw_body.decode("utf-8") or "{}")

        if self.path == "/admin/login":
            if payload.get("password") != "admin-pass":
                self._write_json(401, {"ok": False, "error": "bad_password"})
                return
            self._write_json(
                200,
                {"ok": True, "role": "admin"},
                headers={"Set-Cookie": "auth_token=test-token; Path=/admin; HttpOnly"},
            )
            return

        if self.path == "/admin":
            cookie = self.headers.get("cookie", "")
            if "auth_token=test-token" not in cookie:
                self._write_json(401, {"ok": False, "error": "missing_cookie"})
                return
            if payload.get("action") == "getAdminBootstrap":
                self._write_json(
                    200,
                    {
                        "config": {"uiRadiusPx": 12},
                        "nodes": [],
                        "runtimeStatus": {"status": "ok"},
                        "revisions": {"worker": "test"},
                    },
                )
                return
            if payload.get("action") == "list":
                self._write_json(200, {"nodes": []})
                return
            self._write_json(400, {"ok": False, "error": "unknown_action"})
            return

        self._write_json(404, {"ok": False, "error": "not_found"})


class WorkerTestServer:
    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), WorkerStubHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __enter__(self) -> "WorkerTestServer":
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def run_tool(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        cwd=str(ROOT_DIR),
        text=True,
        capture_output=True,
        check=False,
    )


def test_smoke_command_passes_against_worker_stub() -> None:
    with WorkerTestServer() as server:
        result = run_tool(
            "--base-url",
            server.base_url,
            "--admin-pass",
            "admin-pass",
            "--json",
            "smoke",
        )
    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["counts"]["PASS"] == 4
    assert payload["counts"]["FAIL"] == 0


def test_action_command_returns_action_payload() -> None:
    with WorkerTestServer() as server:
        result = run_tool(
            "--base-url",
            server.base_url,
            "--admin-pass",
            "admin-pass",
            "--json",
            "action",
            "list",
        )
    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["action_response"] == {"nodes": []}


def test_smoke_command_reports_login_skip_when_password_missing() -> None:
    with WorkerTestServer() as server:
        result = run_tool(
            "--base-url",
            server.base_url,
            "--json",
            "smoke",
        )
    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["counts"]["SKIP"] == 2
