#!/usr/bin/env python3
"""Worker 黑盒 smoke 测试工具。

默认用于验证一个已经运行起来的 Cloudflare Worker URL，例如：

    ./.venv/bin/python scripts/worker_smoke.py smoke \
      --base-url http://127.0.0.1:8787 \
      --admin-pass admin-pass

也支持在登录后调用任意管理动作：

    ./.venv/bin/python scripts/worker_smoke.py action getAdminBootstrap \
      --base-url http://127.0.0.1:8787 \
      --admin-pass admin-pass
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
from dataclasses import asdict, dataclass
from http.cookiejar import CookieJar
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_USER_AGENT = "worker-python-smoke/1.0"
DEFAULT_ADMIN_PATH = "/admin"


class WorkerSmokeError(RuntimeError):
    """工具自身的可读错误。"""


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text())


@dataclass
class CheckResult:
    name: str
    outcome: str
    url: str
    detail: str
    http_status: int | None = None


def normalize_admin_path(raw: str | None) -> str:
    value = str(raw or "").strip()
    if not value:
        return DEFAULT_ADMIN_PATH
    normalized = value if value.startswith("/") else f"/{value}"
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    if len(normalized) > 1:
        normalized = normalized.rstrip("/")
    if not normalized or normalized == "/" or normalized.lower().startswith("/api"):
        return DEFAULT_ADMIN_PATH
    return normalized


def build_url(base_url: str, path: str) -> str:
    cleaned_base = str(base_url or "").strip()
    if not cleaned_base:
        raise WorkerSmokeError("base_url 不能为空")
    if not cleaned_base.endswith("/"):
        cleaned_base = f"{cleaned_base}/"
    return urljoin(cleaned_base, str(path or "").lstrip("/"))


def looks_like_html(body_text: str) -> bool:
    lowered = str(body_text or "").lower()
    return "<html" in lowered or "<!doctype html" in lowered or "getadminbootstrap" in lowered


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cloudflare Worker Python 黑盒测试工具")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("WORKER_BASE_URL", "http://127.0.0.1:8787"),
        help="Worker 基础地址，默认读取 WORKER_BASE_URL 或 http://127.0.0.1:8787",
    )
    parser.add_argument(
        "--admin-path",
        default=os.environ.get("WORKER_ADMIN_PATH", DEFAULT_ADMIN_PATH),
        help="管理后台路径，默认读取 WORKER_ADMIN_PATH 或 /admin",
    )
    parser.add_argument(
        "--admin-pass",
        default=os.environ.get("WORKER_ADMIN_PASS", ""),
        help="管理员密码；需要登录管理动作时提供",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("WORKER_TIMEOUT", DEFAULT_TIMEOUT_SECONDS)),
        help=f"HTTP 超时时间（秒），默认 {DEFAULT_TIMEOUT_SECONDS}",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=str(os.environ.get("WORKER_ALLOW_INSECURE", "")).strip().lower() in {"1", "true", "yes", "on"},
        help="跳过 HTTPS 证书校验，仅用于测试环境",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 输出结果摘要",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    smoke = subparsers.add_parser("smoke", help="验证 Worker 根路径、管理页、登录和 bootstrap")
    smoke.add_argument(
        "--skip-root",
        action="store_true",
        help="跳过根路径 / 的连通性检查",
    )
    smoke.add_argument(
        "--skip-login",
        action="store_true",
        help="跳过登录与 getAdminBootstrap 检查",
    )

    action = subparsers.add_parser("action", help="登录后执行单个管理动作")
    action.add_argument("action_name", help="例如 getAdminBootstrap")
    action.add_argument(
        "--payload",
        default="{}",
        help="JSON 字符串，会与 action 合并后发送给 POST ADMIN_PATH",
    )
    return parser


class WorkerSmokeClient:
    def __init__(self, *, base_url: str, admin_path: str, timeout: float, insecure: bool = False) -> None:
        self.base_url = str(base_url).strip()
        self.admin_path = normalize_admin_path(admin_path)
        self.timeout = float(timeout)
        self.cookie_jar = CookieJar()
        handlers: list[Any] = [HTTPCookieProcessor(self.cookie_jar)]
        if insecure:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            handlers.append(HTTPSHandler(context=context))
        self.opener = build_opener(*handlers)

    @property
    def admin_login_path(self) -> str:
        return "/login" if self.admin_path == "/" else f"{self.admin_path}/login"

    def has_cookie(self, name: str) -> bool:
        target = str(name or "").strip()
        return any(cookie.name == target for cookie in self.cookie_jar)

    def request(self, method: str, path: str, *, json_body: Any | None = None) -> HttpResponse:
        url = build_url(self.base_url, path)
        headers = {
            "accept": "application/json, text/html;q=0.9, */*;q=0.8",
            "user-agent": DEFAULT_USER_AGENT,
        }
        data = None
        if json_body is not None:
            headers["content-type"] = "application/json"
            data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
        req = Request(url, method=method.upper(), headers=headers, data=data)
        try:
            with self.opener.open(req, timeout=self.timeout) as res:
                body = res.read()
                return HttpResponse(
                    status=int(getattr(res, "status", 200)),
                    headers={key.lower(): value for key, value in res.headers.items()},
                    body=body,
                    url=url,
                )
        except HTTPError as error:
            body = error.read()
            return HttpResponse(
                status=int(error.code),
                headers={key.lower(): value for key, value in error.headers.items()},
                body=body,
                url=url,
            )
        except URLError as error:
            raise WorkerSmokeError(f"请求 {url} 失败: {error.reason}") from error

    def check_root(self) -> CheckResult:
        response = self.request("GET", "/")
        if response.status != 200:
            return CheckResult("root", "FAIL", response.url, f"期望 200，实际 {response.status}", response.status)
        return CheckResult("root", "PASS", response.url, "根路径可访问", response.status)

    def check_admin_html(self) -> CheckResult:
        response = self.request("GET", self.admin_path)
        if response.status != 200:
            return CheckResult("admin_html", "FAIL", response.url, f"期望 200，实际 {response.status}", response.status)
        body_text = response.text()
        if not looks_like_html(body_text):
            return CheckResult("admin_html", "FAIL", response.url, "返回内容不像管理页 HTML", response.status)
        return CheckResult("admin_html", "PASS", response.url, "管理页骨架返回正常", response.status)

    def login_admin(self, password: str) -> CheckResult:
        response = self.request("POST", self.admin_login_path, json_body={"password": password})
        if response.status != 200:
            return CheckResult("admin_login", "FAIL", response.url, f"登录失败，HTTP {response.status}", response.status)
        try:
            payload = response.json()
        except json.JSONDecodeError as error:
            return CheckResult("admin_login", "FAIL", response.url, f"登录响应不是 JSON: {error}", response.status)
        if payload.get("ok") is not True:
            return CheckResult("admin_login", "FAIL", response.url, f"登录响应未返回 ok=true: {payload}", response.status)
        if not self.has_cookie("auth_token"):
            return CheckResult("admin_login", "FAIL", response.url, "登录成功但未拿到 auth_token Cookie", response.status)
        return CheckResult("admin_login", "PASS", response.url, "管理员登录成功", response.status)

    def run_admin_action(self, action_name: str, payload: dict[str, Any] | None = None) -> HttpResponse:
        body = {"action": action_name}
        if payload:
            body.update(payload)
        return self.request("POST", self.admin_path, json_body=body)

    def check_bootstrap(self) -> CheckResult:
        response = self.run_admin_action("getAdminBootstrap")
        if response.status != 200:
            return CheckResult("getAdminBootstrap", "FAIL", response.url, f"期望 200，实际 {response.status}", response.status)
        try:
            payload = response.json()
        except json.JSONDecodeError as error:
            return CheckResult("getAdminBootstrap", "FAIL", response.url, f"bootstrap 响应不是 JSON: {error}", response.status)
        expected_keys = {"config", "nodes", "runtimeStatus", "revisions"}
        if not isinstance(payload, dict) or not (expected_keys & set(payload.keys())):
            return CheckResult(
                "getAdminBootstrap",
                "FAIL",
                response.url,
                f"bootstrap 响应缺少关键字段，实际 keys={sorted(payload.keys()) if isinstance(payload, dict) else type(payload).__name__}",
                response.status,
            )
        return CheckResult("getAdminBootstrap", "PASS", response.url, "管理台 bootstrap 正常", response.status)


def summarize_results(results: list[CheckResult]) -> dict[str, Any]:
    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    for result in results:
        counts[result.outcome] = counts.get(result.outcome, 0) + 1
    return {
        "ok": counts.get("FAIL", 0) == 0,
        "counts": counts,
        "results": [asdict(result) for result in results],
    }


def print_summary(summary: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return
    for result in summary["results"]:
        status = result["outcome"]
        http_status = result.get("http_status")
        suffix = f" | http={http_status}" if http_status is not None else ""
        print(f"{status:<4} | {result['name']} | {result['detail']} | {result['url']}{suffix}")
    counts = summary["counts"]
    print(
        "SUMMARY "
        f"ok={summary['ok']} "
        f"pass={counts.get('PASS', 0)} "
        f"fail={counts.get('FAIL', 0)} "
        f"skip={counts.get('SKIP', 0)}"
    )


def run_smoke_command(args: argparse.Namespace) -> int:
    client = WorkerSmokeClient(
        base_url=args.base_url,
        admin_path=args.admin_path,
        timeout=args.timeout,
        insecure=args.insecure,
    )
    results: list[CheckResult] = []
    if args.skip_root:
        results.append(CheckResult("root", "SKIP", build_url(args.base_url, "/"), "按参数跳过根路径检查"))
    else:
        results.append(client.check_root())
    results.append(client.check_admin_html())

    if args.skip_login:
        results.append(CheckResult("admin_login", "SKIP", build_url(args.base_url, client.admin_login_path), "按参数跳过登录检查"))
        results.append(CheckResult("getAdminBootstrap", "SKIP", build_url(args.base_url, client.admin_path), "按参数跳过 bootstrap 检查"))
    elif not str(args.admin_pass or "").strip():
        results.append(CheckResult("admin_login", "SKIP", build_url(args.base_url, client.admin_login_path), "未提供 --admin-pass，跳过登录检查"))
        results.append(CheckResult("getAdminBootstrap", "SKIP", build_url(args.base_url, client.admin_path), "未提供 --admin-pass，跳过 bootstrap 检查"))
    else:
        login_result = client.login_admin(str(args.admin_pass))
        results.append(login_result)
        if login_result.outcome == "PASS":
            results.append(client.check_bootstrap())
        else:
            results.append(CheckResult("getAdminBootstrap", "SKIP", build_url(args.base_url, client.admin_path), "登录失败，跳过 bootstrap 检查"))

    summary = summarize_results(results)
    print_summary(summary, args.json)
    return 0 if summary["ok"] else 1


def run_action_command(args: argparse.Namespace) -> int:
    client = WorkerSmokeClient(
        base_url=args.base_url,
        admin_path=args.admin_path,
        timeout=args.timeout,
        insecure=args.insecure,
    )
    password = str(args.admin_pass or "").strip()
    if not password:
        raise WorkerSmokeError("action 子命令需要提供 --admin-pass")

    login_result = client.login_admin(password)
    results = [login_result]
    if login_result.outcome != "PASS":
        summary = summarize_results(results)
        print_summary(summary, args.json)
        return 1

    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError as error:
        raise WorkerSmokeError(f"--payload 不是合法 JSON: {error}") from error
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise WorkerSmokeError("--payload 必须是 JSON 对象")

    response = client.run_admin_action(args.action_name, payload)
    try:
        response_body = response.json()
    except json.JSONDecodeError:
        response_body = response.text()

    result = CheckResult(
        name=f"action:{args.action_name}",
        outcome="PASS" if 200 <= response.status < 300 else "FAIL",
        url=response.url,
        detail=f"动作执行完成，HTTP {response.status}",
        http_status=response.status,
    )
    summary = summarize_results(results + [result])
    if args.json:
        summary["action_response"] = response_body
        print_summary(summary, True)
    else:
        print_summary(summary, False)
        print("ACTION_RESPONSE")
        if isinstance(response_body, str):
            print(response_body)
        else:
            print(json.dumps(response_body, ensure_ascii=False, indent=2))
    return 0 if summary["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "smoke":
            return run_smoke_command(args)
        if args.command == "action":
            return run_action_command(args)
        raise WorkerSmokeError(f"不支持的命令: {args.command}")
    except WorkerSmokeError as error:
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False, indent=2))
        else:
            print(f"ERROR | {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
