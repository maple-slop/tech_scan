import shutil
import io
import socket
import socketserver
import subprocess
import sys
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tech_scan.diagnostics import Diagnostics
from tech_scan.fetchers import (
    BrowserSession,
    browser_extension_identity,
    chromium_executable_path,
    fetch_requests,
    redirect_target,
    same_hostname,
    should_try_browser,
    ubol_extension_path,
)
from tech_scan.fetchers.adblock import is_blocked_script_url
from tech_scan.models import FetchResult


class FakeResponse:
    def __init__(self, url, status_code=200, headers=None, text=""):
        self.url = url
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.content = text.encode("utf-8")
        self.encoding = "utf-8"
        self.cookies = []


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.urls = []
        self.kwargs = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        self.kwargs.append(kwargs)
        return self.responses.pop(0)


class FakeBrowserRequest:
    def __init__(self, resource_type):
        self.resource_type = resource_type


class FakeBrowserResponse:
    def __init__(
        self,
        url="https://example.com/app",
        resource_type="document",
        status=200,
        headers=None,
        body=b"",
        body_error=None,
    ):
        self.url = url
        self.request = FakeBrowserRequest(resource_type)
        self.status = status
        self.headers = headers or {"server": "Chromium"}
        self._body = body
        self._body_error = body_error

    def body(self):
        if self._body_error:
            raise RuntimeError(self._body_error)
        return self._body


class FakePage:
    def __init__(self):
        self.main_frame = object()
        self.url = "https://example.com/app"
        self.routes = []
        self.handlers = {}
        self.closed = False

    def route(self, pattern, handler):
        self.routes.append((pattern, handler))

    def on(self, event, handler):
        setattr(handler, "_pw_impl_instance_", object())
        self.handlers.setdefault(event, []).append(handler)

    def goto(self, url, **kwargs):
        self.url = url
        responses = [
            FakeBrowserResponse(url, "document", headers={"server": "Chromium"}, body=b"<html></html>"),
            FakeBrowserResponse(
                "https://example.com/app.js",
                "script",
                headers={"content-type": "application/javascript"},
                body=b"React.version='18.0.0'",
            ),
            FakeBrowserResponse(
                "https://example.com/app.css",
                "stylesheet",
                headers={"content-type": "text/css"},
                body=b"body{}",
            ),
            FakeBrowserResponse(
                "https://example.com/logo.png",
                "image",
                headers={"content-type": "image/png"},
                body=b"PNG",
            ),
            FakeBrowserResponse(
                "https://example.com/broken.js",
                "script",
                headers={"content-type": "application/javascript"},
                body_error="body failed",
            ),
        ]
        for response in responses:
            for handler in self.handlers.get("response", []):
                handler(response)
        return responses[0]

    def content(self):
        return '<html><script src="/app.js"></script></html>'

    def evaluate(self, script):
        if "Object.keys(window)" in script:
            return ["React"]
        return ["https://example.com/app.js"]

    def close(self):
        self.closed = True


class FakeContext:
    def __init__(self, browser):
        self.browser = browser
        self.pages = []
        self.closed = False
        self.cleared_cookies = 0

    def new_page(self):
        page = FakePage()
        self.pages.append(page)
        return page

    def cookies(self):
        return [{"name": "sid", "value": "abc"}]

    def clear_cookies(self):
        self.cleared_cookies += 1

    def close(self):
        self.closed = True


class FakeBrowser:
    def __init__(self):
        self.contexts = []
        self.closed = False

    def new_context(self, **kwargs):
        context = FakeContext(self)
        self.contexts.append((context, kwargs))
        return context

    def close(self):
        self.closed = True


class FakeChromium:
    def __init__(self):
        self.launch_args = []
        self.persistent_launch_args = []
        self.browser = FakeBrowser()
        self.persistent_context = FakeContext(self.browser)

    def launch(self, **kwargs):
        self.launch_args.append(kwargs)
        return self.browser

    def launch_persistent_context(self, user_data_dir, **kwargs):
        self.persistent_launch_args.append((user_data_dir, kwargs))
        return self.persistent_context


class FakePlaywright:
    def __init__(self):
        self.chromium = FakeChromium()
        self.stopped = False

    def stop(self):
        self.stopped = True


class FakePlaywrightStarter:
    def __init__(self, playwright):
        self.playwright = playwright

    def start(self):
        return self.playwright


def install_fake_playwright(playwright):
    sync_api = SimpleNamespace(sync_playwright=lambda: FakePlaywrightStarter(playwright))
    return patch.dict(
        sys.modules,
        {
            "playwright": SimpleNamespace(),
            "playwright.sync_api": sync_api,
        },
    )


class FetchTests(unittest.TestCase):
    def test_vendored_adblock_rules_are_available(self):
        self.assertTrue(is_blocked_script_url("https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"))
        self.assertFalse(is_blocked_script_url("https://example.com/static/app.js"))

    def test_same_hostname_ignores_scheme_but_not_host(self):
        self.assertTrue(same_hostname("https://example.com", "http://example.com/path"))
        self.assertFalse(same_hostname("https://example.com", "https://www.example.com"))
        self.assertFalse(same_hostname("https://example.com", "https://google.com"))

    def test_redirect_target_resolves_relative_location(self):
        self.assertEqual(
            redirect_target("https://example.com/a/b", "../login"),
            "https://example.com/login",
        )

    def test_requests_follow_same_host_redirect(self):
        session = FakeSession(
            [
                FakeResponse(
                    "https://example.com",
                    302,
                    {"location": "https://example.com/login"},
                ),
                FakeResponse(
                    "https://example.com/login",
                    200,
                    {"server": "Apache"},
                    "ok",
                ),
            ]
        )

        with patch("tech_scan.fetchers.requests.requests.Session", return_value=session):
            result = fetch_requests("example.com", "https://example.com", 5, None)

        self.assertEqual(session.urls, ["https://example.com", "https://example.com/login"])
        self.assertEqual(result.final_url, "https://example.com/login")
        self.assertEqual(result.status, 200)
        self.assertEqual(result.headers, {"server": "Apache"})

    def test_requests_passes_proxy_and_tls_options(self):
        session = FakeSession([FakeResponse("https://example.com", 200, {}, "ok")])

        with patch("tech_scan.fetchers.requests.requests.Session", return_value=session):
            fetch_requests(
                "example.com",
                "https://example.com",
                5,
                "socks5h://127.0.0.1:1080",
                "/tmp/ca.pem",
            )

        self.assertEqual(
            session.kwargs[0]["proxies"],
            {
                "http": "socks5h://127.0.0.1:1080",
                "https": "socks5h://127.0.0.1:1080",
            },
        )
        self.assertEqual(session.kwargs[0]["verify"], "/tmp/ca.pem")

    def test_requests_insecure_disables_tls_verification(self):
        session = FakeSession([FakeResponse("https://example.com", 200, {}, "ok")])

        with patch("tech_scan.fetchers.requests.requests.Session", return_value=session):
            fetch_requests("example.com", "https://example.com", 5, "http://proxy:8080", False)

        self.assertEqual(
            session.kwargs[0]["proxies"],
            {"http": "http://proxy:8080", "https": "http://proxy:8080"},
        )
        self.assertIs(session.kwargs[0]["verify"], False)

    def test_requests_fetches_visible_script_subresources(self):
        session = FakeSession(
            [
                FakeResponse(
                    "https://example.com/app",
                    200,
                    {},
                    '<script src="/static/app.js"></script>'
                    '<script src="https://cdn.example.net/lib.js"></script>',
                ),
                FakeResponse("https://example.com/static/app.js", 200, {}, "React.version='18.0.0'"),
                FakeResponse("https://cdn.example.net/lib.js", 200, {}, "window.Vue={}"),
            ]
        )

        with patch("tech_scan.fetchers.requests.requests.Session", return_value=session):
            with patch("tech_scan.fetchers.requests.is_blocked_script_url", return_value=False):
                result = fetch_requests("example.com", "https://example.com/app", 5, None)

        self.assertEqual(
            session.urls,
            [
                "https://example.com/app",
                "https://example.com/static/app.js",
                "https://cdn.example.net/lib.js",
            ],
        )
        self.assertEqual(result.primary_resource.kind, "document")
        self.assertEqual([resource.kind for resource in result.resources], ["document", "script", "script"])
        self.assertEqual(result.resources[1].parent_id, result.primary_resource_id)
        self.assertIn("React.version", result.resources[1].body)
        self.assertEqual(
            result.script_srcs,
            ["https://example.com/static/app.js", "https://cdn.example.net/lib.js"],
        )

    def test_requests_passes_proxy_and_tls_options_to_script_fetches(self):
        session = FakeSession(
            [
                FakeResponse("https://example.com", 200, {}, '<script src="/app.js"></script>'),
                FakeResponse("https://example.com/app.js", 200, {}, "ok"),
            ]
        )

        with patch("tech_scan.fetchers.requests.requests.Session", return_value=session):
            with patch("tech_scan.fetchers.requests.is_blocked_script_url", return_value=False):
                fetch_requests("example.com", "https://example.com", 5, "http://proxy:8080", False)

        self.assertEqual(len(session.kwargs), 2)
        self.assertEqual(session.kwargs[1]["proxies"], {"http": "http://proxy:8080", "https": "http://proxy:8080"})
        self.assertIs(session.kwargs[1]["verify"], False)

    def test_requests_records_script_fetch_errors_without_failing_document(self):
        class ErrorSession(FakeSession):
            def get(self, url, **kwargs):
                if url.endswith("/app.js"):
                    raise RuntimeError("wrong exception")
                return super().get(url, **kwargs)

        session = ErrorSession(
            [FakeResponse("https://example.com", 200, {}, '<script src="/app.js"></script>')]
        )

        with patch("tech_scan.fetchers.requests.requests.Session", return_value=session):
            with patch("tech_scan.fetchers.requests.is_blocked_script_url", return_value=False):
                with patch(
                    "tech_scan.fetchers.requests.requests.RequestException",
                    Exception,
                ):
                    result = fetch_requests("example.com", "https://example.com", 5, None)

        self.assertEqual(result.status, 200)
        self.assertEqual(result.resources[1].kind, "script")
        self.assertEqual(result.resources[1].error, "wrong exception")

    def test_requests_primary_fetch_errors_include_traceback(self):
        class ErrorSession(FakeSession):
            def get(self, url, **kwargs):
                raise RuntimeError(f"cannot fetch {url}")

        with patch("tech_scan.fetchers.requests.requests.Session", return_value=ErrorSession([])):
            with patch("tech_scan.fetchers.requests.requests.RequestException", Exception):
                result = fetch_requests("example.com", "https://example.com", 5, None)

        self.assertIsNone(result.status)
        assert result.error is not None
        self.assertIn("cannot fetch http://example.com", result.error)
        self.assertNotIn("Traceback (most recent call last):", result.error)

    def test_requests_primary_fetch_errors_include_traceback_when_requested(self):
        class ErrorSession(FakeSession):
            def get(self, url, **kwargs):
                raise RuntimeError(f"cannot fetch {url}")

        with patch("tech_scan.fetchers.requests.requests.Session", return_value=ErrorSession([])):
            with patch("tech_scan.fetchers.requests.requests.RequestException", Exception):
                result = fetch_requests(
                    "example.com",
                    "https://example.com",
                    5,
                    None,
                    include_traceback=True,
                )

        assert result.error is not None
        self.assertIn("Traceback (most recent call last):", result.error)

    def test_requests_does_not_fetch_adblock_filtered_scripts(self):
        session = FakeSession(
            [
                FakeResponse(
                    "https://example.com",
                    200,
                    {},
                    '<script src="/app.js"></script><script src="/ads/banner.js"></script>',
                ),
                FakeResponse("https://example.com/app.js", 200, {}, "ok"),
            ]
        )

        def blocked(url):
            return "/ads/" in url

        with patch("tech_scan.fetchers.requests.requests.Session", return_value=session):
            with patch("tech_scan.fetchers.requests.is_blocked_script_url", side_effect=blocked):
                result = fetch_requests("example.com", "https://example.com", 5, None)

        self.assertEqual(session.urls, ["https://example.com", "https://example.com/app.js"])
        self.assertEqual([resource.url for resource in result.script_resources], ["https://example.com/app.js"])

    def test_requests_stop_script_before_cross_host_redirect(self):
        session = FakeSession(
            [
                FakeResponse("https://example.com", 200, {}, '<script src="/app.js"></script>'),
                FakeResponse(
                    "https://example.com/app.js",
                    302,
                    {"location": "https://cdn.example.net/app.js"},
                    "",
                ),
            ]
        )

        with patch("tech_scan.fetchers.requests.requests.Session", return_value=session):
            with patch("tech_scan.fetchers.requests.is_blocked_script_url", return_value=False):
                result = fetch_requests("example.com", "https://example.com", 5, None)

        self.assertEqual(session.urls, ["https://example.com", "https://example.com/app.js"])
        self.assertEqual(result.script_resources[0].status, 302)

    def test_requests_uses_http_proxy_for_http_target(self):
        received = []

        class ProxyHandler(socketserver.BaseRequestHandler):
            def handle(self):
                data = self.request.recv(4096)
                received.append(data.decode("iso-8859-1"))
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/html\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: close\r\n"
                    b"\r\nok"
                )

        try:
            server = socketserver.TCPServer(("127.0.0.1", 0), ProxyHandler)
        except PermissionError:
            self.skipTest("local sockets are not permitted in this sandbox")
        with server:
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            result = fetch_requests(
                "example.test",
                "http://example.test/",
                5,
                f"http://127.0.0.1:{server.server_address[1]}",
            )
            thread.join(timeout=5)

        self.assertEqual(result.status, 200)
        self.assertTrue(received)
        self.assertIn("GET http://example.test/ HTTP/1.1", received[0])

    def test_requests_can_use_mitmproxy_socks_proxy_when_available(self):
        if shutil.which("mitmdump") is None:
            self.skipTest("mitmdump is not installed")
        try:
            import socks  # noqa: F401
        except ImportError:
            self.skipTest("requests SOCKS support is not installed")

        origin_received = []

        class OriginHandler(socketserver.BaseRequestHandler):
            def handle(self):
                data = self.request.recv(4096)
                origin_received.append(data.decode("iso-8859-1"))
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: close\r\n"
                    b"\r\nok"
                )

        try:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                proxy_port = sock.getsockname()[1]
        except PermissionError:
            self.skipTest("local sockets are not permitted in this sandbox")

        try:
            origin = socketserver.TCPServer(("127.0.0.1", 0), OriginHandler)
        except PermissionError:
            self.skipTest("local sockets are not permitted in this sandbox")
        with origin:
            origin_thread = threading.Thread(target=origin.handle_request)
            origin_thread.start()
            proc = subprocess.Popen(
                [
                    "mitmdump",
                    "--mode",
                    "socks5",
                    "--listen-host",
                    "127.0.0.1",
                    "--listen-port",
                    str(proxy_port),
                    "--set",
                    "termlog_verbosity=error",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.time() + 10
                while time.time() < deadline:
                    with socket.socket() as probe:
                        if probe.connect_ex(("127.0.0.1", proxy_port)) == 0:
                            break
                    time.sleep(0.1)
                else:
                    self.skipTest("mitmdump did not start")

                result = fetch_requests(
                    "local",
                    f"http://127.0.0.1:{origin.server_address[1]}/",
                    5,
                    f"socks5h://127.0.0.1:{proxy_port}",
                )
                origin_thread.join(timeout=5)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

        self.assertEqual(result.status, 200)
        self.assertTrue(origin_received)
        self.assertIn("GET / HTTP/1.1", origin_received[0])

    def test_requests_stop_before_cross_host_redirect(self):
        session = FakeSession(
            [
                FakeResponse(
                    "https://example.com",
                    302,
                    {"location": "https://accounts.google.com/o/sso"},
                )
            ]
        )

        with patch("tech_scan.fetchers.requests.requests.Session", return_value=session):
            result = fetch_requests("example.com", "https://example.com", 5, None)

        self.assertEqual(session.urls, ["https://example.com"])
        self.assertEqual(result.final_url, "https://example.com")
        self.assertEqual(result.status, 302)
        self.assertEqual(result.body, "")

    def test_requests_redirect_trace_uses_diagnostics(self):
        stderr = io.StringIO()
        diagnostics = Diagnostics(verbosity=1, stream=stderr)
        session = FakeSession(
            [
                FakeResponse("https://example.com", 302, {"location": "https://example.com/login"}),
                FakeResponse("https://example.com/login", 302, {"location": "https://idp.example.net/sso"}),
            ]
        )

        with patch("tech_scan.fetchers.requests.requests.Session", return_value=session):
            fetch_requests(
                "example.com",
                "https://example.com",
                5,
                None,
                diagnostics=diagnostics,
            )

        logs = stderr.getvalue()
        self.assertIn("requests redirect: https://example.com -> https://example.com/login", logs)
        self.assertIn("requests redirect stopped:", logs)

    def test_chromium_path_prefers_environment(self):
        with patch.dict("os.environ", {"CHROMIUM_PATH": "/custom/chromium"}):
            with patch("tech_scan.fetchers.browser.os.access", return_value=True):
                self.assertEqual(chromium_executable_path(), "/custom/chromium")

    def test_chromium_path_uses_system_chromium(self):
        with patch.dict("os.environ", {}, clear=True):
            with patch("tech_scan.fetchers.browser.os.access", return_value=True):
                self.assertEqual(chromium_executable_path(), "/usr/bin/chromium")

    def test_chromium_path_falls_back_to_playwright_default(self):
        with patch.dict("os.environ", {}, clear=True):
            with patch("tech_scan.fetchers.browser.os.access", return_value=False):
                self.assertIsNone(chromium_executable_path())

    def test_browser_session_uses_one_persistent_context_with_extension(self):
        playwright = FakePlaywright()
        with install_fake_playwright(playwright):
            with patch.dict("os.environ", {"CHROMIUM_PATH": "/custom/chromium"}):
                session = BrowserSession(proxy="http://proxy:8080")
                first = session.fetch("example.com", "https://example.com", 5)
                second = session.fetch("example.org", "https://example.org", 5)
                session.close()

        self.assertEqual(len(playwright.chromium.launch_args), 0)
        self.assertEqual(len(playwright.chromium.persistent_launch_args), 1)
        user_data_dir, launch_args = playwright.chromium.persistent_launch_args[0]
        self.assertEqual(launch_args["executable_path"], "/custom/chromium")
        self.assertEqual(launch_args["proxy"], {"server": "http://proxy:8080"})
        self.assertIn("--load-extension=", launch_args["args"][1])
        self.assertIn("tech_scan/fetchers/data/ubol", launch_args["args"][1])
        self.assertEqual(playwright.chromium.persistent_context.cleared_cookies, 2)
        self.assertFalse(__import__("os").path.exists(user_data_dir))
        self.assertEqual(first.browser_globals, ["React"])
        self.assertEqual(second.script_srcs, ["https://example.com/app.js"])
        self.assertTrue(playwright.chromium.persistent_context.closed)
        self.assertTrue(playwright.stopped)

    def test_browser_session_applies_tls_options(self):
        playwright = FakePlaywright()
        with install_fake_playwright(playwright):
            session = BrowserSession(
                proxy=None,
                ignore_https_errors=True,
                ca_bundle="/tmp/mitmproxy-ca.pem",
            )
            session.fetch("example.com", "https://example.com", 5)
            session.close()

        launch_env = playwright.chromium.persistent_launch_args[0][1]["env"]
        self.assertEqual(launch_env["SSL_CERT_FILE"], "/tmp/mitmproxy-ca.pem")
        self.assertEqual(launch_env["REQUESTS_CA_BUNDLE"], "/tmp/mitmproxy-ca.pem")
        self.assertEqual(launch_env["CURL_CA_BUNDLE"], "/tmp/mitmproxy-ca.pem")
        self.assertTrue(playwright.chromium.persistent_launch_args[0][1]["ignore_https_errors"])

    def test_browser_session_raw_mode_uses_browser_contexts(self):
        playwright = FakePlaywright()
        with install_fake_playwright(playwright):
            session = BrowserSession(proxy=None, enable_extension=False)
            session.fetch("example.com", "https://example.com", 5)
            session.close()

        self.assertEqual(len(playwright.chromium.launch_args), 1)
        self.assertEqual(len(playwright.chromium.persistent_launch_args), 0)
        self.assertEqual(len(playwright.chromium.browser.contexts), 1)
        self.assertTrue(playwright.chromium.browser.contexts[0][0].closed)
        self.assertTrue(playwright.chromium.browser.closed)

    def test_browser_session_records_subresources_and_body_errors(self):
        playwright = FakePlaywright()
        with install_fake_playwright(playwright):
            session = BrowserSession(proxy=None)
            result = session.fetch("example.com", "https://example.com", 5)
            session.close()

        by_url = {resource.url: resource for resource in result.resources}
        self.assertEqual(result.primary_resource.kind, "document")
        self.assertIn("https://example.com/app.js", by_url)
        self.assertEqual(by_url["https://example.com/app.js"].kind, "script")
        self.assertEqual(by_url["https://example.com/app.js"].parent_id, result.primary_resource_id)
        self.assertIn("React.version", by_url["https://example.com/app.js"].body)
        self.assertEqual(by_url["https://example.com/app.css"].body, "body{}")
        self.assertEqual(by_url["https://example.com/logo.png"].body, "")
        self.assertEqual(by_url["https://example.com/broken.js"].error, "body failed")

    def test_browser_startup_errors_include_traceback(self):
        class BrokenChromium(FakeChromium):
            def launch_persistent_context(self, user_data_dir, **kwargs):
                raise RuntimeError("cannot launch browser")

        playwright = FakePlaywright()
        playwright.chromium = BrokenChromium()
        with install_fake_playwright(playwright):
            session = BrowserSession(proxy=None, include_traceback=True)
            result = session.fetch("example.com", "https://example.com", 5)
            session.close()

        self.assertIsNone(result.status)
        assert result.error is not None
        self.assertIn("cannot launch browser", result.error)
        self.assertIn("Traceback (most recent call last):", result.error)

    def test_browser_startup_errors_are_short_by_default(self):
        class BrokenChromium(FakeChromium):
            def launch_persistent_context(self, user_data_dir, **kwargs):
                raise RuntimeError("cannot launch browser")

        playwright = FakePlaywright()
        playwright.chromium = BrokenChromium()
        with install_fake_playwright(playwright):
            session = BrowserSession(proxy=None)
            result = session.fetch("example.com", "https://example.com", 5)
            session.close()

        self.assertEqual(result.error, "cannot launch browser")

    def test_ubol_package_data_is_available(self):
        self.assertTrue(ubol_extension_path().endswith("tech_scan/fetchers/data/ubol"))
        self.assertEqual(browser_extension_identity(True), "extension:ubol:2026.628.2035")
        self.assertEqual(browser_extension_identity(False), "extension:none")

    def test_auto_does_not_retry_small_static_html(self):
        fetch = FetchResult(
            input="example.com",
            url="https://example.com",
            final_url="https://example.com",
            status=200,
            headers={"server": "example"},
            cookies={},
            body="<html><body>Example Domain</body></html>",
            mode="requests",
        )

        self.assertFalse(should_try_browser(fetch, findings_count=0))

    def test_auto_retries_request_errors_and_blocking_statuses(self):
        errored = FetchResult(
            input="example.com",
            url="https://example.com",
            final_url=None,
            status=None,
            headers={},
            cookies={},
            body="",
            mode="requests",
            error="connection failed",
        )
        self.assertTrue(should_try_browser(errored, findings_count=0))

        for status in [401, 403, 429, 503]:
            with self.subTest(status=status):
                blocked = FetchResult(
                    input="example.com",
                    url="https://example.com",
                    final_url="https://example.com",
                    status=status,
                    headers={},
                    cookies={},
                    body="blocked",
                    mode="requests",
                )
                self.assertTrue(should_try_browser(blocked, findings_count=1))

    def test_auto_retries_explicit_javascript_required_text(self):
        fetch = FetchResult(
            input="example.com",
            url="https://example.com",
            final_url="https://example.com",
            status=200,
            headers={},
            cookies={},
            body="<html>Please enable JavaScript to continue.</html>",
            mode="requests",
        )

        self.assertTrue(should_try_browser(fetch, findings_count=1))

    def test_auto_retries_sparse_spa_shell_without_findings(self):
        fetch = FetchResult(
            input="example.com",
            url="https://example.com",
            final_url="https://example.com",
            status=200,
            headers={},
            cookies={},
            body='<html><body><div id="root"></div><script src="/app.js"></script></body></html>',
            mode="requests",
            script_srcs=["/app.js"],
        )

        self.assertTrue(should_try_browser(fetch, findings_count=0))
        self.assertFalse(should_try_browser(fetch, findings_count=1))

    def test_auto_retries_next_nuxt_markers_when_sparse(self):
        fetch = FetchResult(
            input="example.com",
            url="https://example.com",
            final_url="https://example.com",
            status=200,
            headers={},
            cookies={},
            body='<html><script id="__NEXT_DATA__">{}</script></html>',
            mode="requests",
        )

        self.assertTrue(should_try_browser(fetch, findings_count=0))
        self.assertFalse(should_try_browser(fetch, findings_count=1))


if __name__ == "__main__":
    unittest.main()
