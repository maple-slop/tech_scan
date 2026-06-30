import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tech_scan.fetchers import (
    BrowserSession,
    chromium_executable_path,
    fetch_requests,
    redirect_target,
    same_hostname,
    should_try_browser,
)
from tech_scan.models import FetchResult


class FakeResponse:
    def __init__(self, url, status_code=200, headers=None, text=""):
        self.url = url
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
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


class FakeBrowserResponse:
    status = 200
    headers = {"server": "Chromium"}


class FakePage:
    def __init__(self):
        self.main_frame = object()
        self.url = "https://example.com/app"
        self.routes = []

    def route(self, pattern, handler):
        self.routes.append((pattern, handler))

    def goto(self, url, **kwargs):
        self.url = url
        return FakeBrowserResponse()

    def content(self):
        return '<html><script src="/app.js"></script></html>'

    def evaluate(self, script):
        if "Object.keys(window)" in script:
            return ["React"]
        return ["https://example.com/app.js"]


class FakeContext:
    def __init__(self, browser):
        self.browser = browser
        self.page = FakePage()
        self.closed = False

    def new_page(self):
        return self.page

    def cookies(self):
        return [{"name": "sid", "value": "abc"}]

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
        self.browser = FakeBrowser()

    def launch(self, **kwargs):
        self.launch_args.append(kwargs)
        return self.browser


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

    def test_browser_session_reuses_one_browser_with_separate_contexts(self):
        playwright = FakePlaywright()
        with install_fake_playwright(playwright):
            with patch.dict("os.environ", {"CHROMIUM_PATH": "/custom/chromium"}):
                session = BrowserSession(proxy="http://proxy:8080")
                first = session.fetch("example.com", "https://example.com", 5)
                second = session.fetch("example.org", "https://example.org", 5)
                session.close()

        self.assertEqual(len(playwright.chromium.launch_args), 1)
        self.assertEqual(
            playwright.chromium.launch_args[0]["executable_path"],
            "/custom/chromium",
        )
        self.assertEqual(
            playwright.chromium.launch_args[0]["proxy"],
            {"server": "http://proxy:8080"},
        )
        self.assertEqual(len(playwright.chromium.browser.contexts), 2)
        self.assertEqual(first.browser_globals, ["React"])
        self.assertEqual(second.script_srcs, ["https://example.com/app.js"])
        self.assertTrue(playwright.chromium.browser.closed)
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

        launch_env = playwright.chromium.launch_args[0]["env"]
        self.assertEqual(launch_env["SSL_CERT_FILE"], "/tmp/mitmproxy-ca.pem")
        self.assertEqual(launch_env["REQUESTS_CA_BUNDLE"], "/tmp/mitmproxy-ca.pem")
        self.assertEqual(launch_env["CURL_CA_BUNDLE"], "/tmp/mitmproxy-ca.pem")
        context_kwargs = playwright.chromium.browser.contexts[0][1]
        self.assertTrue(context_kwargs["ignore_https_errors"])

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
