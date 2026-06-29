import unittest
from types import SimpleNamespace
from unittest.mock import patch
import sys

from tech_scan.fetch import (
    BrowserSession,
    chromium_executable_path,
    fetch_requests,
    redirect_target,
    same_hostname,
)


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

    def get(self, url, **kwargs):
        self.urls.append(url)
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

        with patch("tech_scan.fetch.requests.Session", return_value=session):
            result = fetch_requests("example.com", "https://example.com", 5, None)

        self.assertEqual(session.urls, ["https://example.com", "https://example.com/login"])
        self.assertEqual(result.final_url, "https://example.com/login")
        self.assertEqual(result.status, 200)
        self.assertEqual(result.headers, {"server": "Apache"})

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

        with patch("tech_scan.fetch.requests.Session", return_value=session):
            result = fetch_requests("example.com", "https://example.com", 5, None)

        self.assertEqual(session.urls, ["https://example.com"])
        self.assertEqual(result.final_url, "https://example.com")
        self.assertEqual(result.status, 302)
        self.assertEqual(result.body, "")

    def test_chromium_path_prefers_environment(self):
        with patch.dict("os.environ", {"CHROMIUM_PATH": "/custom/chromium"}):
            with patch("tech_scan.fetch.os.access", return_value=True):
                self.assertEqual(chromium_executable_path(), "/custom/chromium")

    def test_chromium_path_uses_system_chromium(self):
        with patch.dict("os.environ", {}, clear=True):
            with patch("tech_scan.fetch.os.access", return_value=True):
                self.assertEqual(chromium_executable_path(), "/usr/bin/chromium")

    def test_chromium_path_falls_back_to_playwright_default(self):
        with patch.dict("os.environ", {}, clear=True):
            with patch("tech_scan.fetch.os.access", return_value=False):
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


if __name__ == "__main__":
    unittest.main()
