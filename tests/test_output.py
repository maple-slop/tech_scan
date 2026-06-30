import io
import json
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tech_scan.cli import main, parse_args, resolve_provider_names
from tech_scan.output import (
    confidence_color,
    evidence_color,
    format_human,
    format_jsonl,
    origin_display_url,
)


RESULT = {
    "input": "example.com",
    "url": "https://example.com",
    "status": 200,
    "mode": "requests",
    "providers": ["builtin"],
    "cached": True,
    "technologies": [
        {
            "name": "Apache",
            "dimension": "cdn_waf_server",
            "provider": "builtin",
            "confidence": 90,
            "evidence": ["server header"],
        }
    ],
    "error": None,
}


class OutputTests(unittest.TestCase):
    def test_jsonl_format_matches_sorted_json_dump(self):
        self.assertEqual(format_jsonl(RESULT), json.dumps(RESULT, sort_keys=True))

    def test_human_format_includes_all_top_level_fields(self):
        output = format_human(RESULT, color=False)

        self.assertIn("input: example.com", output)
        self.assertIn("url: https://example.com", output)
        self.assertIn("status: 200", output)
        self.assertIn("mode: requests", output)
        self.assertIn("providers: builtin", output)
        self.assertIn("cached: True", output)
        self.assertIn("error: None", output)

    def test_human_format_includes_full_technology_information(self):
        output = format_human(RESULT, color=False)

        self.assertIn("Apache", output)
        self.assertIn("dimension=cdn_waf_server", output)
        self.assertIn("provider=builtin", output)
        self.assertIn("confidence=90", output)
        self.assertIn("evidence: server header", output)

    def test_human_format_color_can_be_enabled(self):
        output = format_human(RESULT, color=True)

        self.assertIn("\033[", output)

    def test_human_format_reports_no_technologies(self):
        result = dict(RESULT)
        result["technologies"] = []

        self.assertIn("technologies: none", format_human(result, color=False))

    def test_ca_bundle_defaults_from_known_environment_variables(self):
        with patch.dict(
            "os.environ",
            {
                "REQUESTS_CA_BUNDLE": "/tmp/requests-ca.pem",
                "CURL_CA_BUNDLE": "/tmp/curl-ca.pem",
                "SSL_CERT_FILE": "/tmp/ssl-ca.pem",
            },
            clear=True,
        ):
            self.assertEqual(str(parse_args([]).ca_bundle), "/tmp/requests-ca.pem")

        with patch.dict(
            "os.environ",
            {"CURL_CA_BUNDLE": "/tmp/curl-ca.pem", "SSL_CERT_FILE": "/tmp/ssl-ca.pem"},
            clear=True,
        ):
            self.assertEqual(str(parse_args([]).ca_bundle), "/tmp/curl-ca.pem")

        with patch.dict("os.environ", {"SSL_CERT_FILE": "/tmp/ssl-ca.pem"}, clear=True):
            self.assertEqual(str(parse_args([]).ca_bundle), "/tmp/ssl-ca.pem")

    def test_main_rejects_conflicting_tls_options(self):
        with TemporaryDirectory() as tmpdir:
            ca_bundle = Path(tmpdir) / "ca.pem"
            ca_bundle.write_text("ca", encoding="utf-8")
            args = ["--ca-bundle", str(ca_bundle), "--insecure"]

            stderr = io.StringIO()
            with patch("sys.stdin", io.StringIO("")):
                with patch("sys.stderr", stderr):
                    self.assertEqual(main(args), 2)

        self.assertIn("cannot be used", stderr.getvalue())

    def test_main_rejects_missing_ca_bundle(self):
        with TemporaryDirectory() as tmpdir:
            args = ["--ca-bundle", str(Path(tmpdir) / "missing.pem")]

            stderr = io.StringIO()
            with patch("sys.stdin", io.StringIO("")):
                with patch("sys.stderr", stderr):
                    self.assertEqual(main(args), 2)

        self.assertIn("does not exist", stderr.getvalue())

    def test_all_provider_names_include_wappalyzergo_by_default(self):
        self.assertEqual(
            resolve_provider_names(["all"]),
            ["builtin", "wappalyzergo"],
        )

    def test_wappalyzergo_command_flag_is_removed(self):
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            with self.assertRaises(SystemExit) as raised:
                parse_args(["--wappalyzergo-cmd", "unused"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("unrecognized arguments: --wappalyzergo-cmd", stderr.getvalue())

    def test_no_browser_extension_flag(self):
        self.assertTrue(parse_args([]).no_browser_extension is False)
        self.assertTrue(parse_args(["--no-browser-extension"]).no_browser_extension)

    def test_verbosity_flag(self):
        self.assertEqual(parse_args([]).verbosity, 0)
        for level in range(4):
            self.assertEqual(parse_args(["--verbosity", str(level)]).verbosity, level)
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parse_args(["--verbosity", "4"])

    def test_sanity_timeout_flag(self):
        self.assertEqual(parse_args([]).sanity_timeout, 1.0)
        self.assertEqual(parse_args(["--sanity-timeout", "0.25"]).sanity_timeout, 0.25)

    def test_main_human_output_separates_entries_with_blank_line(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            args = [
                "--db",
                str(db),
                "--mode",
                "requests",
                "--output",
                "human",
                "--concurrency",
                "1",
            ]
            fetch_result = {
                "input": "example.com",
                "url": "https://example.com",
                "status": 200,
                "mode": "requests",
                "providers": ["builtin"],
                "cached": False,
                "technologies": [],
                "error": None,
            }

            with patch("tech_scan.cli.scan_target", return_value=fetch_result):
                with patch("sys.stdin", io.StringIO("a.example\nb.example\n")):
                    stdout = io.StringIO()
                    with redirect_stdout(stdout):
                        self.assertEqual(main(args), 0)

            self.assertIn("\n\n", stdout.getvalue())

    def test_main_requests_output_is_eager_completion_order(self):
        first_can_finish = threading.Event()

        def fake_scan_target(target, args, providers_requested, provider_names, browser_session=None):
            if target == "a.example":
                self.assertTrue(first_can_finish.wait(timeout=5))
            else:
                first_can_finish.set()
            return {
                "input": target,
                "url": f"https://{target}/",
                "status": 200,
                "mode": "requests",
                "providers": ["builtin"],
                "cached": False,
                "technologies": [],
                "error": None,
            }

        with TemporaryDirectory() as tmpdir:
            args = [
                "--db",
                str(Path(tmpdir) / "results.db"),
                "--mode",
                "requests",
                "--output",
                "jsonl",
                "--concurrency",
                "2",
            ]
            with patch("tech_scan.cli.scan_target", side_effect=fake_scan_target):
                with patch("sys.stdin", io.StringIO("a.example\nb.example\n")):
                    stdout = io.StringIO()
                    with redirect_stdout(stdout):
                        self.assertEqual(main(args), 0)

        lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual([line["input"] for line in lines], ["b.example", "a.example"])

    def test_main_browser_mode_reuses_one_browser_session(self):
        sessions = []

        class FakeBrowserSession:
            def __init__(
                self,
                proxy,
                ignore_https_errors=False,
                ca_bundle=None,
                enable_extension=True,
                diagnostics=None,
                include_traceback=False,
            ):
                self.proxy = proxy
                self.ignore_https_errors = ignore_https_errors
                self.ca_bundle = ca_bundle
                self.enable_extension = enable_extension
                self.diagnostics = diagnostics
                self.include_traceback = include_traceback
                self.closed = False
                sessions.append(self)

            def close(self):
                self.closed = True

        def fake_scan_target(target, args, providers_requested, provider_names, browser_session=None):
            self.assertIs(browser_session, sessions[0])
            return {
                "input": target,
                "url": f"https://{target}/",
                "status": 200,
                "mode": "browser",
                "providers": ["builtin"],
                "cached": False,
                "technologies": [],
                "error": None,
            }

        with TemporaryDirectory() as tmpdir:
            args = [
                "--db",
                str(Path(tmpdir) / "results.db"),
                "--mode",
                "browser",
                "--output",
                "jsonl",
            ]
            with patch("tech_scan.cli.BrowserSession", FakeBrowserSession):
                with patch("tech_scan.cli.scan_target", side_effect=fake_scan_target) as scan_mock:
                    with patch("sys.stdin", io.StringIO("a.example\nb.example\n")):
                        stdout = io.StringIO()
                        with redirect_stdout(stdout):
                            self.assertEqual(main(args), 0)

        self.assertEqual(len(sessions), 1)
        self.assertTrue(sessions[0].closed)
        self.assertEqual(scan_mock.call_count, 2)

    def test_jsonl_output_stays_stdout_and_verbosity_logs_go_to_stderr(self):
        def fake_scan_target(target, args, providers_requested, provider_names, browser_session=None):
            args._diagnostics.log(1, f"diagnostic for {target}")
            return {
                "input": target,
                "url": f"https://{target}/",
                "status": 200,
                "mode": "requests",
                "providers": ["builtin"],
                "cached": False,
                "technologies": [],
                "error": None,
            }

        with TemporaryDirectory() as tmpdir:
            args = [
                "--db",
                str(Path(tmpdir) / "results.db"),
                "--mode",
                "requests",
                "--output",
                "jsonl",
                "--verbosity",
                "1",
            ]
            with patch("tech_scan.cli.scan_target", side_effect=fake_scan_target):
                with patch("sys.stdin", io.StringIO("a.example\n")):
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        self.assertEqual(main(args), 0)

        lines = stdout.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["input"], "a.example")
        self.assertIn("diagnostic for a.example", stderr.getvalue())

    def test_human_first_line_uses_origin_not_redirected_url(self):
        result = dict(RESULT)
        result["url"] = "https://example.com/some/long/path?token=abc"

        output = format_human(result, color=False)
        first_line = output.splitlines()[0]

        self.assertTrue(first_line.startswith("https://example.com/ 200 "))
        self.assertNotIn("/some/long/path", first_line)
        self.assertIn("url: https://example.com/some/long/path?token=abc", output)
        self.assertEqual(origin_display_url(result), "https://example.com/")

    def test_status_code_is_colorized(self):
        output = format_human(RESULT, color=True)

        self.assertIn("\033[32m200\033[0m", output)

    def test_confidence_color_gets_stronger_for_high_scores(self):
        self.assertEqual(confidence_color(95), "bright_green")
        self.assertEqual(confidence_color(80), "green")
        self.assertEqual(confidence_color(55), "yellow")
        self.assertEqual(confidence_color(20), "dim")

    def test_evidence_color_varies_by_strength(self):
        self.assertEqual(evidence_color("server header"), "green")
        self.assertEqual(evidence_color("react script/html marker"), "yellow")
        self.assertEqual(evidence_color("php url suffix"), "dim")

    def test_human_evidence_lines_use_strength_colors(self):
        result = dict(RESULT)
        result["technologies"] = [
            {
                "name": "PHP",
                "dimension": "backend_framework",
                "provider": "builtin",
                "confidence": 70,
                "evidence": ["php url suffix", "php header"],
            }
        ]

        output = format_human(result, color=True)

        self.assertIn("\033[2mphp url suffix\033[0m", output)
        self.assertIn("\033[32mphp header\033[0m", output)


if __name__ == "__main__":
    unittest.main()
