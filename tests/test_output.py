import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tech_scan.cli import format_human, format_jsonl, main


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


if __name__ == "__main__":
    unittest.main()
