import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import json
import subprocess

from tech_scan.models import FetchResult, ResourceObservation
from tech_scan.providers import (
    BuiltinProvider,
    WappalyzerGoProvider,
    WappalyzerJsonProvider,
    build_providers,
    merge_findings,
    parse_wappalyzer_pattern,
)
from tech_scan.providers.wappalyzergo import load_vendored_fingerprints


def make_fetch(headers=None, cookies=None, body="", globals_=None, url="https://example.com"):
    document = ResourceObservation(
        id="document:0",
        kind="document",
        url=url,
        final_url=url,
        status=200,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        cookies=cookies or {},
        body=body,
    )
    return FetchResult(
        input="example.com",
        url=url,
        final_url=url,
        status=200,
        headers=document.headers,
        cookies=document.cookies,
        body=body,
        mode="requests",
        browser_globals=globals_ or [],
        resources=[document],
        primary_resource_id=document.id,
    )


def names(findings):
    return {finding.name for finding in findings}


class ProviderTests(unittest.TestCase):
    def test_builtin_detects_traditional_backend_tech(self):
        fetch = make_fetch(
            headers={
                "Server": "Microsoft-IIS/10.0",
                "X-AspNet-Version": "4.0.30319",
            },
            cookies={"JSESSIONID": "abc", ".AspNetCore.Session": "xyz"},
            body="Whitelabel Error Page /login.jsp",
        )

        detected = BuiltinProvider().detect(fetch)

        self.assertLessEqual(
            {"Microsoft IIS", "ASP.NET", "ASP.NET Core", "Java", "Spring", "JSP"},
            names(detected),
        )
        self.assertNotIn("Django", names(detected))

    def test_builtin_detects_frontend_and_server_markers(self):
        fetch = make_fetch(
            headers={"Server": "cloudflare"},
            body='<script src="/_next/static/app.js"></script><div id="root" data-reactroot></div>',
        )

        detected = BuiltinProvider().detect(fetch)

        self.assertLessEqual({"Cloudflare", "Next.js", "React"}, names(detected))

    def test_builtin_detects_frontend_markers_from_script_body(self):
        document = ResourceObservation(
            id="document:0",
            kind="document",
            url="https://example.com",
            final_url="https://example.com",
            status=200,
            headers={},
            cookies={},
            body='<script src="/app.js"></script>',
        )
        script = ResourceObservation(
            id="script:0",
            parent_id=document.id,
            kind="script",
            url="https://example.com/app.js",
            final_url="https://example.com/app.js",
            status=200,
            headers={},
            cookies={},
            body="/* react-dom production */",
        )
        fetch = FetchResult(
            input="example.com",
            url=document.url,
            final_url=document.final_url,
            status=document.status,
            headers=document.headers,
            cookies=document.cookies,
            body=document.body,
            mode="requests",
            script_srcs=[script.url],
            resources=[document, script],
            primary_resource_id=document.id,
        )

        self.assertIn("React", names(BuiltinProvider().detect(fetch)))

    def test_merge_findings_combines_duplicate_provider_evidence(self):
        fetch = make_fetch(headers={"Server": "nginx"})
        finding = BuiltinProvider().detect(fetch)[0]
        duplicate = BuiltinProvider().detect(fetch)[0]
        duplicate.provider = "other"
        duplicate.evidence = ["other evidence"]

        merged = merge_findings([finding, duplicate])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].provider, "builtin,other")
        self.assertEqual(set(merged[0].evidence), {"server header", "other evidence"})

    def test_wappalyzergo_provider_uses_vendored_fingerprints(self):
        data = load_vendored_fingerprints()
        provider = WappalyzerGoProvider(data)

        detected = provider.detect(
            make_fetch(
                headers={"Server": "cloudflare"},
                body='<div data-reactroot></div><script src="react.js"></script>',
            )
        )
        by_name = {finding.name: finding for finding in detected}

        self.assertIn("Cloudflare", by_name)
        self.assertIn("React", by_name)
        self.assertEqual(by_name["Cloudflare"].provider, "wappalyzergo")

    def test_wappalyzergo_provider_has_no_subprocess_dependency(self):
        with patch.object(subprocess, "run") as run_mock:
            WappalyzerGoProvider(
                {
                    "apps": {
                        "Apache": {
                            "cats": [22],
                            "headers": {"server": "Apache"},
                        }
                    }
                }
            ).detect(make_fetch(headers={"Server": "Apache"}))

        run_mock.assert_not_called()

    def test_provider_factory_enables_wappalyzergo_without_command(self):
        providers = build_providers(["wappalyzergo"])

        self.assertEqual([provider.name for provider in providers], ["wappalyzergo"])

    def test_provider_factory_all_includes_wappalyzergo(self):
        providers = build_providers(["all"])

        self.assertLessEqual({"builtin", "wappalyzergo"}, {provider.name for provider in providers})

    def test_wappalyzer_pattern_metadata_parser(self):
        parsed = parse_wappalyzer_pattern(r"react\.js\;confidence:75\;version:\1")

        self.assertEqual(parsed.pattern, r"react\.js")
        self.assertEqual(parsed.confidence, 75)

    def test_url_suffixes_detect_backend_tech(self):
        cases = [
            ("https://example.com/login.aspx", "ASP.NET"),
            ("https://example.com/default.asp", "Classic ASP"),
            ("https://example.com/index.php", "PHP"),
            ("https://example.com/account.jsp", "JSP"),
            ("https://example.com/view.jspx", "JSP"),
            ("https://example.com/login.do", "Java Servlet"),
            ("https://example.com/save.action", "Java Servlet"),
        ]

        for url, expected in cases:
            with self.subTest(url=url):
                detected = BuiltinProvider().detect(make_fetch(url=url))
                self.assertIn(expected, names(detected))

    def test_aspnet_web_forms_markers_are_strong_evidence(self):
        fetch = make_fetch(
            url="https://example.com/default.aspx",
            body='<input type="hidden" name="__VIEWSTATE" value="abc" />'
            '<script src="/WebResource.axd?d=123"></script>',
        )

        detected = BuiltinProvider().detect(fetch)
        by_name = {finding.name: finding for finding in detected}

        self.assertIn("ASP.NET", by_name)
        self.assertIn("ASP.NET Web Forms", by_name)
        self.assertGreater(by_name["ASP.NET Web Forms"].confidence, by_name["ASP.NET"].confidence)

    def test_laravel_cookie_and_csrf_markers(self):
        fetch = make_fetch(
            url="https://example.com/login.php",
            cookies={
                "laravel_session": "eyJpdiI6ImFhYSIsInZhbHVlIjoiYmJiIn0=",
                "XSRF-TOKEN": "eyJpdiI6ImNjYyJ9",
            },
            body='<meta name="csrf-token" content="abc"><input name="_token" value="abc">',
        )

        detected = BuiltinProvider().detect(fetch)
        by_name = {finding.name: finding for finding in detected}

        self.assertIn("PHP", by_name)
        self.assertIn("Laravel", by_name)
        self.assertIn("laravel encrypted cookie", by_name["Laravel"].evidence)

    def test_java_ee_jsf_and_spring_markers(self):
        jsf = make_fetch(
            url="https://example.com/app.xhtml",
            body='<input type="hidden" name="javax.faces.ViewState" value="abc"> PrimeFaces',
        )
        spring = make_fetch(
            headers={"X-Application-Context": "app:prod"},
            body='Whitelabel Error Page <input type="hidden" name="_csrf" value="abc">',
        )

        self.assertLessEqual({"JavaServer Faces", "Java EE/Jakarta EE"}, names(BuiltinProvider().detect(jsf)))
        self.assertLessEqual({"Spring", "Spring Security"}, names(BuiltinProvider().detect(spring)))

    def test_generic_cookie_patterns_do_not_overidentify_frameworks(self):
        detected = BuiltinProvider().detect(
            make_fetch(cookies={"JSESSIONID": "abc", "my_session": "generic"})
        )

        detected_names = names(detected)
        self.assertIn("Java", detected_names)
        self.assertNotIn("Django", detected_names)
        self.assertNotIn("Ruby on Rails", detected_names)

    def test_suffix_only_has_lower_confidence_than_framework_markers(self):
        suffix_only = BuiltinProvider().detect(make_fetch(url="https://example.com/default.aspx"))
        web_forms = BuiltinProvider().detect(
            make_fetch(
                url="https://example.com/default.aspx",
                body='<input type="hidden" name="__VIEWSTATE" value="abc">',
            )
        )

        aspnet_suffix = next(finding for finding in suffix_only if finding.name == "ASP.NET")
        forms_marker = next(finding for finding in web_forms if finding.name == "ASP.NET Web Forms")
        self.assertLess(aspnet_suffix.confidence, forms_marker.confidence)

    def test_wappalyzer_json_provider_matches_supported_fields_and_implies(self):
        with TemporaryDirectory() as tmpdir:
            data_path = Path(tmpdir) / "fingerprints_data.json"
            data_path.write_text(
                json.dumps(
                    {
                        "apps": {
                            "Express": {
                                "cats": [18],
                                "headers": {"x-powered-by": "Express\\;confidence:90"},
                                "implies": ["Node.js\\;confidence:70"],
                            },
                            "Node.js": {"cats": [27]},
                            "React": {"cats": [12], "scriptSrc": ["react(?:\\.min)?\\.js"]},
                            "Cloudflare": {"cats": [31], "headers": {"server": "cloudflare"}},
                            "Apache": {"cats": [22], "html": "Apache Server at"},
                            "Laravel": {
                                "cats": [18],
                                "cookies": {"laravel_session": ""},
                                "meta": {"csrf-token": ""},
                            },
                            "Stripe": {"cats": ["Payment processors"], "html": "stripe"},
                        }
                    }
                ),
                encoding="utf-8",
            )
            provider = WappalyzerJsonProvider(data_path)
            fetch = make_fetch(
                headers={"Server": "cloudflare", "X-Powered-By": "Express"},
                cookies={"laravel_session": "abc"},
                body=(
                    '<meta name="csrf-token" content="abc">'
                    '<script src="/assets/react.min.js"></script>'
                    "Apache Server at example stripe"
                ),
            )

            detected = provider.detect(fetch)
            by_name = {finding.name: finding for finding in detected}

            self.assertLessEqual(
                {"Express", "Node.js", "React", "Cloudflare", "Apache", "Laravel"},
                set(by_name),
            )
            self.assertNotIn("Stripe", by_name)
            self.assertEqual(by_name["Express"].confidence, 90)
            self.assertEqual(by_name["Node.js"].confidence, 70)
            self.assertIn("wappalyzer header: x-powered-by", by_name["Express"].evidence)
            self.assertIn("wappalyzer implied by: Express", by_name["Node.js"].evidence)
            self.assertIn("wappalyzer scriptSrc", by_name["React"].evidence)
            self.assertIn("wappalyzer meta: csrf-token", by_name["Laravel"].evidence)

    def test_wappalyzer_json_provider_uses_categories_data_names(self):
        with TemporaryDirectory() as tmpdir:
            data_path = Path(tmpdir) / "fingerprints_data.json"
            data_path.write_text(
                json.dumps(
                    {
                        "categories": {
                            "999": {"name": "Web frameworks"},
                            "998": {"name": "Analytics"},
                        },
                        "apps": {
                            "Custom Framework": {"cats": ["999"], "html": "custom-framework"},
                            "Analytics Tool": {"cats": ["998"], "html": "analytics-tool"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            provider = WappalyzerJsonProvider(data_path)
            detected = provider.detect(make_fetch(body="custom-framework analytics-tool"))

            self.assertEqual(names(detected), {"Custom Framework"})

    def test_wappalyzer_json_merges_with_builtin(self):
        builtin = BuiltinProvider().detect(make_fetch(headers={"Server": "Apache"}))
        with TemporaryDirectory() as tmpdir:
            data_path = Path(tmpdir) / "fingerprints_data.json"
            data_path.write_text(
                json.dumps({"apps": {"Apache": {"cats": [22], "headers": {"server": "Apache"}}}}),
                encoding="utf-8",
            )
            wappalyzer = WappalyzerJsonProvider(data_path).detect(
                make_fetch(headers={"Server": "Apache"})
            )

        merged = merge_findings([*builtin, *wappalyzer])

        apache = next(finding for finding in merged if finding.name == "Apache")
        self.assertEqual(apache.provider, "builtin,wappalyzer_json")


if __name__ == "__main__":
    unittest.main()
