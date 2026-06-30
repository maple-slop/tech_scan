import unittest
from unittest.mock import patch
import subprocess

from tech_scan.models import FetchResult, ResourceObservation
from tech_scan.providers import (
    BuiltinProvider,
    WappalyzerGoProvider,
    build_providers,
    merge_findings,
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
        self.assertEqual(set(merged[0].evidence), {"Server: nginx", "other evidence"})

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

    def test_wappalyzer_pattern_metadata_affects_provider_confidence(self):
        provider = WappalyzerGoProvider(
            {
                "apps": {
                    "React": {
                        "cats": [12],
                        "scriptSrc": [r"react\.js\;confidence:75\;version:\1"],
                    }
                }
            }
        )

        detected = provider.detect(make_fetch(body='<script src="/react.js"></script>'))

        self.assertEqual(detected[0].name, "React")
        self.assertEqual(detected[0].confidence, 75)

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

    def test_aspnet_x_powered_by_is_generic_not_core(self):
        fetch = make_fetch(
            headers={
                "Server": "Microsoft-IIS/10.0",
                "X-Powered-By": "ASP.NET",
            }
        )

        detected = BuiltinProvider().detect(fetch)
        detected_names = names(detected)

        self.assertIn("ASP.NET", detected_names)
        self.assertIn("Microsoft IIS", detected_names)
        self.assertNotIn("ASP.NET Core", detected_names)
        by_name = {finding.name: finding for finding in detected}
        self.assertIn("Server: Microsoft-IIS/10.0", by_name["Microsoft IIS"].evidence)
        self.assertIn("X-Powered-By: ASP.NET", by_name["ASP.NET"].evidence)

    def test_aspnet_core_detects_kestrel_and_core_cookie(self):
        detected = BuiltinProvider().detect(
            make_fetch(
                headers={"Server": "Kestrel"},
                cookies={".AspNetCore.Session": "abc"},
            )
        )
        by_name = {finding.name: finding for finding in detected}

        self.assertIn("ASP.NET Core", by_name)
        self.assertIn("Server: Kestrel", by_name["ASP.NET Core"].evidence)
        self.assertIn("cookie: .AspNetCore.Session", by_name["ASP.NET Core"].evidence)

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
        self.assertNotIn(
            "eyJpdiI6ImFhYSIsInZhbHVlIjoiYmJiIn0=",
            "\n".join(by_name["Laravel"].evidence),
        )

    def test_generic_csrf_token_meta_does_not_identify_laravel_or_rails(self):
        detected = BuiltinProvider().detect(
            make_fetch(body='<meta name="csrf-token" content="abc">')
        )

        detected_names = names(detected)
        self.assertNotIn("Laravel", detected_names)
        self.assertNotIn("Ruby on Rails", detected_names)

    def test_rails_specific_markers(self):
        fetch = make_fetch(
            headers={"X-Powered-By": "Phusion Passenger (mod_rails/mod_rack) 3.0.19"},
            cookies={"_session_id": "abc"},
            body=(
                '<meta name="csrf-param" content="authenticity_token">'
                '<meta name="csrf-token" content="abc">'
                '<script src="/assets/application-0123456789abcdef0123456789abcdef.js"></script>'
            ),
            globals_=["_rails_loaded"],
        )

        detected = BuiltinProvider().detect(fetch)
        by_name = {finding.name: finding for finding in detected}

        self.assertIn("Ruby on Rails", by_name)
        self.assertIn("rails csrf param meta", by_name["Ruby on Rails"].evidence)
        self.assertIn("rails asset pipeline script", by_name["Ruby on Rails"].evidence)
        self.assertIn(
            "X-Powered-By: Phusion Passenger (mod_rails/mod_rack) 3.0.19",
            by_name["Ruby on Rails"].evidence,
        )
        self.assertIn("cookie: _session_id", by_name["Ruby on Rails"].evidence)
        self.assertIn("window global: _rails_loaded", by_name["Ruby on Rails"].evidence)

    def test_phusion_passenger_header_detects_passenger_and_rails(self):
        detected = BuiltinProvider().detect(
            make_fetch(headers={"X-Powered-By": "Phusion Passenger (mod_rails/mod_rack) 3.0.19"})
        )
        by_name = {finding.name: finding for finding in detected}

        self.assertIn("Phusion Passenger", by_name)
        self.assertIn("Ruby on Rails", by_name)
        self.assertIn(
            "X-Powered-By: Phusion Passenger (mod_rails/mod_rack) 3.0.19",
            by_name["Phusion Passenger"].evidence,
        )

    def test_same_host_embedded_url_suffixes_detect_backend_tech(self):
        fetch = make_fetch(
            url="https://example.com/home",
            body=(
                '<a href="/admin/index.php">admin</a>'
                '<form action="https://example.com/save.action"></form>'
                '<script src="/account.jsp"></script>'
                '<a href="https://other.test/default.aspx">external</a>'
            ),
        )

        detected = BuiltinProvider().detect(fetch)
        by_name = {finding.name: finding for finding in detected}

        self.assertIn("PHP", by_name)
        self.assertIn("Java Servlet", by_name)
        self.assertIn("JSP", by_name)
        self.assertNotIn("ASP.NET", by_name)
        self.assertIn("same-host embedded url: https://example.com/admin/index.php", by_name["PHP"].evidence)

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

    def test_wappalyzergo_provider_matches_supported_fields_and_implies(self):
        provider = WappalyzerGoProvider(
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
        )
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

    def test_wappalyzergo_provider_uses_categories_data_names(self):
        provider = WappalyzerGoProvider(
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
        )
        detected = provider.detect(make_fetch(body="custom-framework analytics-tool"))

        self.assertEqual(names(detected), {"Custom Framework"})

    def test_wappalyzergo_merges_with_builtin(self):
        builtin = BuiltinProvider().detect(make_fetch(headers={"Server": "Apache"}))
        wappalyzer = WappalyzerGoProvider(
            {"apps": {"Apache": {"cats": [22], "headers": {"server": "Apache"}}}}
        ).detect(make_fetch(headers={"Server": "Apache"}))

        merged = merge_findings([*builtin, *wappalyzer])

        apache = next(finding for finding in merged if finding.name == "Apache")
        self.assertEqual(apache.provider, "builtin,wappalyzergo")


if __name__ == "__main__":
    unittest.main()
