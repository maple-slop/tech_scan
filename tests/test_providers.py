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

    def test_builtin_detects_wappalyzer_informed_server_signatures(self):
        cases = [
            ({"Server": "openresty/1.25.3"}, "OpenResty", "Server: openresty/1.25.3"),
            ({"Server": "Tengine"}, "Tengine", "Server: Tengine"),
            ({"Server": "Caddy"}, "Caddy", "Server: Caddy"),
            ({"Server": "lighttpd/1.4.76"}, "lighttpd", "Server: lighttpd/1.4.76"),
            ({"Server": "gunicorn/22.0.0"}, "gunicorn", "Server: gunicorn/22.0.0"),
            ({"Server": "Werkzeug/3.0.0 Python/3.12"}, "Werkzeug", "Server: Werkzeug/3.0.0 Python/3.12"),
            ({"Server": "CherryPy/18.9.0"}, "CherryPy", "Server: CherryPy/18.9.0"),
            ({"Server": "WebLogic Server 14"}, "WebLogic", "Server: WebLogic Server 14"),
            ({"Server": "GSE"}, "OpenGSE", "Server: GSE"),
            ({"Server": "BigIP"}, "F5 BIG-IP", "Server: BigIP"),
            ({"X-CDN": "Imperva"}, "Imperva", "X-CDN: Imperva"),
            ({"X-NF-Request-ID": "01ABC"}, "Netlify", "X-NF-Request-ID: 01ABC"),
            ({"X-Vercel-Id": "iad1::abc"}, "Vercel", "X-Vercel-Id: iad1::abc"),
            ({"Via": "1.1 vegur"}, "Heroku", "Via: 1.1 vegur"),
            ({"Server": "AmazonS3"}, "Amazon S3", "Server: AmazonS3"),
            ({"X-LiteSpeed-Cache": "hit"}, "LiteSpeed Cache", "X-LiteSpeed-Cache: hit"),
        ]

        for headers, expected, evidence in cases:
            with self.subTest(expected=expected):
                by_name = {finding.name: finding for finding in BuiltinProvider().detect(make_fetch(headers=headers))}
                self.assertIn(expected, by_name)
                self.assertIn(evidence, by_name[expected].evidence)

    def test_builtin_detects_wappalyzer_informed_backend_signatures(self):
        cases = [
            (make_fetch(headers={"Server": "Werkzeug/3.0.0 Python/3.12"}), {"Flask", "Python"}),
            (make_fetch(headers={"Server": "Ruby/3.3.0"}), {"Ruby"}),
            (make_fetch(headers={"X-Powered-By": "Koa"}), {"Koa", "Node.js"}),
            (make_fetch(headers={"X-Powered-By": "hono"}), {"Hono", "Node.js"}),
            (make_fetch(headers={"X-Powered-By": "Sails"}), {"Sails.js", "Node.js"}),
            (make_fetch(headers={"X-Powered-By": "total.js"}), {"total.js"}),
            (make_fetch(headers={"X-Powered-By": "bun"}), {"Bun"}),
            (make_fetch(cookies={"sf_redirect": "1"}), {"Symfony", "PHP"}),
            (make_fetch(cookies={"ci_session": "1"}), {"CodeIgniter", "PHP"}),
            (make_fetch(cookies={"cakephp": "1"}), {"CakePHP", "PHP"}),
            (make_fetch(cookies={"yii_csrf_token": "1"}), {"Yii", "PHP"}),
            (make_fetch(body='<div wire:click="save"></div>'), {"Livewire", "PHP"}),
            (make_fetch(cookies={"CFTOKEN": "secret"}, body='<script src="/cfajax/foo.js"></script>'), {"Adobe ColdFusion"}),
        ]

        for fetch, expected in cases:
            with self.subTest(expected=expected):
                self.assertLessEqual(expected, names(BuiltinProvider().detect(fetch)))

    def test_builtin_detects_wappalyzer_informed_frontend_signatures(self):
        cases = [
            (make_fetch(body='<html ng-app="app"></html>'), "AngularJS"),
            (make_fetch(body='<div x-data="{open:false}"></div>'), "Alpine.js"),
            (make_fetch(body='<meta name="generator" content="Astro v4.0.0">'), "Astro"),
            (make_fetch(body='<div data-controller="hello"></div>'), "Stimulus"),
            (make_fetch(body='<script src="/htmx.min.js"></script>'), "htmx"),
            (make_fetch(body='<link rel="import" href="/polymer.html">'), "Polymer"),
            (make_fetch(globals_=["__remixContext"]), "Remix"),
            (make_fetch(body='<meta name="generator" content="SvelteKit">'), "SvelteKit"),
        ]

        for fetch, expected in cases:
            with self.subTest(expected=expected):
                self.assertIn(expected, names(BuiltinProvider().detect(fetch)))

    def test_builtin_implied_runtime_does_not_come_from_generic_headers(self):
        generic = BuiltinProvider().detect(
            make_fetch(headers={"X-Powered-By": "SomethingCustom", "Server": "WeirdServer/9.9"})
        )

        detected_names = names(generic)
        self.assertNotIn("Node.js", detected_names)
        self.assertNotIn("PHP", detected_names)
        self.assertNotIn("Ruby", detected_names)
        self.assertNotIn("Python", detected_names)

    def test_builtin_cookie_value_rules_still_do_not_expose_raw_values(self):
        detected = BuiltinProvider().detect(
            make_fetch(cookies={"laravel_session": "eyJpdiI6InNlY3JldCJ9"})
        )
        laravel = next(finding for finding in detected if finding.name == "Laravel")

        self.assertNotIn("eyJpdiI6InNlY3JldCJ9", "\n".join(laravel.evidence))

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

    def test_wappalyzergo_dom_exists_matches_captured_html(self):
        provider = WappalyzerGoProvider(
            {
                "apps": {
                    "Svelte": {
                        "cats": [12],
                        "dom": {"[class*='svelte-']": {"exists": r"\;confidence:88"}},
                    }
                }
            }
        )

        detected = provider.detect(make_fetch(body='<main class="page svelte-abc"></main>'))
        by_name = {finding.name: finding for finding in detected}

        self.assertIn("Svelte", by_name)
        self.assertEqual(by_name["Svelte"].confidence, 88)
        self.assertIn("wappalyzer dom: [class*='svelte-']", by_name["Svelte"].evidence)

    def test_wappalyzergo_dom_text_matches_selected_node_text(self):
        provider = WappalyzerGoProvider(
            {
                "apps": {
                    "Apereo CAS": {
                        "cats": [18],
                        "dom": {"head > title": {"text": "Central Authentication Service"}},
                    }
                }
            }
        )

        detected = provider.detect(
            make_fetch(body="<html><head><title>CAS - Central Authentication Service</title></head></html>")
        )

        self.assertIn("Apereo CAS", names(detected))

    def test_wappalyzergo_dom_attributes_match_selected_node_attributes(self):
        provider = WappalyzerGoProvider(
            {
                "apps": {
                    "Angular": {
                        "cats": [12],
                        "dom": {"[ng-version]": {"attributes": {"ng-version": r"^17\.\;confidence:91"}}},
                    }
                }
            }
        )

        detected = provider.detect(make_fetch(body='<app-root ng-version="17.3.2"></app-root>'))
        by_name = {finding.name: finding for finding in detected}

        self.assertIn("Angular", by_name)
        self.assertEqual(by_name["Angular"].confidence, 91)

    def test_wappalyzergo_dom_empty_attribute_pattern_requires_attribute_presence(self):
        provider = WappalyzerGoProvider(
            {
                "apps": {
                    "SvelteKit": {
                        "cats": [66],
                        "dom": {
                            "a,body": {
                                "attributes": {
                                    "data-sveltekit-preload-data": "",
                                    "sveltekit:prefetch": "",
                                }
                            }
                        },
                        "implies": ["Svelte", "Node.js"],
                    },
                    "Svelte": {"cats": [12]},
                    "Node.js": {"cats": [27]},
                }
            }
        )

        detected = provider.detect(make_fetch(body="<body><a href='/post'>post</a></body>"))

        self.assertEqual(detected, [])

    def test_wappalyzergo_dom_direct_attribute_key_matches_selected_node_attributes(self):
        provider = WappalyzerGoProvider(
            {
                "apps": {
                    "GetYourGuide": {
                        "cats": [12],
                        "dom": {"img.hero": {"src": "cdn\\.getyourguide\\.com"}},
                    }
                }
            }
        )

        detected = provider.detect(
            make_fetch(body='<img class="hero" src="https://cdn.getyourguide.com/tour.jpg">')
        )

        self.assertIn("GetYourGuide", names(detected))

    def test_wappalyzergo_dom_invalid_selectors_are_ignored(self):
        provider = WappalyzerGoProvider(
            {
                "apps": {
                    "Broken Selector": {
                        "cats": [12],
                        "dom": {"div[": {"exists": ""}},
                    },
                    "Valid Selector": {
                        "cats": [12],
                        "dom": {".valid": {"exists": ""}},
                    },
                }
            }
        )

        detected = provider.detect(make_fetch(body='<div class="valid"></div>'))

        self.assertEqual(names(detected), {"Valid Selector"})

    def test_wappalyzergo_dom_properties_do_not_match_static_html(self):
        provider = WappalyzerGoProvider(
            {
                "apps": {
                    "React": {
                        "cats": [12],
                        "dom": {"body > div": {"properties": {"_reactRootContainer": ""}}},
                    }
                }
            }
        )

        detected = provider.detect(make_fetch(body="<body><div></div></body>"))

        self.assertEqual(detected, [])

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
