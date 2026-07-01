import unittest

from tech_scan.models import Observation, ScanResult, TechnologyResult


class ModelResultTests(unittest.TestCase):
    def test_scan_result_to_json_emits_output_schema(self):
        result = ScanResult(
            input="example.com",
            url="https://example.com",
            final_url="https://example.com",
            status=200,
            mode="requests",
            providers=["builtin"],
            cached=True,
            cache_lookup="hit",
            cache_stored=None,
            cache_reason=None,
            cache_created_at=1710000000,
            cache_updated_at=1710000100,
            observations=[
                Observation(kind="header", name="Server", value="example"),
            ],
            technologies=[
                TechnologyResult(
                    name="Apache",
                    dimension="cdn_waf_server",
                    provider="builtin",
                    confidence=90,
                    evidence=["Server: Apache"],
                ),
            ],
            error=None,
        )

        self.assertEqual(
            list(result.to_json()),
            [
                "input",
                "url",
                "final_url",
                "status",
                "mode",
                "providers",
                "cached",
                "cache_lookup",
                "cache_stored",
                "cache_reason",
                "cache_created_at",
                "cache_updated_at",
                "observations",
                "technologies",
                "error",
            ],
        )
        self.assertEqual(
            result.to_json()["observations"],
            [{"kind": "header", "name": "Server", "value": "example"}],
        )
        self.assertEqual(result.to_json()["technologies"][0]["name"], "Apache")

    def test_validation_error_result_is_not_cache_applicable(self):
        result = ScanResult.validation_error(
            "example.com:8080",
            "requests",
            ["builtin"],
            "scheme is required",
        )

        self.assertEqual(result.cache_lookup, "not_applicable")
        self.assertIsNone(result.cache_stored)
        self.assertIsNone(result.cache_reason)
        self.assertEqual(result.observations, [])
        self.assertEqual(result.technologies, [])
        self.assertIn("scheme is required", result.error)

    def test_observation_and_technology_json_wire_shape(self):
        observation = Observation(kind="auto", name="browser_fallback_failed", value="failed")
        technology = TechnologyResult(
            name="nginx",
            dimension="cdn_waf_server",
            provider="builtin",
            confidence=90,
            evidence=["Server: nginx"],
        )

        self.assertEqual(
            observation.to_json(),
            {"kind": "auto", "name": "browser_fallback_failed", "value": "failed"},
        )
        self.assertEqual(
            technology.to_json(),
            {
                "name": "nginx",
                "dimension": "cdn_waf_server",
                "provider": "builtin",
                "confidence": 90,
                "evidence": ["Server: nginx"],
            },
        )
