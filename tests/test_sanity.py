import io
import socket
import unittest
from unittest.mock import patch

from tech_scan.diagnostics import Diagnostics
from tech_scan.sanity import check_target_ports, derive_port_target


def addrinfo(ip, port, family=socket.AF_INET):
    return (family, socket.SOCK_STREAM, 6, "", (ip, port))


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None


class SanityTests(unittest.TestCase):
    def test_derives_ports_from_input_shape(self):
        cases = [
            ("http://example.com/path", "http://example.com/path", "example.com", (80,)),
            ("https://example.com/path", "https://example.com/path", "example.com", (443,)),
            ("https://example.com:8443/path", "https://example.com:8443/path", "example.com", (8443,)),
            ("https://[2001:db8::1]/", "https://[2001:db8::1]", "2001:db8::1", (443,)),
            ("http://[2001:db8::1]:8080/", "http://[2001:db8::1]:8080", "2001:db8::1", (8080,)),
        ]

        for raw, normalized, host, ports in cases:
            with self.subTest(raw=raw):
                target = derive_port_target(raw, normalized)
                self.assertEqual(target.host, host)
                self.assertEqual(target.ports, ports)

    def test_succeeds_when_any_ip_port_connects(self):
        def connect(address, timeout):
            if address == ("192.0.2.2", 443):
                return FakeSocket()
            raise OSError("closed")

        with patch(
            "tech_scan.sanity.socket.getaddrinfo",
            return_value=[
                addrinfo("192.0.2.1", 443),
                addrinfo("192.0.2.2", 443),
            ],
        ):
            with patch("tech_scan.sanity.socket.create_connection", side_effect=connect):
                result = check_target_ports("https://example.com", "https://example.com", 1)

        self.assertTrue(result.ok)
        self.assertEqual(result.open_ip, "192.0.2.2")
        self.assertEqual(result.open_port, 443)
        self.assertEqual(result.attempts, ("192.0.2.1:443", "192.0.2.2:443"))

    def test_fails_when_dns_resolution_fails(self):
        with patch(
            "tech_scan.sanity.socket.getaddrinfo",
            side_effect=socket.gaierror("no host"),
        ):
            result = check_target_ports("example.com", "http://example.com", 1)

        self.assertEqual(result.status, "dns-error")
        self.assertIn("DNS resolution failed", result.error)

    def test_fails_when_all_connection_attempts_fail(self):
        with patch(
            "tech_scan.sanity.socket.getaddrinfo",
            return_value=[addrinfo("192.0.2.1", 80)],
        ):
            with patch("tech_scan.sanity.socket.create_connection", side_effect=OSError("closed")):
                result = check_target_ports("example.com", "http://example.com", 1)

        self.assertEqual(result.status, "no-open-port")
        self.assertIn("no open port", result.error)
        self.assertEqual(result.ports, (80,))

    def test_tries_a_and_aaaa_results(self):
        with patch(
            "tech_scan.sanity.socket.getaddrinfo",
            return_value=[
                addrinfo("192.0.2.1", 443),
                addrinfo("2001:db8::1", 443, socket.AF_INET6),
            ],
        ):
            with patch("tech_scan.sanity.socket.create_connection", side_effect=OSError("closed")):
                result = check_target_ports("https://example.com", "https://example.com", 1)

        self.assertEqual(result.attempts, ("192.0.2.1:443", "2001:db8::1:443"))

    def test_verbosity_logs_attempt_details(self):
        stderr = io.StringIO()
        diagnostics = Diagnostics(verbosity=3, stream=stderr)
        with patch(
            "tech_scan.sanity.socket.getaddrinfo",
            return_value=[addrinfo("192.0.2.1", 443)],
        ):
            with patch("tech_scan.sanity.socket.create_connection", side_effect=OSError("closed")):
                check_target_ports(
                    "https://example.com",
                    "https://example.com",
                    1,
                    diagnostics=diagnostics,
                )

        logs = stderr.getvalue()
        self.assertIn("sanity resolved", logs)
        self.assertIn("sanity connect start: 192.0.2.1:443", logs)
        self.assertIn("sanity connect failed: 192.0.2.1:443", logs)


if __name__ == "__main__":
    unittest.main()
