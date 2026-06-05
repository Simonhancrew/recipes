import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

import tls_verify


class TlsVerifyTests(unittest.TestCase):
    def test_select_server_hostname_prefers_explicit_sni(self) -> None:
        self.assertEqual(
            tls_verify.select_server_hostname("114.236.137.40", "agora.io"),
            "agora.io",
        )

    def test_parse_args_keeps_domain_and_sni_separate(self) -> None:
        args = tls_verify.parse_args(
            ["114.236.137.40", "--sni", "agora.io", "--domain", "example.com"],
        )

        self.assertEqual(args.target, "114.236.137.40")
        self.assertEqual(args.sni, "agora.io")
        self.assertEqual(args.domain, "example.com")

    def test_extract_verifiable_names_prefers_san_and_dedupes(self) -> None:
        certificate = {
            "subjectAltName": (
                ("DNS", "*.example.com"),
                ("DNS", "example.com"),
                ("DNS", "*.example.com"),
                ("IP Address", "10.0.0.1"),
            ),
            "subject": ((("commonName", "ignored.example.com"),),),
        }

        self.assertEqual(
            tls_verify.extract_verifiable_names(certificate),
            ["*.example.com", "example.com", "10.0.0.1"],
        )

    def test_extract_verifiable_names_falls_back_to_common_name(self) -> None:
        certificate = {
            "subject": ((("commonName", "legacy.example.com"),),),
        }

        self.assertEqual(
            tls_verify.extract_verifiable_names(certificate),
            ["legacy.example.com"],
        )

    def test_certificate_matches_name_accepts_wildcard(self) -> None:
        certificate = {
            "subjectAltName": (
                ("DNS", "*.example.com"),
                ("DNS", "example.com"),
            ),
        }

        matched, reason = tls_verify.certificate_matches_name(certificate, "api.example.com")

        self.assertTrue(matched)
        self.assertIsNone(reason)

    def test_certificate_matches_name_rejects_mismatch(self) -> None:
        certificate = {
            "subjectAltName": (("DNS", "example.com"),),
        }

        matched, reason = tls_verify.certificate_matches_name(certificate, "agora.io")

        self.assertFalse(matched)
        self.assertIn("doesn't match any certificate DNS names", reason)

    def test_certificate_matches_ip_address(self) -> None:
        certificate = {
            "subjectAltName": (("IP Address", "10.0.0.1"),),
        }

        matched, reason = tls_verify.certificate_matches_name(certificate, "10.0.0.1")

        self.assertTrue(matched)
        self.assertIsNone(reason)

    def test_decode_peer_certificate_uses_der_when_plain_cert_is_empty(self) -> None:
        fake_socket = mock.Mock()
        fake_socket.getpeercert.side_effect = [{}, b"fake-der"]

        expected = {"subjectAltName": (("DNS", "example.com"),)}
        with mock.patch("tls_verify.decode_der_certificate", return_value=expected) as decode_der:
            decoded = tls_verify.decode_peer_certificate(fake_socket)

        self.assertEqual(decoded, expected)
        decode_der.assert_called_once_with(b"fake-der")

    @mock.patch("tls_verify.fetch_peer_certificate")
    def test_main_lists_names_without_domain(self, fetch_peer_certificate: mock.Mock) -> None:
        fetch_peer_certificate.return_value = {
            "subjectAltName": (("DNS", "example.com"),),
        }

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = tls_verify.main(["192.0.2.10"])

        self.assertEqual(exit_code, 0)
        self.assertIn("Connected to 192.0.2.10:443", stdout.getvalue())
        self.assertIn("- example.com", stdout.getvalue())

    @mock.patch("tls_verify.fetch_peer_certificate")
    def test_main_reports_failed_validation(self, fetch_peer_certificate: mock.Mock) -> None:
        fetch_peer_certificate.return_value = {
            "subjectAltName": (("DNS", "example.com"),),
        }

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = tls_verify.main(
                ["192.0.2.10", "--sni", "agora.io", "--domain", "agora.io"],
            )

        self.assertEqual(exit_code, 1)
        self.assertIn("Validation for agora.io: FAIL", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
