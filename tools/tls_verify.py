#!/usr/bin/env python3
"""Fetch a server certificate and show which names it can validate."""

from __future__ import annotations

import argparse
import ipaddress
import socket
import ssl
import sys
import tempfile
from typing import Any, Iterable


Certificate = dict[str, Any]


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def select_server_hostname(target: str, sni: str | None) -> str | None:
    if sni:
        return sni
    if is_ip_address(target):
        return None
    return target


def fetch_peer_certificate(
    target: str,
    port: int,
    sni: str | None = None,
    timeout: float = 5.0,
) -> Certificate:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    server_hostname = select_server_hostname(target, sni)
    with socket.create_connection((target, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=server_hostname) as tls_sock:
            certificate = decode_peer_certificate(tls_sock)

    if not certificate:
        raise RuntimeError("Peer did not provide a readable certificate.")

    return certificate


def decode_der_certificate(der_certificate: bytes) -> Certificate:
    pem_certificate = ssl.DER_cert_to_PEM_cert(der_certificate)
    with tempfile.NamedTemporaryFile("w", encoding="ascii", delete=False) as tmp:
        tmp.write(pem_certificate)
        cert_path = tmp.name

    try:
        return ssl._ssl._test_decode_cert(cert_path)
    finally:
        try:
            import os

            os.unlink(cert_path)
        except OSError:
            pass


def decode_peer_certificate(tls_socket: ssl.SSLSocket) -> Certificate:
    certificate = tls_socket.getpeercert()
    if certificate:
        return certificate

    der_certificate = tls_socket.getpeercert(binary_form=True)
    if not der_certificate:
        raise RuntimeError("Peer did not provide a readable certificate.")

    return decode_der_certificate(der_certificate)


def _append_unique(values: list[str], seen: set[str], items: Iterable[str]) -> None:
    for item in items:
        if item not in seen:
            seen.add(item)
            values.append(item)


def extract_verifiable_names(certificate: Certificate) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()

    for name_type, value in certificate.get("subjectAltName", ()):
        if name_type in {"DNS", "IP Address"}:
            _append_unique(names, seen, [value])

    if names:
        return names

    common_names = []
    for name_group in certificate.get("subject", ()):
        for key, value in name_group:
            if key == "commonName":
                common_names.append(value)

    _append_unique(names, seen, common_names)
    return names


def _to_idna_ascii(value: str) -> str:
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return value


def _dnsname_match(pattern: str, hostname: str) -> bool:
    pattern = _to_idna_ascii(pattern)
    hostname = _to_idna_ascii(hostname)

    if not pattern:
        return False

    wildcards = pattern.count("*")
    if not wildcards:
        return pattern.lower() == hostname.lower()

    if wildcards > 1:
        raise ssl.CertificateError(
            f"too many wildcards in certificate DNS name: {pattern!r}.",
        )

    leftmost, separator, remainder = pattern.partition(".")
    if "*" in remainder:
        raise ssl.CertificateError(
            "wildcard can only be present in the leftmost label: "
            f"{pattern!r}.",
        )

    if not separator:
        raise ssl.CertificateError(
            f"sole wildcard without additional labels is not supported: {pattern!r}.",
        )

    if leftmost != "*":
        raise ssl.CertificateError(
            "partial wildcards in leftmost label are not supported: "
            f"{pattern!r}.",
        )

    hostname_leftmost, hostname_separator, hostname_remainder = hostname.partition(".")
    if not hostname_leftmost or not hostname_separator:
        return False

    return remainder.lower() == hostname_remainder.lower()


def _ipaddress_match(pattern: str, hostname: str) -> bool:
    try:
        return ipaddress.ip_address(pattern.rstrip()) == ipaddress.ip_address(hostname)
    except ValueError:
        return False


def certificate_matches_name(certificate: Certificate, domain: str) -> tuple[bool, str | None]:
    subject_alt_names = certificate.get("subjectAltName", ())

    if is_ip_address(domain):
        ip_names = [value for name_type, value in subject_alt_names if name_type == "IP Address"]
        for ip_name in ip_names:
            if _ipaddress_match(ip_name, domain):
                return True, None
        if ip_names:
            listed = ", ".join(repr(name) for name in ip_names)
            return False, f"hostname {domain!r} doesn't match any certificate IP addresses: {listed}"
        return False, f"hostname {domain!r} doesn't match any certificate IP addresses"

    dns_names = [value for name_type, value in subject_alt_names if name_type == "DNS"]
    for dns_name in dns_names:
        try:
            if _dnsname_match(dns_name, domain):
                return True, None
        except ssl.CertificateError as exc:
            return False, str(exc)
    if dns_names:
        listed = ", ".join(repr(name) for name in dns_names)
        return False, f"hostname {domain!r} doesn't match any certificate DNS names: {listed}"

    common_names = []
    for name_group in certificate.get("subject", ()):
        for key, value in name_group:
            if key == "commonName":
                common_names.append(value)

    for common_name in common_names:
        try:
            if _dnsname_match(common_name, domain):
                return True, None
        except ssl.CertificateError as exc:
            return False, str(exc)

    if common_names:
        listed = ", ".join(repr(name) for name in common_names)
        return False, f"hostname {domain!r} doesn't match commonName entries: {listed}"

    return False, "certificate has no subjectAltName or commonName entries"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Show the names listed in a server certificate and optionally validate one.",
    )
    parser.add_argument("target", help="Host or IP to connect to.")
    parser.add_argument(
        "domain",
        nargs="?",
        help="Optional domain/name to validate against the certificate.",
    )
    parser.add_argument(
        "--domain",
        dest="domain_option",
        help="Optional domain/name to validate against the certificate.",
    )
    parser.add_argument(
        "--sni",
        help="Optional SNI value to send during the TLS handshake.",
    )
    parser.add_argument("--port", type=int, default=443, help="TLS port. Default: 443.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Connect timeout in seconds. Default: 5.",
    )
    args = parser.parse_args(argv)

    if args.domain and args.domain_option:
        parser.error("Pass the domain either positionally or with --domain, not both.")

    args.domain = args.domain_option or args.domain
    del args.domain_option
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        certificate = fetch_peer_certificate(
            target=args.target,
            port=args.port,
            sni=args.sni,
            timeout=args.timeout,
        )
    except Exception as exc:
        print(f"TLS check failed: {exc}", file=sys.stderr)
        return 2

    names = extract_verifiable_names(certificate)

    print(f"Connected to {args.target}:{args.port}")
    print("Verifiable names:")
    if names:
        for name in names:
            print(f"- {name}")
    else:
        print("- <none found in SAN/CN>")

    if not args.domain:
        return 0

    matched, reason = certificate_matches_name(certificate, args.domain)
    print(f"Validation for {args.domain}: {'PASS' if matched else 'FAIL'}")
    if reason:
        print(f"Reason: {reason}")
    return 0 if matched else 1


if __name__ == "__main__":
    raise SystemExit(main())
