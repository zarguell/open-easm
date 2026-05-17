from __future__ import annotations

import logging
import ssl
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)


class TlsCertGrabHandler(PivotHandler):
    pivot_type = "tls_cert_grab"
    source_name = "tls_cert"

    async def execute(self, job: dict, pool) -> list[dict]:
        hostname = job["entity_value"]
        port = 443
        timeout = 10

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    der_cert = tls_sock.getpeercert(binary_form=True)
        except (ssl.SSLError, socket.timeout, socket.gaierror, ConnectionError, OSError) as e:
            logger.debug("TLS grab failed for %s: %s", hostname, e)
            return [{"hostname": hostname, "message": f"tls grab failed: {e}"}]

        if not der_cert:
            return [{"hostname": hostname, "message": "no certificate returned"}]

        cert = x509.load_der_x509_certificate(der_cert)

        try:
            subject_cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            subject_cn = ""

        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            issuer_cn = ""
        try:
            issuer_org = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
        except (IndexError, Exception):
            issuer_org = ""

        san_dns_names: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
        serial_number = format(cert.serial_number, "x")
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()

        return [{
            "hostname": hostname,
            "port": port,
            "cert": {
                "subject_cn": subject_cn,
                "issuer_cn": issuer_cn,
                "issuer_org": issuer_org,
                "serial_number": serial_number,
                "not_before": not_before,
                "not_after": not_after,
                "fingerprint_sha256": fingerprint_sha256,
                "san_dns_names": san_dns_names,
            },
        }]
