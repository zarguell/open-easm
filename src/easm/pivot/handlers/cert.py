"""Certificate pivot handlers.

* ``crtsh_search`` — historical certificate transparency search via crt.sh
* ``tls_cert_grab``— live TLS handshake + cert parse against a hostname
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import socket
import ssl
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from easm.network_guard import create_guard_client, resolve_and_validate

logger = logging.getLogger(__name__)


def _certificate_to_raw_dict(
    cert: x509.Certificate, hostname: str, port: int,
) -> dict[str, Any]:
    try:
        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        subject_cn = ""
    try:
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        issuer_cn = ""
    try:
        issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    except (IndexError, Exception):
        issuer_org = ""

    san_dns_names: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_dns_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        logger.debug("certificate has no SubjectAlternativeName extension")

    public_key = cert.public_key()
    public_key_algorithm = type(public_key).__name__
    public_key_size_bits = getattr(public_key, "key_size", None)
    public_key_curve: str | None = None
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key_algorithm = "RSA"
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key_algorithm = "DSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key_algorithm = "EC"
        public_key_curve = public_key.curve.name

    signature_hash_algorithm = ""
    if cert.signature_hash_algorithm is not None:
        signature_hash_algorithm = cert.signature_hash_algorithm.name.lower()
    signature_algorithm = getattr(
        cert.signature_algorithm_oid,
        "_name",
        cert.signature_algorithm_oid.dotted_string,
    )

    is_ca = False
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = basic_constraints.value.ca
    except x509.ExtensionNotFound:
        logger.debug("certificate has no BasicConstraints extension")

    key_usage: list[str] = []
    try:
        usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if usage.digital_signature:
            key_usage.append("digital_signature")
        if usage.content_commitment:
            key_usage.append("content_commitment")
        if usage.key_encipherment:
            key_usage.append("key_encipherment")
        if usage.data_encipherment:
            key_usage.append("data_encipherment")
        if usage.key_agreement:
            key_usage.append("key_agreement")
            if usage.encipher_only:
                key_usage.append("encipher_only")
            if usage.decipher_only:
                key_usage.append("decipher_only")
        if usage.key_cert_sign:
            key_usage.append("key_cert_sign")
        if usage.crl_sign:
            key_usage.append("crl_sign")
    except x509.ExtensionNotFound:
        logger.debug("certificate has no KeyUsage extension")

    extended_key_usage: list[str] = []
    try:
        usages = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        if ExtendedKeyUsageOID.SERVER_AUTH in usages:
            extended_key_usage.append("server_auth")
    except x509.ExtensionNotFound:
        logger.debug("certificate has no ExtendedKeyUsage extension")

    cert_dict: dict[str, Any] = {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "issuer_org": issuer_org,
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "san_dns_names": san_dns_names,
        "public_key_algorithm": public_key_algorithm,
        "public_key_size_bits": public_key_size_bits,
        "public_key_curve": public_key_curve,
        "signature_algorithm": signature_algorithm,
        "signature_hash_algorithm": signature_hash_algorithm,
        "is_ca": is_ca,
        "key_usage": key_usage,
        "extended_key_usage": extended_key_usage,
    }
    return {"hostname": hostname, "port": port, "cert": cert_dict}


async def tls_cert_grab(job: dict[str, Any], pool: Any) -> list[dict[str, Any]]:
    hostname = job["entity_value"]

    guard = resolve_and_validate(hostname)
    if not guard.safe:
        logger.debug("TLS cert grab blocked for %s: %s", hostname, guard.reason)
        return [{"hostname": hostname, "message": f"blocked by network guard: {guard.reason}"}]

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
    return [_certificate_to_raw_dict(cert, hostname, port)]


async def crtsh_search(
    job: dict[str, Any],
    pool: Any,
    *,
    http_client: httpx.AsyncClient | None = None,
    limiters: Any = None,
) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    max_retries = 3
    retry_statuses = (429, 502, 503, 504)
    sem = limiters.crtsh if limiters else None
    if sem:
        await sem.acquire()
    try:
        if http_client is not None:
            certs = await _crtsh_fetch(http_client, url, domain, max_retries, retry_statuses)
        else:
            async with create_guard_client(timeout=30.0) as client:
                certs = await _crtsh_fetch(client, url, domain, max_retries, retry_statuses)
    finally:
        if sem:
            sem.release()
    return [{
        "name_value": c.get("name_value", ""),
        "issuer_name_id": c.get("issuer_name_id", ""),
        "not_before": c.get("not_before", ""),
        "not_after": c.get("not_after", ""),
        "serial_number": c.get("serial_number", ""),
        "fingerprint": c.get("fingerprint", ""),
    } for c in certs]


async def _crtsh_fetch(
    client: httpx.AsyncClient,
    url: str,
    domain: str,
    max_retries: int,
    retry_statuses: tuple[int, ...],
) -> list[dict[str, Any]]:
    """Fetch + retry crt.sh JSON. Raises ``RuntimeError`` on terminal failure."""
    certs: list[dict[str, Any]] | None = None
    for attempt in range(max_retries):
        try:
            resp = await client.get(url)
        except (httpx.ReadTimeout, httpx.ConnectError, httpx.NetworkError) as e:
            wait = (2 ** attempt) + random.uniform(0, 1)
            logger.warning("crtsh request failed (%s) for %s, retrying %.1fs",
                           type(e).__name__, domain, wait)
            if attempt < max_retries - 1:
                await asyncio.sleep(wait)
                continue
            break
        if resp.status_code == 200:
            certs = resp.json()
            break
        if resp.status_code in retry_statuses:
            retry_after = resp.headers.get("Retry-After")
            wait = float(retry_after) if retry_after else (2 ** attempt) + random.uniform(0, 1)
            logger.warning("crtsh rate limited (status %d) for %s, retrying %.1fs",
                           resp.status_code, domain, wait)
            if attempt < max_retries - 1:
                await asyncio.sleep(wait)
                continue
            break
        resp.raise_for_status()
    if certs is None:
        raise RuntimeError("crtsh request failed after all retries")
    return certs
