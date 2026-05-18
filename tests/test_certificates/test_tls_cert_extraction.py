from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from easm.pivot.handlers import _certificate_to_raw_dict


def test_certificate_to_raw_dict_extracts_tls_certificate_fields():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "app.example.invalid"),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuer"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Test CA"),
        ]))
        .public_key(key.public_key())
        .serial_number(0xA1B2C3D4)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("app.example.invalid"),
                x509.DNSName("www.example.invalid"),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    raw = _certificate_to_raw_dict(cert, "app.example.invalid", 443)

    assert raw["hostname"] == "app.example.invalid"
    assert raw["port"] == 443
    assert raw["cert"]["subject_cn"] == "app.example.invalid"
    assert raw["cert"]["issuer_cn"] == "Test Issuer"
    assert raw["cert"]["issuer_org"] == "Example Test CA"
    assert raw["cert"]["serial_number"] == "a1b2c3d4"
    assert raw["cert"]["not_before"] == cert.not_valid_before_utc.isoformat()
    assert raw["cert"]["not_after"] == cert.not_valid_after_utc.isoformat()
    assert raw["cert"]["fingerprint_sha256"] == cert.fingerprint(hashes.SHA256()).hex()
    assert "app.example.invalid" in raw["cert"]["san_dns_names"]
    assert raw["cert"]["public_key_algorithm"] == "RSA"
    assert raw["cert"]["public_key_size_bits"] == 2048
    assert raw["cert"]["signature_hash_algorithm"] == "sha256"
    assert raw["cert"]["is_ca"] is False
    assert set(raw["cert"]["key_usage"]) == {"digital_signature", "key_encipherment"}
    assert raw["cert"]["extended_key_usage"] == ["server_auth"]
