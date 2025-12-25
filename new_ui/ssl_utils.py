"""
[MCP Context] SSL Certificate Generation Utility
================================================
Purpose: Generate self-signed SSL certificates at first startup
Security: Ensures HTTPS communication for production deployments
"""

import os
import logging
import ipaddress
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

def generate_self_signed_cert(
    cert_dir="certs",
    cert_file="cert.pem",
    key_file="key.pem",
    validity_days=365,
    common_name="promere.local"
):
    """
    Generate a self-signed SSL certificate if it doesn't exist.

    Args:
        cert_dir: Directory to store certificates
        cert_file: Certificate filename
        key_file: Private key filename
        validity_days: Certificate validity period
        common_name: CN for the certificate

    Returns:
        tuple: (cert_path, key_path) or (None, None) on error
    """

    os.makedirs(cert_dir, exist_ok=True)
    cert_path = os.path.join(cert_dir, cert_file)
    key_path = os.path.join(cert_dir, key_file)

    # Check if certificate already exists
    if os.path.exists(cert_path) and os.path.exists(key_path):
        logger.info(f"SSL certificate already exists at {cert_path}")
        return cert_path, key_path

    try:
        logger.info("Generating self-signed SSL certificate...")

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Create certificate builder
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Ile-de-France"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Promere"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(common_name),
                    x509.DNSName("localhost"),
                    x509.DNSName("*.localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),  # 127.0.0.1
                ]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        # Write private key
        with open(key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Write certificate
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Set restrictive permissions
        os.chmod(key_path, 0o600)
        os.chmod(cert_path, 0o644)

        logger.info(f"SSL certificate generated successfully:")
        logger.info(f"  Certificate: {cert_path}")
        logger.info(f"  Private Key: {key_path}")
        logger.info(f"  Valid for: {validity_days} days")
        logger.info(f"  Common Name: {common_name}")

        return cert_path, key_path

    except Exception as e:
        logger.error(f"Failed to generate SSL certificate: {e}", exc_info=True)
        return None, None
