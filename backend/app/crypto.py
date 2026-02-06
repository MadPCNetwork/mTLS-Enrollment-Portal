"""
Cryptographic operations for X.509 certificate management.
Handles CSR parsing, certificate signing, and CRL generation.
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    CertificateBuilder,
    CertificateRevocationListBuilder,
    Name,
    NameAttribute,
    RevokedCertificateBuilder,
)
from cryptography.x509.oid import ExtensionOID, NameOID

from .auth import UserClaims
from .config import X509CAConfig, get_config


# Mapping of X.509 attribute names to OIDs
X509_ATTRIBUTE_OIDS = {
    "CN": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "SN": NameOID.SURNAME,
    "GN": NameOID.GIVEN_NAME,
    "UID": NameOID.USER_ID,
    "EMAIL": NameOID.EMAIL_ADDRESS,
    "SERIALNUMBER": NameOID.SERIAL_NUMBER,
    "T": NameOID.TITLE,
    "DC": NameOID.DOMAIN_COMPONENT,
}


def load_ca_certificate(ca_config: X509CAConfig) -> x509.Certificate:
    """Load a CA certificate from file."""
    with open(ca_config.cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_ca_private_key(ca_config: X509CAConfig):
    """Load a CA private key from file."""
    with open(ca_config.key_path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=ca_config.key_password,
        )


def parse_csr(csr_pem: str) -> x509.CertificateSigningRequest:
    """Parse a PEM-encoded CSR."""
    return x509.load_pem_x509_csr(csr_pem.encode())


def build_subject_from_claims(user_claims: UserClaims) -> Name:
    """
    Build X.509 subject from OIDC claims using the configured mapping.
    
    Rules:
    1. Static values are always written.
    2. Mapped values are only written if the claim exists and is non-empty.
    3. If a claim is a list, multiple RDNs are created for that attribute.
    """
    config = get_config()
    subject_config = config.subject_attributes
    name_attributes = []
    
    # Add static attributes first (these are always included)
    for attr_name, value in subject_config.static.items():
        if value and attr_name in X509_ATTRIBUTE_OIDS:
            oid = X509_ATTRIBUTE_OIDS[attr_name]
            name_attributes.append(NameAttribute(oid, value))
    
    # Add mapped attributes (only if claim exists and is non-empty)
    for attr_name, claim_name in subject_config.mapping.items():
        if attr_name not in X509_ATTRIBUTE_OIDS:
            continue
        
        oid = X509_ATTRIBUTE_OIDS[attr_name]
        claim_value = user_claims.get_claim(claim_name)
        
        if claim_value is None:
            continue
        
        # Handle list values (e.g., groups -> multiple OU entries)
        if isinstance(claim_value, list):
            for item in claim_value:
                if item:  # Skip empty strings
                    name_attributes.append(NameAttribute(oid, str(item)))
        elif isinstance(claim_value, str) and claim_value.strip():
            name_attributes.append(NameAttribute(oid, claim_value.strip()))
        elif claim_value:  # Non-empty, non-string value
            name_attributes.append(NameAttribute(oid, str(claim_value)))
    
    return Name(name_attributes)


def build_san_from_claims(user_claims: UserClaims) -> Optional[x509.SubjectAlternativeName]:
    """Build Subject Alternative Names from claims if configured."""
    config = get_config()
    san_config = config.san_mapping
    general_names = []
    
    # Email SAN
    if san_config.email:
        email = user_claims.get_claim(san_config.email)
        if email and isinstance(email, str):
            general_names.append(x509.RFC822Name(email))
    
    # Static DNS names
    if san_config.dns:
        for dns_name in san_config.dns:
            if dns_name:
                general_names.append(x509.DNSName(dns_name))
    
    # URI SAN
    if san_config.uri:
        uri = user_claims.get_claim(san_config.uri)
        if uri and isinstance(uri, str):
            general_names.append(x509.UniformResourceIdentifier(uri))
    
    if general_names:
        return x509.SubjectAlternativeName(general_names)
    return None


def generate_serial_number() -> int:
    """Generate a cryptographically random serial number."""
    return secrets.randbits(128)


def sign_csr(
    csr_pem: str,
    ca_config: X509CAConfig,
    user_claims: UserClaims,
    ttl_hours: int = 720,
) -> tuple[x509.Certificate, str]:
    """
    Sign a CSR with the CA, enforcing the subject from OIDC claims.
    
    Returns:
        Tuple of (certificate object, PEM-encoded certificate string)
    """
    # Parse the CSR
    csr = parse_csr(csr_pem)
    
    # Verify CSR signature
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    
    # Load CA
    ca_cert = load_ca_certificate(ca_config)
    ca_key = load_ca_private_key(ca_config)
    
    # Build the subject from claims (ignore CSR subject entirely)
    subject = build_subject_from_claims(user_claims)
    
    # Build the certificate
    now = datetime.utcnow()
    serial = generate_serial_number()
    
    builder = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(hours=ttl_hours))
    )
    
    # Add standard extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    
    # Add Extended Key Usage for Client Authentication (OID 1.3.6.1.5.5.7.3.2)
    # Required for Authentik to verify mTLS certificates
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=False,
    )
    
    # Add Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False,
    )
    
    # Add Authority Key Identifier
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False,
    )
    
    # Add SAN if configured
    san = build_san_from_claims(user_claims)
    if san:
        builder = builder.add_extension(san, critical=False)
    
    # Sign the certificate
    certificate = builder.sign(ca_key, hashes.SHA256())
    
    # Export to PEM
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    
    return certificate, cert_pem


def get_ca_chain_pem(ca_config: X509CAConfig) -> str:
    """Get the CA certificate chain as PEM."""
    with open(ca_config.cert_path, "r") as f:
        return f.read()


def generate_crl(
    ca_config: X509CAConfig,
    revoked_certs: list[tuple[int, datetime, Optional[str]]],
) -> bytes:
    """
    Generate a CRL for the given CA.
    
    Args:
        ca_config: The CA configuration
        revoked_certs: List of (serial_number, revocation_time, reason)
    
    Returns:
        DER-encoded CRL
    """
    ca_cert = load_ca_certificate(ca_config)
    ca_key = load_ca_private_key(ca_config)
    
    now = datetime.utcnow()
    
    builder = (
        CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=1))  # Update daily
    )
    
    # Add revoked certificates
    for serial, revoked_at, reason in revoked_certs:
        revoked_builder = (
            RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(revoked_at)
        )
        
        # Add reason extension if provided
        if reason:
            reason_map = {
                "unspecified": x509.ReasonFlags.unspecified,
                "key_compromise": x509.ReasonFlags.key_compromise,
                "ca_compromise": x509.ReasonFlags.ca_compromise,
                "affiliation_changed": x509.ReasonFlags.affiliation_changed,
                "superseded": x509.ReasonFlags.superseded,
                "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
                "certificate_hold": x509.ReasonFlags.certificate_hold,
                "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
                "aa_compromise": x509.ReasonFlags.aa_compromise,
            }
            if reason.lower() in reason_map:
                revoked_builder = revoked_builder.add_extension(
                    x509.CRLReason(reason_map[reason.lower()]),
                    critical=False,
                )
        
        builder = builder.add_revoked_certificate(revoked_builder.build())
    
    # Sign the CRL
    crl = builder.sign(ca_key, hashes.SHA256())
    
    return crl.public_bytes(serialization.Encoding.PEM)


def format_subject_string(subject: Name) -> str:
    """Format an X.509 Name as a DN string."""
    parts = []
    for attr in subject:
        # Find the short name for this OID
        short_name = None
        for name, oid in X509_ATTRIBUTE_OIDS.items():
            if oid == attr.oid:
                short_name = name
                break
        if short_name:
            parts.append(f"{short_name}={attr.value}")
        else:
            parts.append(f"{attr.oid.dotted_string}={attr.value}")
    return ", ".join(parts)
