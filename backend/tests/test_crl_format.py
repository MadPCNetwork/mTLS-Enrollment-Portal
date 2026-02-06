
import pytest
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from app.crypto import generate_crl
from app.config import X509CAConfig

# Mock configuration
class MockX509CAConfig:
    def __init__(self, cert_path, key_path, key_password):
        self.cert_path = cert_path
        self.key_path = key_path
        self.key_password = key_password
        self.id = "test-ca"
        self.name = "Test CA"

@pytest.fixture
def mock_ca_files(tmp_path):
    # Generate a self-signed CA for testing
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Test CA"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=10)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(key, hashes.SHA256())

    # Save to files
    cert_path = tmp_path / "ca.crt"
    key_path = tmp_path / "ca.key"
    
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    return MockX509CAConfig(str(cert_path), str(key_path), None)

def test_generate_crl_returns_pem(mock_ca_files):
    # Setup revoked certs
    revoked_certs = [
        (12345, datetime.utcnow(), "key_compromise"),
    ]
    
    # Generate CRL
    crl_bytes = generate_crl(mock_ca_files, revoked_certs)
    
    # Check if it starts with PEM header
    assert crl_bytes.startswith(b"-----BEGIN X509 CRL-----"), "CRL should be in PEM format"
    assert crl_bytes.endswith(b"-----END X509 CRL-----\n"), "CRL should be in PEM format"
