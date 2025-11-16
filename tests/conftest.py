"""
Pytest configuration and fixtures for TapService tests.
"""
import os
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from tapservice.main import app
from tapservice.session_manager import get_session_manager
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone


@pytest.fixture
def client(test_ca_certificate):
    """
    Create test client with CA certificate configured.
    The test_ca_certificate fixture sets up environment variables automatically.
    """
    # Reset the certificate manager singleton to pick up new env vars
    import tapservice.provisioning as prov_module
    prov_module._cert_manager = None
    
    return TestClient(app)


@pytest.fixture
def session_manager():
    """Get session manager instance."""
    return get_session_manager()


@pytest.fixture(autouse=True)
def reset_session_manager():
    """Reset session manager state before each test."""
    manager = get_session_manager()
    manager._operation_sessions.clear()
    manager._device_states.clear()
    manager._event_queue = None
    yield
    manager._operation_sessions.clear()
    manager._device_states.clear()
    manager._event_queue = None


@pytest.fixture(scope="session")
def test_ca_dir():
    """Create a temporary directory for test CA certificates."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture(scope="session")
def test_ca_certificate(test_ca_dir):
    """
    Generate a test CA certificate for the test session.
    This runs once per test session and sets environment variables.
    
    If TAPSERVICE_TEST_CA_DIR is set, uses those certificates instead of
    generating temporary ones (for integration testing).
    """
    # Check if integration CA directory is specified
    integration_ca_dir = os.environ.get("TAPSERVICE_TEST_CA_DIR")
    if integration_ca_dir:
        ca_path = Path(integration_ca_dir)
        cert_path = ca_path / "ca.crt"
        key_path = ca_path / "ca.key"
        
        if cert_path.exists() and key_path.exists():
            print(f"\n✅ Using integration CA certificates from: {integration_ca_dir}")
            
            # Load actual certificate and key
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            
            with open(key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            
            # Set environment variables
            os.environ["TAPSERVICE_CA_CERT_PATH"] = str(cert_path)
            os.environ["TAPSERVICE_CA_KEY_PATH"] = str(key_path)
            
            yield {
                "cert_path": cert_path,
                "key_path": key_path,
                "certificate": cert,
                "private_key": private_key,
            }
            
            # Cleanup
            os.environ.pop("TAPSERVICE_CA_CERT_PATH", None)
            os.environ.pop("TAPSERVICE_CA_KEY_PATH", None)
            return
    
    # Generate temporary test CA
    # Generate CA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Test City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LibreTap Test CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "LibreTap Test Root CA"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(private_key, hashes.SHA256())
    
    # Write certificate and key to temporary directory
    cert_path = test_ca_dir / "ca.crt"
    key_path = test_ca_dir / "ca.key"
    
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Set environment variables for the test session
    os.environ["TAPSERVICE_CA_CERT_PATH"] = str(cert_path)
    os.environ["TAPSERVICE_CA_KEY_PATH"] = str(key_path)
    
    yield {
        "cert_path": cert_path,
        "key_path": key_path,
        "certificate": cert,
        "private_key": private_key,
    }
    
    # Cleanup environment variables
    os.environ.pop("TAPSERVICE_CA_CERT_PATH", None)
    os.environ.pop("TAPSERVICE_CA_KEY_PATH", None)
