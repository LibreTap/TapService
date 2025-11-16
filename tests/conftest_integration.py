"""
Integration test configuration - uses real broker certificates.

This module provides fixtures that use the actual CA certificates from
the running Docker environment, enabling full end-to-end mTLS tests.

Usage:
    # Run tests with integration config
    pytest tests/test_provisioning.py::TestMTLSBrokerConnection --integration
    
    # Or set environment variable
    export TAPSERVICE_TEST_INTEGRATION=1
    pytest tests/test_provisioning.py::TestMTLSBrokerConnection
"""
import os
from pathlib import Path
import pytest


def pytest_addoption(parser):
    """Add integration testing option."""
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="Run integration tests with real broker certificates"
    )


def pytest_configure(config):
    """Register integration marker."""
    config.addinivalue_line(
        "markers", "integration: marks tests that require real broker setup"
    )


@pytest.fixture(scope="session")
def use_integration_certs(request):
    """
    Determine whether to use integration certificates.
    
    Returns True if:
    - --integration flag is passed
    - TAPSERVICE_TEST_INTEGRATION=1 environment variable is set
    - Docker volume CA certificates are accessible
    """
    # Check command line flag
    if request.config.getoption("--integration"):
        return True
    
    # Check environment variable
    if os.environ.get("TAPSERVICE_TEST_INTEGRATION") == "1":
        return True
    
    return False


@pytest.fixture(scope="session")
def integration_ca_dir():
    """
    Get path to CA certificates from Docker volume.
    
    This assumes the ca-data volume is mounted or accessible locally.
    Common locations:
    - /var/lib/docker/volumes/tapservice_ca-data/_data (Linux with sudo)
    - Docker Desktop: volume data is in VM
    
    For local development, you can:
    1. Copy certs from container: docker compose cp inventory:/etc/libretap/ca ./test_ca
    2. Set TAPSERVICE_TEST_CA_DIR environment variable
    """
    # Check if user specified CA directory
    ca_dir = os.environ.get("TAPSERVICE_TEST_CA_DIR")
    if ca_dir:
        ca_path = Path(ca_dir)
        if ca_path.exists():
            return ca_path
    
    # Try common Docker volume locations
    possible_paths = [
        Path("./ca"),  # If certs were copied locally
        Path("./test_ca"),  # Alternative local copy location
        Path("/var/lib/docker/volumes/tapservice_ca-data/_data"),  # Linux
    ]
    
    for path in possible_paths:
        if path.exists() and (path / "ca.crt").exists():
            return path
    
    return None


@pytest.fixture(scope="session")
def test_ca_certificate(request, test_ca_dir, use_integration_certs, integration_ca_dir):
    """
    Override default test_ca_certificate to use integration certs when requested.
    
    Falls back to temporary test CA if integration mode is not enabled or
    integration certs are not available.
    """
    if use_integration_certs and integration_ca_dir:
        # Use real broker CA certificates
        cert_path = integration_ca_dir / "ca.crt"
        key_path = integration_ca_dir / "ca.key"
        
        if cert_path.exists() and key_path.exists():
            print(f"\n✅ Using integration CA certificates from: {integration_ca_dir}")
            
            # Load actual certificate and key
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            with open(key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
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
    
    # Fall back to default conftest behavior (temporary test CA)
    # Import and call the original fixture
    from tests.conftest import test_ca_certificate as original_fixture
    yield from original_fixture(test_ca_dir)
