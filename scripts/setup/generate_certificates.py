#!/usr/bin/env python3
"""
Generate certificates for LibreTap MQTT infrastructure.

This script generates:
- CA certificate (root certificate authority)
- Broker certificate (for Mosquitto TLS server)
- Service certificate (for TapService client authentication)

Usage:
    # Generate all certificates (Docker)
    python scripts/setup/generate_certificates.py --all
    
    # Generate only CA
    python scripts/setup/generate_certificates.py --ca-only
    
    # Generate broker and service certs (requires existing CA)
    python scripts/setup/generate_certificates.py --skip-ca
"""
import argparse
import sys
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta, UTC
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from tapservice.certificate_manager import generate_ca_certificate


def generate_broker_certificate(ca_cert_path: Path, ca_key_path: Path, output_dir: Path) -> bool:
    """Generate broker TLS certificate signed by CA."""
    print("⚙️  Generating broker certificate...")
    
    broker_cert_path = output_dir / "broker.crt"
    broker_key_path = output_dir / "broker.key"
    
    # Check if already exists
    if broker_cert_path.exists() and broker_key_path.exists():
        print(f"✅ Broker certificate already exists: {broker_cert_path}")
        return True
    
    # Load CA certificate and key
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
    # Generate broker private key
    broker_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Build broker certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mqtt-broker"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LibreTap"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "MQTT Broker"),
    ])
    
    broker_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        broker_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(UTC)
    ).not_valid_after(
        datetime.now(UTC) + timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("mqtt-broker"),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    ).add_extension(
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    # Write broker private key
    with open(broker_key_path, "wb") as f:
        f.write(broker_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write broker certificate
    with open(broker_cert_path, "wb") as f:
        f.write(broker_cert.public_bytes(serialization.Encoding.PEM))
    
    # Set permissions
    broker_cert_path.chmod(0o644)
    broker_key_path.chmod(0o640)
    
    print(f"✅ Generated broker certificate: {broker_cert_path}")
    return True


def generate_service_certificate(ca_cert_path: Path, ca_key_path: Path, output_dir: Path) -> bool:
    """Generate service client certificate signed by CA."""
    print("⚙️  Generating service certificate...")
    
    service_cert_path = output_dir / "service.crt"
    service_key_path = output_dir / "service.key"
    
    # Check if already exists
    if service_cert_path.exists() and service_key_path.exists():
        print(f"✅ Service certificate already exists: {service_cert_path}")
        return True
    
    # Load CA certificate and key
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
    # Generate service private key
    service_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Build service certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "tapservice"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LibreTap"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "TapService"),
    ])
    
    service_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        service_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(UTC)
    ).not_valid_after(
        datetime.now(UTC) + timedelta(days=3650)
    ).add_extension(
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    # Write service private key
    with open(service_key_path, "wb") as f:
        f.write(service_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write service certificate
    with open(service_cert_path, "wb") as f:
        f.write(service_cert.public_bytes(serialization.Encoding.PEM))
    
    # Set permissions
    service_cert_path.chmod(0o644)
    service_key_path.chmod(0o640)
    
    print(f"✅ Generated service certificate: {service_cert_path}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Generate certificates for LibreTap MQTT infrastructure"
    )
    parser.add_argument(
        "--ca-dir",
        type=str,
        default="/etc/libretap/ca",
        help="Directory for CA certificate and key"
    )
    parser.add_argument(
        "--broker-dir",
        type=str,
        default="/mosquitto/certs",
        help="Directory for broker certificate and key"
    )
    parser.add_argument(
        "--service-dir",
        type=str,
        default="/etc/libretap/service",
        help="Directory for service certificate and key"
    )
    parser.add_argument(
        "--ca-only",
        action="store_true",
        help="Generate only CA certificate"
    )
    parser.add_argument(
        "--skip-ca",
        action="store_true",
        help="Skip CA generation (use existing CA)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Generate all certificates (default)"
    )
    parser.add_argument(
        "--common-name",
        type=str,
        default="LibreTap Docker CA",
        help="Common Name for CA certificate"
    )
    
    args = parser.parse_args()
    
    ca_dir = Path(args.ca_dir)
    broker_dir = Path(args.broker_dir)
    service_dir = Path(args.service_dir)
    
    print("=" * 60)
    print("LibreTap Certificate Generation")
    print("=" * 60)
    
    success = True
    
    # Generate CA certificate
    if not args.skip_ca:
        ca_dir.mkdir(parents=True, exist_ok=True)
        ca_cert_path = ca_dir / "ca.crt"
        ca_key_path = ca_dir / "ca.key"
        
        if ca_cert_path.exists() and ca_key_path.exists():
            print(f"✅ CA certificate already exists: {ca_cert_path}")
        else:
            print("⚙️  Generating CA certificate...")
            try:
                generate_ca_certificate(
                    common_name=args.common_name,
                    validity_days=3650,
                    output_cert_path=str(ca_cert_path),
                    output_key_path=str(ca_key_path)
                )
                print(f"✅ Generated CA certificate: {ca_cert_path}")
            except Exception as e:
                print(f"❌ Failed to generate CA certificate: {e}")
                return 1
    
    # Stop here if CA-only
    if args.ca_only:
        print("=" * 60)
        return 0
    
    # Generate broker and service certificates
    if not args.ca_only:
        ca_cert_path = ca_dir / "ca.crt"
        ca_key_path = ca_dir / "ca.key"
        
        if not ca_cert_path.exists() or not ca_key_path.exists():
            print(f"❌ CA certificate not found at {ca_dir}")
            print("   Run with --ca-only first or ensure CA exists")
            return 1
        
        # Generate broker certificate
        broker_dir.mkdir(parents=True, exist_ok=True)
        if not generate_broker_certificate(ca_cert_path, ca_key_path, broker_dir):
            success = False
        
        # Generate service certificate
        service_dir.mkdir(parents=True, exist_ok=True)
        if not generate_service_certificate(ca_cert_path, ca_key_path, service_dir):
            success = False
    
    print("=" * 60)
    if success:
        print("✅ Certificate generation complete!")
        return 0
    else:
        print("❌ Some certificates failed to generate")
        return 1


if __name__ == "__main__":
    sys.exit(main())
