"""
Certificate management for LibreTap device provisioning.

Handles:
- CA certificate operations
- CSR signing for device certificates
- Certificate Revocation List (CRL) management
- Certificate validation and expiration tracking
"""
import logging
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Optional, Tuple
import hashlib

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("tapservice.certificate")


class CertificateManager:
    """
    Manages device certificate lifecycle for LibreTap.
    
    Implements CSR-based provisioning where:
    - Device generates private key locally (never transmitted)
    - Device sends CSR to service
    - Service signs CSR with CA private key
    - Device receives signed certificate
    """
    
    def __init__(self, ca_cert_path: str, ca_key_path: str, crl_path: Optional[str] = None):
        """
        Initialize certificate manager with CA credentials.
        
        Args:
            ca_cert_path: Path to CA certificate (PEM format)
            ca_key_path: Path to CA private key (PEM format)
            crl_path: Path to Certificate Revocation List (optional)
        """
        self.ca_cert_path = Path(ca_cert_path)
        self.ca_key_path = Path(ca_key_path)
        self.crl_path = Path(crl_path) if crl_path else None
        
        self.ca_cert: Optional[x509.Certificate] = None
        self.ca_key = None
        self.revoked_serials: set[int] = set()
        
        self._load_ca_credentials()
        if self.crl_path and self.crl_path.exists():
            self._load_crl()
    
    def _load_ca_credentials(self):
        """Load CA certificate and private key from disk."""
        try:
            # Load CA certificate
            if not self.ca_cert_path.exists():
                raise FileNotFoundError(f"CA certificate not found: {self.ca_cert_path}")
            
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            # Load CA private key
            if not self.ca_key_path.exists():
                raise FileNotFoundError(f"CA private key not found: {self.ca_key_path}")
            
            with open(self.ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,  # TODO: Support encrypted keys in production
                    backend=default_backend()
                )
            
            logger.info(f"✅ Loaded CA certificate: {self.ca_cert.subject.rfc4514_string()}")
            logger.info(f"   Valid until: {self.ca_cert.not_valid_after_utc}")
            
        except Exception as e:
            logger.error(f"Failed to load CA credentials: {e}")
            raise
    
    def _load_crl(self):
        """Load Certificate Revocation List from disk."""
        try:
            if not self.crl_path.exists():
                return
            
            with open(self.crl_path, "rb") as f:
                crl = x509.load_pem_x509_crl(f.read(), default_backend())
            
            # Extract revoked serial numbers
            for revoked_cert in crl:
                self.revoked_serials.add(revoked_cert.serial_number)
            
            logger.info(f"Loaded CRL with {len(self.revoked_serials)} revoked certificates")
            
        except Exception as e:
            logger.warning(f"Failed to load CRL: {e}")
    
    def sign_csr(
        self,
        csr_pem: str,
        device_id: str,
        validity_days: int = 365
    ) -> Tuple[str, str, dict]:
        """
        Sign a Certificate Signing Request to issue device certificate.
        
        Args:
            csr_pem: PEM-encoded CSR from device
            device_id: Unique device identifier
            validity_days: Certificate validity period (default 1 year)
        
        Returns:
            Tuple of (certificate_pem, ca_certificate_pem, metadata)
        
        Raises:
            ValueError: If CSR is invalid or device_id is malformed
        """
        try:
            # Parse CSR
            csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
            
            # Validate CSR signature
            if not csr.is_signature_valid:
                raise ValueError("CSR signature validation failed")
            
            # Extract public key
            public_key = csr.public_key()
            
            # Build subject for device certificate
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, device_id),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LibreTap"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "TapReader"),
            ])
            
            # Generate serial number
            serial_number = x509.random_serial_number()
            
            # Calculate validity period
            not_valid_before = datetime.now(UTC)
            not_valid_after = not_valid_before + timedelta(days=validity_days)
            
            # Build certificate
            cert_builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(self.ca_cert.subject)
                .public_key(public_key)
                .serial_number(serial_number)
                .not_valid_before(not_valid_before)
                .not_valid_after(not_valid_after)
            )
            
            # Add Subject Alternative Name (SAN)
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(f"{device_id}.libretap.local"),
                    x509.DNSName(device_id),
                ]),
                critical=False
            )
            
            # Add Key Usage (client authentication only)
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            
            # Add Extended Key Usage (explicitly for client auth)
            cert_builder = cert_builder.add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True
            )
            
            # Add Authority Key Identifier
            cert_builder = cert_builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_cert.public_key()
                ),
                critical=False
            )
            
            # Add Subject Key Identifier
            cert_builder = cert_builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False
            )
            
            # Sign certificate with CA private key
            certificate = cert_builder.sign(self.ca_key, hashes.SHA256(), default_backend())
            
            # Serialize to PEM
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
            ca_cert_pem = self.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
            
            # Calculate fingerprint
            fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
            
            # Build metadata
            metadata = {
                "serial_number": serial_number,
                "fingerprint_sha256": fingerprint,
                "not_valid_before": not_valid_before.isoformat(),
                "not_valid_after": not_valid_after.isoformat(),
                "subject": certificate.subject.rfc4514_string(),
                "issuer": certificate.issuer.rfc4514_string(),
            }
            
            logger.info(f"✅ Signed certificate for device {device_id}")
            logger.info(f"   Serial: {serial_number}")
            logger.info(f"   Fingerprint: {fingerprint[:16]}...")
            logger.info(f"   Valid: {validity_days} days")
            
            return cert_pem, ca_cert_pem, metadata
            
        except Exception as e:
            logger.error(f"Failed to sign CSR for {device_id}: {e}")
            raise ValueError(f"CSR signing failed: {str(e)}")
    
    def revoke_certificate(self, serial_number: int) -> bool:
        """
        Add certificate to revocation list.
        
        Args:
            serial_number: Serial number of certificate to revoke
        
        Returns:
            True if successfully revoked
        """
        try:
            self.revoked_serials.add(serial_number)
            self._update_crl()
            
            logger.warning(f"🚫 Revoked certificate with serial {serial_number}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke certificate {serial_number}: {e}")
            return False
    
    def _update_crl(self):
        """Update Certificate Revocation List file."""
        if not self.crl_path:
            logger.warning("CRL path not configured, skipping CRL update")
            return
        
        try:
            # Build revoked certificate list
            revoked_certs = []
            for serial in self.revoked_serials:
                revoked_cert = (
                    x509.RevokedCertificateBuilder()
                    .serial_number(serial)
                    .revocation_date(datetime.now(UTC))
                    .build(default_backend())
                )
                revoked_certs.append(revoked_cert)
            
            # Build CRL
            crl_builder = x509.CertificateRevocationListBuilder()
            crl_builder = crl_builder.issuer_name(self.ca_cert.subject)
            crl_builder = crl_builder.last_update(datetime.now(UTC))
            crl_builder = crl_builder.next_update(datetime.now(UTC) + timedelta(days=7))
            
            for revoked in revoked_certs:
                crl_builder = crl_builder.add_revoked_certificate(revoked)
            
            # Sign CRL
            crl = crl_builder.sign(self.ca_key, hashes.SHA256(), default_backend())
            
            # Write to disk
            self.crl_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.crl_path, "wb") as f:
                f.write(crl.public_bytes(serialization.Encoding.PEM))
            
            logger.info(f"Updated CRL with {len(self.revoked_serials)} revoked certificates")
            
        except Exception as e:
            logger.error(f"Failed to update CRL: {e}")
    
    def is_revoked(self, serial_number: int) -> bool:
        """Check if certificate is revoked."""
        return serial_number in self.revoked_serials
    
    def validate_certificate(self, cert_pem: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a device certificate.
        
        Args:
            cert_pem: PEM-encoded certificate
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            
            # Check if expired
            now = datetime.now(UTC)
            if now < cert.not_valid_before_utc:
                return False, "Certificate not yet valid"
            if now > cert.not_valid_after_utc:
                return False, "Certificate expired"
            
            # Check if revoked
            if self.is_revoked(cert.serial_number):
                return False, "Certificate revoked"
            
            # Verify signature (issued by our CA)
            try:
                self.ca_cert.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    cert.signature_algorithm_parameters
                )
            except Exception:
                return False, "Certificate signature verification failed"
            
            return True, None
            
        except Exception as e:
            return False, f"Certificate validation error: {str(e)}"
    
    def get_ca_certificate_pem(self) -> str:
        """Get CA certificate in PEM format."""
        return self.ca_cert.public_bytes(serialization.Encoding.PEM).decode()


def generate_ca_certificate(
    common_name: str = "LibreTap Certificate Authority",
    validity_days: int = 3650,
    output_cert_path: str = "ca.crt",
    output_key_path: str = "ca.key"
) -> Tuple[str, str]:
    """
    Generate a self-signed CA certificate for LibreTap.
    
    This function is used during initial setup to create the root CA.
    
    Args:
        common_name: Common Name for CA certificate
        validity_days: CA validity period (default 10 years)
        output_cert_path: Path to save CA certificate
        output_key_path: Path to save CA private key
    
    Returns:
        Tuple of (cert_pem, key_pem)
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    
    # Build CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LibreTap"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
    ])
    
    not_valid_before = datetime.now(UTC)
    not_valid_after = not_valid_before + timedelta(days=validity_days)
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    # Serialize to PEM
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    # Write to files
    Path(output_cert_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_cert_path, "w") as f:
        f.write(cert_pem)
    
    Path(output_key_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_key_path, "w") as f:
        f.write(key_pem)
    
    # Set restrictive permissions on private key
    Path(output_key_path).chmod(0o600)
    
    logger.info(f"✅ Generated CA certificate: {common_name}")
    logger.info(f"   Certificate: {output_cert_path}")
    logger.info(f"   Private key: {output_key_path}")
    logger.info(f"   Valid for: {validity_days} days")
    
    return cert_pem, key_pem
