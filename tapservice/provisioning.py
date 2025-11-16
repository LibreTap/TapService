"""
Device provisioning endpoints for CSR-based mTLS certificate issuance.

Handles enrollment token generation, certificate signing, and revocation.
"""
from fastapi import APIRouter, HTTPException, Header
from datetime import datetime, UTC, timedelta
import logging
import secrets
import re

from .certificate_manager import CertificateManager
from .settings import get_settings
from .schemas import (
    EnrollmentTokenRequest,
    EnrollmentTokenResponse,
    ProvisionDeviceRequest,
    ProvisionDeviceResponse,
    RevokeDeviceRequest,
    RevokeDeviceResponse,
    DeviceCertificateInfo,
)

router = APIRouter(prefix="/api/v1", tags=["provisioning"])
logger = logging.getLogger("tapservice.provisioning")

# In-memory storage for enrollment tokens (use Redis/DB in production)
enrollment_tokens: dict[str, dict] = {}

# In-memory storage for registered devices (use database in production)
registered_devices: dict[str, dict] = {}

# Certificate manager singleton
_cert_manager: CertificateManager | None = None


def get_certificate_manager() -> CertificateManager:
    """Get or initialize certificate manager."""
    global _cert_manager
    if _cert_manager is None:
        settings = get_settings()
        try:
            _cert_manager = CertificateManager(
                ca_cert_path=settings.ca_cert_path,
                ca_key_path=settings.ca_key_path,
                crl_path=settings.crl_path
            )
        except Exception as e:
            logger.error(f"Failed to initialize certificate manager: {e}")
            raise HTTPException(
                status_code=500,
                detail="Certificate management unavailable. Check CA certificate configuration."
            )
    return _cert_manager


@router.post(
    "/admin/enrollment-tokens",
    response_model=EnrollmentTokenResponse,
    summary="Generate enrollment token for device provisioning"
)
async def create_enrollment_token(request: EnrollmentTokenRequest):
    """
    Generate time-limited enrollment token for device provisioning.
    
    **Security:** This endpoint should require admin authentication in production.
    Token allows one-time device certificate issuance via CSR signing.
    
    **Workflow:**
    1. Admin generates token via this endpoint
    2. Token printed/displayed as QR code for device setup
    3. Device uses token in Authorization header when submitting CSR
    4. Token invalidated after successful use
    
    **Returns:**
    - Enrollment token (32-byte URL-safe string)
    - Expiration timestamp
    - QR code data for easy scanning
    """
    # Generate cryptographically secure token
    token = secrets.token_urlsafe(32)
    
    # Store token with metadata
    enrollment_tokens[token] = {
        "created_at": datetime.now(UTC),
        "expires_at": datetime.now(UTC) + timedelta(minutes=request.expires_minutes),
        "max_uses": request.max_uses,
        "uses": 0,
        "description": request.description
    }
    
    logger.info(
        f"Generated enrollment token (expires in {request.expires_minutes}m, "
        f"max uses: {request.max_uses})"
    )
    
    # Generate QR code data (JSON for device to parse)
    import json
    settings = get_settings()
    qr_data = json.dumps({
        "token": token,
        "server": settings.device_mqtt_host,
        "expires": enrollment_tokens[token]["expires_at"].isoformat()
    })
    
    return EnrollmentTokenResponse(
        token=token,
        expires_at=enrollment_tokens[token]["expires_at"].isoformat(),
        max_uses=request.max_uses,
        qr_code_data=qr_data
    )


@router.post(
    "/device/provision",
    response_model=ProvisionDeviceResponse,
    summary="Provision device by signing CSR"
)
async def provision_device(
    request: ProvisionDeviceRequest,
    authorization: str | None = Header(None)
):
    """
    Provision device by signing Certificate Signing Request.
    
    **Security Model (CSR-based):**
    1. Device generates RSA/ECC keypair locally (private key NEVER transmitted)
    2. Device creates CSR with public key
    3. Device sends CSR + enrollment token to this endpoint
    4. Service validates token and signs CSR with CA private key
    5. Service returns signed certificate (public only)
    6. Device stores certificate + uses existing private key for mTLS
    
    **Authentication:** Requires valid enrollment token in Authorization header
    
    **Benefits over server-generated certificates:**
    - Private key never leaves device
    - No private key in transit (even encrypted)
    - Aligns with PKI best practices
    - Used by AWS IoT Core, Azure IoT Hub
    
    **Request Body:**
    - `device_id`: Unique device identifier (3-50 alphanumeric chars)
    - `csr_pem`: PEM-encoded Certificate Signing Request
    - `hardware_info`: Optional metadata (MAC address, chip ID, etc.)
    
    **Returns:**
    - Signed device certificate (PEM)
    - CA certificate for trust chain validation
    - MQTT broker connection details (host, TLS port)
    - Certificate expiration date
    """
    # Extract and validate authorization token
    if not authorization or not authorization.startswith("Bearer "):
        logger.warning(f"Provisioning attempt without valid authorization: {request.device_id}")
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid authorization header. Format: Bearer <token>"
        )
    
    token = authorization.replace("Bearer ", "").strip()
    
    # Validate enrollment token
    if token not in enrollment_tokens:
        logger.warning(f"Invalid enrollment token attempted: {token[:8]}...")
        raise HTTPException(
            status_code=403,
            detail="Invalid enrollment token"
        )
    
    token_data = enrollment_tokens[token]
    
    # Check token expiration
    if datetime.now(UTC) > token_data["expires_at"]:
        del enrollment_tokens[token]
        logger.warning(f"Expired enrollment token used: {token[:8]}...")
        raise HTTPException(
            status_code=403,
            detail="Enrollment token expired"
        )
    
    # Check token usage limit
    if token_data["uses"] >= token_data["max_uses"]:
        del enrollment_tokens[token]
        logger.warning(f"Enrollment token max uses exceeded: {token[:8]}...")
        raise HTTPException(
            status_code=403,
            detail="Enrollment token already used"
        )
    
    # Validate device_id format
    if not re.match(r'^[a-zA-Z0-9-_]{3,50}$', request.device_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid device_id format. Use 3-50 alphanumeric characters, hyphens, or underscores."
        )
    
    # Check if device already provisioned
    if request.device_id in registered_devices:
        existing = registered_devices[request.device_id]
        logger.warning(f"Device {request.device_id} already provisioned (serial: {existing['serial_number']})")
        raise HTTPException(
            status_code=409,
            detail=f"Device {request.device_id} already provisioned. Use revoke endpoint first."
        )
    
    # Get certificate manager
    try:
        cert_manager = get_certificate_manager()
    except Exception as e:
        logger.error(f"Certificate manager unavailable: {e}")
        raise HTTPException(
            status_code=503,
            detail="Certificate provisioning service unavailable"
        )
    
    # Sign CSR to issue device certificate
    try:
        settings = get_settings()
        cert_pem, ca_cert_pem, metadata = cert_manager.sign_csr(
            csr_pem=request.csr_pem,
            device_id=request.device_id,
            validity_days=settings.device_cert_validity_days
        )
        
        # Store device registration
        registered_devices[request.device_id] = {
            "provisioned_at": datetime.now(UTC).isoformat(),
            "serial_number": metadata["serial_number"],
            "fingerprint": metadata["fingerprint_sha256"],
            "expires_at": metadata["not_valid_after"],
            "revoked": False,
            "hardware_info": request.hardware_info or {}
        }
        
        # Increment token usage
        token_data["uses"] += 1
        if token_data["uses"] >= token_data["max_uses"]:
            logger.info(f"Enrollment token {token[:8]}... exhausted, removing")
            del enrollment_tokens[token]
        
        logger.info(
            f"✅ Provisioned device {request.device_id} | "
            f"Serial: {metadata['serial_number']} | "
            f"Fingerprint: {metadata['fingerprint_sha256'][:16]}..."
        )
        
        return ProvisionDeviceResponse(
            device_id=request.device_id,
            certificate=cert_pem,
            ca_certificate=ca_cert_pem,
            mqtt_host=settings.device_mqtt_host,
            mqtt_port=settings.mqtt_tls_port,
            expires_at=metadata["not_valid_after"],
            fingerprint=metadata["fingerprint_sha256"]
        )
        
    except ValueError as e:
        logger.error(f"CSR signing failed for {request.device_id}: {e}")
        raise HTTPException(
            status_code=400,
            detail=f"Invalid CSR: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Provisioning failed for {request.device_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Provisioning failed: {str(e)}"
        )


@router.delete(
    "/device/{device_id}/certificate",
    response_model=RevokeDeviceResponse,
    summary="Revoke device certificate"
)
async def revoke_device_certificate(device_id: str, request: RevokeDeviceRequest | None = None):
    """
    Revoke device certificate and add to Certificate Revocation List (CRL).
    
    **Use Cases:**
    - Device compromised or lost
    - Device decommissioned
    - Security incident response
    - Certificate renewal (revoke old, issue new)
    
    **Effect:**
    - Certificate added to CRL
    - MQTT broker will reject connections from this device
    - Device must be re-provisioned with new certificate
    
    **Security:** This endpoint should require admin authentication in production.
    """
    if device_id not in registered_devices:
        raise HTTPException(
            status_code=404,
            detail=f"Device {device_id} not found or not provisioned"
        )
    
    device_info = registered_devices[device_id]
    
    if device_info.get("revoked", False):
        raise HTTPException(
            status_code=400,
            detail=f"Device {device_id} certificate already revoked"
        )
    
    # Get certificate manager
    cert_manager = get_certificate_manager()
    
    # Revoke certificate
    serial_number = device_info["serial_number"]
    success = cert_manager.revoke_certificate(serial_number)
    
    if not success:
        raise HTTPException(
            status_code=500,
            detail="Failed to revoke certificate"
        )
    
    # Update device record
    device_info["revoked"] = True
    device_info["revoked_at"] = datetime.now(UTC).isoformat()
    if request and request.reason:
        device_info["revocation_reason"] = request.reason
    
    logger.warning(
        f"🚫 Revoked certificate for device {device_id} | "
        f"Serial: {serial_number} | "
        f"Reason: {request.reason if request else 'Not specified'}"
    )
    
    return RevokeDeviceResponse(
        device_id=device_id,
        serial_number=serial_number,
        status="revoked",
        message="Device certificate revoked successfully. Device will be unable to connect via mTLS."
    )


@router.get(
    "/device/{device_id}/certificate",
    response_model=DeviceCertificateInfo,
    summary="Get device certificate information"
)
async def get_device_certificate_info(device_id: str):
    """
    Retrieve certificate information for a provisioned device.
    
    **Returns:**
    - Serial number
    - SHA256 fingerprint
    - Issuance and expiration dates
    - Revocation status
    - Certificate subject
    """
    if device_id not in registered_devices:
        raise HTTPException(
            status_code=404,
            detail=f"Device {device_id} not found or not provisioned"
        )
    
    device_info = registered_devices[device_id]
    
    return DeviceCertificateInfo(
        device_id=device_id,
        serial_number=device_info["serial_number"],
        fingerprint=device_info["fingerprint"],
        issued_at=device_info["provisioned_at"],
        expires_at=device_info["expires_at"],
        revoked=device_info.get("revoked", False),
        subject=f"CN={device_id},O=LibreTap,OU=TapReader"
    )


@router.get(
    "/ca/certificate",
    summary="Get CA certificate"
)
async def get_ca_certificate():
    """
    Get CA certificate in PEM format.
    
    Devices and clients can use this to verify the certificate chain.
    This is a public endpoint as CA certificates are not secret.
    """
    cert_manager = get_certificate_manager()
    ca_cert_pem = cert_manager.get_ca_certificate_pem()
    
    return {
        "ca_certificate": ca_cert_pem,
        "format": "PEM"
    }
