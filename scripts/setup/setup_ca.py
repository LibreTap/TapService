#!/usr/bin/env python3
"""
Generate CA certificate for LibreTap device provisioning.

Usage:
    # Development (10 year CA)
    python scripts/setup_ca.py --output-dir ./dev-ca
    
    # Production (with custom settings)
    python scripts/setup_ca.py --output-dir /etc/libretap/ca --validity 3650 --common-name "LibreTap Production CA"
"""
import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from tapservice.certificate_manager import generate_ca_certificate


def main():
    parser = argparse.ArgumentParser(
        description="Generate CA certificate for LibreTap device provisioning"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./ca",
        help="Output directory for CA certificate and key (default: ./ca)"
    )
    parser.add_argument(
        "--common-name",
        type=str,
        default="LibreTap Certificate Authority",
        help="Common Name for CA certificate"
    )
    parser.add_argument(
        "--validity",
        type=int,
        default=3650,
        help="Certificate validity in days (default: 3650 = 10 years)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing CA certificate if present"
    )
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    cert_path = output_dir / "ca.crt"
    key_path = output_dir / "ca.key"
    
    # Check if CA already exists
    if cert_path.exists() and not args.force:
        print(f"❌ CA certificate already exists: {cert_path}")
        print("   Use --force to overwrite")
        return 1
    
    print("=" * 60)
    print("LibreTap Certificate Authority Setup")
    print("=" * 60)
    print(f"Common Name: {args.common_name}")
    print(f"Validity:    {args.validity} days ({args.validity // 365} years)")
    print(f"Output Dir:  {output_dir.absolute()}")
    print("=" * 60)
    
    try:
        # Generate CA certificate
        cert_pem, key_pem = generate_ca_certificate(
            common_name=args.common_name,
            validity_days=args.validity,
            output_cert_path=str(cert_path),
            output_key_path=str(key_path)
        )
        
        print()
        print("✅ CA certificate generated successfully!")
        print()
        print("Files created:")
        print(f"  📜 Certificate: {cert_path}")
        print(f"  🔑 Private Key: {key_path} (permissions: 0600)")
        print()
        print("Next steps:")
        print("  1. Configure TapService with CA paths:")
        print(f"     export TAPSERVICE_CA_CERT_PATH={cert_path.absolute()}")
        print(f"     export TAPSERVICE_CA_KEY_PATH={key_path.absolute()}")
        print()
        print("  2. Start TapService:")
        print("     uv run uvicorn tapservice.main:app --reload")
        print()
        print("  3. Generate enrollment token:")
        print("     curl -X POST http://localhost:8000/api/v1/admin/enrollment-tokens")
        print()
        print("  4. Use token on ESP32 device during WiFiManager setup")
        print()
        print("⚠️  SECURITY WARNINGS:")
        print("  • Keep ca.key secure - compromise allows forging device certificates")
        print("  • Back up ca.key securely - loss prevents issuing new certificates")
        print("  • For production: store ca.key on HSM or encrypted volume")
        print("  • Restrict ca.key file permissions (already set to 0600)")
        print()
        
        return 0
        
    except Exception as e:
        print(f"❌ Failed to generate CA certificate: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
