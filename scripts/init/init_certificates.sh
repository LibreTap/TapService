#!/bin/sh
set -e

echo "=== LibreTap Certificate Initialization ==="

# Generate all certificates using the unified Python script
cd /app
/app/.venv/bin/python3 scripts/setup/generate_certificates.py --all

# Set ownership for different services
echo "⚙️  Setting certificate permissions..."

# CA directory - accessible by app user (1000)
if [ -d "/etc/libretap/ca" ]; then
    chown -R 1000:1000 /etc/libretap/ca
fi

# Broker certs - accessible by mosquitto user (1883)
if [ -d "/mosquitto/certs" ]; then
    chown -R 1883:1883 /mosquitto/certs
fi

# Service certs - accessible by app user (1000)
if [ -d "/etc/libretap/service" ]; then
    chown -R 1000:1000 /etc/libretap/service
fi

echo "✅ Certificate initialization complete"
