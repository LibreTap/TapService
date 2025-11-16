#!/bin/bash
# Setup Mosquitto authentication for internal service connection

PASSWD_FILE="mosquitto_passwd"

echo "=== Mosquitto Authentication Setup ==="
echo ""

# Check if mosquitto_passwd command is available
if ! command -v mosquitto_passwd &> /dev/null; then
    echo "⚠️  mosquitto_passwd command not found."
    echo "   Install mosquitto clients: sudo apt-get install mosquitto-clients"
    echo ""
    echo "   Or run this inside the mosquitto container:"
    echo "   docker compose exec mqtt-broker mosquitto_passwd -c /mosquitto/config/passwd tapservice"
    exit 1
fi

# Generate password file
echo "Creating password file for user 'tapservice'..."
mosquitto_passwd -c "$PASSWD_FILE" tapservice

echo ""
echo "✅ Password file created: $PASSWD_FILE"
echo ""
echo "📝 Update your docker-compose.yml environment variables:"
echo "   TAPSERVICE_MQTT_USERNAME=tapservice"
echo "   TAPSERVICE_MQTT_PASSWORD=<the password you entered>"
