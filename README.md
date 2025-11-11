# TapService

FastAPI gateway exposing NFC reader operations via HTTP commands with real-time WebSocket events.

## Purpose

Operate NFC readers (register/write tags, authenticate, read) through a lightweight API that cleanly separates command submission (HTTP) from authoritative state (device → MQTT → service → WebSocket).

## Key Features

- Event-driven, devices are source of truth
- Unified `request_id` for tracking & cancellation
- Single WebSocket stream for all devices (client-side filtering)
- In-memory state (easy dev / pluggable for Redis later)
- Extensible operation model (add new operations with same pattern)

See [MQTT Protocol Specification](https://github.com/LibreTap/mqtt-protocol) 
for the communication contract between TapService and TapReader devices.

## Prerequisites

- Python 3.12
- `uv` package manager (https://github.com/astral-sh/uv) installed locally

## Getting Started

```bash
git clone <repo-url>
cd TapService
uv sync                       # install deps
uv run uvicorn tapservice.main:app --reload
```

Visit: http://localhost:8000/docs for interactive API.

Minimal smoke test:
```bash
curl http://localhost:8000/devices            # expect empty list initially
curl -X POST http://localhost:8000/read \
  -H 'Content-Type: application/json' \
  -d '{"device_id": "reader_01"}'          # will error if device not registered by MQTT
```

## State & Lifecycle (High Level)

```mermaid
sequenceDiagram
  participant C as Client
  participant A as API + WebSocket
  participant M as MQTT Broker
  participant D as Device

  C->>A: Command (register/auth/read/reset/cancel)
  A->>M: Publish command
  D-->>M: Device events (mode/status/operation)
  M->>A: Deliver event
  A-->>C: WebSocket event (authoritative state)
  C->>A: (Optional) Poll status
```

Devices are authoritative; HTTP never mutates state directly.

Ephemeral: All state is in-memory; restarting clears devices & requests.

Device presence: Devices appear when MQTT status/mode events are received (no HTTP "register device" endpoint). Operations require the device to be online/idle.

## Architecture

**Event-driven pattern** with eventual consistency:

1. HTTP endpoint → MQTT command → Return `request_id`
2. Device executes → MQTT confirmation
3. MQTT handler → Update state → WebSocket broadcast

**Key principle**: Devices are authoritative. HTTP endpoints never update state directly—only MQTT handlers do when devices confirm.

**Terminology**: Device (NFC reader) · Client (API consumer) · Tag (NFC card/chip)

## API

**HTTP Endpoints**:
- `POST /register` - Start tag write (→ `request_id`)
- `POST /auth/start` - Start auth session (→ `request_id`)
- `POST /auth/{id}/user_data` - Submit credentials
- `POST /read` - Start tag read (→ `request_id`)
- `GET /devices` - List devices (paginated)
- `GET /device/{id}/status` - Device status snapshot
- `POST /device/{id}/reset` - Reset device to idle
- `GET /requests` - List operations (filtered/paginated)
- `GET /requests/{id}/status` - Operation status
- `POST /requests/{id}/cancel` - Cancel operation

**WebSocket**: `WS /events` - Real-time stream from all devices (filter by `device_id`)

## Quick Start

```bash
# Connect WebSocket for events
ws://localhost:8000/events

# Send commands
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"device_id": "reader_01", "tag_uid": "ABC123", "key": "secret"}'
# → {"request_id": "uuid", "status": "initiated"}

# Monitor via WebSocket or poll status
curl http://localhost:8000/requests/uuid/status

# Cancel if needed
curl -X POST http://localhost:8000/requests/uuid/cancel

# Reset device
curl -X POST http://localhost:8000/device/reader_01/reset
```

## Events

**Device**: `status_change`, `mode_change`\
**Register**: `register_waiting`, `register_writing`, `register_success`, `register_error`\
**Auth**: `auth_waiting`, `auth_tag_detected`, `auth_processing`, `auth_success`, `auth_failed`, `auth_error`\
**Read**: `read_waiting`, `read_success`, `read_error`

## Request Tracking

All operations return a `request_id` for:
- Progress polling: `GET /requests/{id}/status`
- Cancellation: `POST /requests/{id}/cancel`
- Event correlation: All WebSocket events include `request_id`

Status response: `{request_id, operation, device_id, status, created_at, metadata}`

## Query Examples

```bash
# Devices with pagination
curl "http://localhost:8000/devices?page=1&page_size=10"

# Requests with filters
curl "http://localhost:8000/requests?device_id=reader_01&operation=auth&status=waiting"
```

**Filters**: `device_id`, `operation` (auth/register/read), `status` (waiting/tag_detected/processing/completed/error/cancelled)\
**Pagination**: `page` (default 1), `page_size` (default 20, max 100)

## Development

```bash
uv sync                                              # Install deps
uv run uvicorn tapservice.main:app --reload         # Run server
uv run pytest                                        # Run tests
uv run pytest --cov=tapservice --cov-report=html    # With coverage
```

**Structure**: `main.py` (app) · `routes.py` (endpoints) · `mqtt_client.py` (MQTT connection) · `mqtt_handlers.py` (state updates) · `schemas.py` (models) · `session_manager.py` (state) · `settings.py` (config)

## MQTT Integration

TapService uses `aiomqtt` to connect to an MQTT broker and communicate with NFC devices according to the [LibreTap MQTT Protocol Specification](https://github.com/LibreTap/mqtt-protocol).

### Configuration

Set environment variables to configure MQTT connection:

```bash
export TAPSERVICE_MQTT_HOST=localhost      # MQTT broker hostname
export TAPSERVICE_MQTT_PORT=1883           # MQTT broker port
export TAPSERVICE_MQTT_USERNAME=tapservice # Optional: MQTT username
export TAPSERVICE_MQTT_PASSWORD=secret     # Optional: MQTT password
```

Or create a `.env` file (automatically loaded by pydantic-settings):
```
TAPSERVICE_MQTT_HOST=mqtt.example.com
TAPSERVICE_MQTT_PORT=8883
TAPSERVICE_MQTT_USERNAME=tapservice
TAPSERVICE_MQTT_PASSWORD=your_password
```

### How It Works

**Startup**: FastAPI lifespan manager connects to MQTT broker and subscribes to device topics using wildcards (`devices/+/status`, `devices/+/register/#`, etc.)

**Command Flow**: HTTP endpoints → `mqtt_client.publish_command()` → MQTT broker → Device

**Event Flow**: Device → MQTT broker → `mqtt_client` routes to handler in `mqtt_handlers.py` → Updates `session_manager` → Broadcasts to WebSocket clients

**Command topics** (Service publishes):
```
devices/{device_id}/register/start
devices/{device_id}/auth/start
devices/{device_id}/auth/verify
devices/{device_id}/read/start
devices/{device_id}/{operation}/cancel
devices/{device_id}/reset
```

**Event topics** (Devices publish, service subscribes):
```
devices/{device_id}/status              # online/offline (retained)
devices/{device_id}/mode                # idle/auth/read/register (retained)
devices/{device_id}/register/*          # waiting/writing/success/error
devices/{device_id}/auth/*              # waiting/tag_detected/processing/success/failed/error
devices/{device_id}/read/*              # waiting/success/error
devices/{device_id}/heartbeat           # periodic health metrics
```

### Message Format

All MQTT messages use a standard envelope (v1.0):

```json
{
  "version": "1.0",
  "timestamp": "2025-11-11T12:00:00.000Z",
  "device_id": "reader-001",
  "event_type": "auth_success",
  "request_id": "550e8400-e29b-41d4-a716-446655440002",
  "payload": { /* operation-specific data */ }
}
```

See the [MQTT Protocol Specification](mqtt-protocol/MQTT_PROTOCOL_SPEC.md) for complete details on message schemas, QoS levels, error codes, and flow diagrams.

### Running with MQTT

For local development, you can use Mosquitto:

```bash
# Install Mosquitto
sudo apt install mosquitto mosquitto-clients  # Ubuntu/Debian
brew install mosquitto                        # macOS

# Start broker
mosquitto -v

# Run TapService (connects automatically on startup)
uv run uvicorn tapservice.main:app --reload

# Test with mosquitto_pub (simulate device)
mosquitto_pub -t 'devices/test_reader/status' -m '{"version":"1.0","timestamp":"2025-11-11T12:00:00Z","device_id":"test_reader","event_type":"status_change","request_id":"test","payload":{"status":"online"}}'
```

## Future
- Operation timeouts
- Redis-backed session manager
- Auth/rate limiting
- Metrics/monitoring
- Docker deployment
