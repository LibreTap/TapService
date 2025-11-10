# TapService AI Guide

## Fast Orientation
- FastAPI gateway (`tapservice/main.py`) exposes NFC reader operations; devices stay authoritative via MQTT confirmations.
- HTTP routes live in `tapservice/routes.py`; every command returns fast with a `request_id` and never mutates device state directly.
- WebSocket `/events` streams from a shared `asyncio.Queue`; MQTT handlers are expected to push events into that queue.
- State lives in-memory inside `tapservice/session_manager.py`; restarting wipes devices and operation sessions.

## Core Files & Responsibilities
- `main.py`: bootstraps logging, sets permissive CORS, and reuses `custom_generate_unique_id` for human OpenAPI IDs.
- `routes.py`: implements `/register`, `/auth/*`, `/read`, `/device/*`, `/requests/*`, `/events`; reuse the existing `COMMON_NFC_RESPONSES` map when adding endpoints.
- `session_manager.py`: singleton accessor via `get_session_manager()`, provides `register_device`, `update_device_status`, `update_device_mode`, and `publish_event` for fan-out.
- `mqtt_handlers.py`: only place that should call `update_device_mode`; follow the existing handler shapes when wiring a real MQTT client.
- `schemas.py`: all HTTP/WebSocket payloads; prefer `.model_dump()` when serializing events so tests keep passing.

## Request Lifecycle Expectations
- Pattern is: HTTP endpoint → `create_operation_session()` → publish MQTT (TODOs mark topics/payloads) → immediate response.
- Devices confirm over MQTT; handlers update `OperationSession.status`/`metadata` and broadcast via WebSocket.
- Availability gates: before creating a session, check `get_device_state` and `is_device_available`; respond with 404/503 like current routes.
- Cancels and resets only mark sessions as cancelled; device mode flips back to idle when MQTT confirms.

## WebSocket Fan-out
- `routes.py` keeps a global `active_connections` list; call `broadcast_to_all` with plain dicts (Pydantic models already dumped).
- WebSocket loop simply drains the shared queue; if you introduce new producers, always use `publish_event(device_id, event_dict)`.
- Tests rely on immediate queue delivery (`test_websocket_event_broadcasting`), so keep the queue hot and non-blocking.

## Testing & Tooling
- Use `uv sync` to install deps and `uv run pytest` to run the suite; coverage command lives in README.
- `tests/conftest.py` autouse fixture clears `SessionManager` state—avoid caching references across tests.
- `tests/test_http_endpoints.py` encodes expected status codes, metadata usage, and the fact that HTTP never calls `update_device_mode`.
- `tests/test_websocket.py` verifies that HTTP routes immediately enqueue waiting events; keep that behavior when refactoring.

## Implementation Notes
- Logging: stick with `logger = logging.getLogger("tapservice")` (or `.mqtt`/`.ws`) and include `request_id` in `extra` where available.
- Typing is dataclass plus `typing.Optional` today—match the existing style unless doing a repo-wide modernization.
- New operations should extend `OperationSession.metadata` rather than changing schema shapes; clients expect consistent response models.
- Device registration currently comes from MQTT via `register_device`; tests call it directly, so keep that API simple and synchronous.

## When Extending
- Mirror the MQTT topic/comment blocks already present so future implementers see where to hook real publishes/subscribes.
- Wire any new endpoint into `COMMON_NFC_RESPONSES` unless it is truly generic.
- If behavior changes, update `README.md` (quick-start commands live there) and add/adjust tests alongside the change.
