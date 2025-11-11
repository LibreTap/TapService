"""
MQTT event handlers for receiving device state changes and operation results.

This module subscribes to MQTT topics and updates session manager state based on
actual device confirmations. This ensures the service's state matches physical device state.

Event-Driven Pattern:
1. HTTP endpoints send MQTT commands (don't update state)
2. Devices execute commands and publish state changes
3. MQTT handlers receive confirmations and update session manager
4. WebSocket clients receive broadcasted events

This pattern ensures:
- Single source of truth (device is authoritative)
- Proper error handling (know when devices fail)
- State consistency across service instances
- Network resilience (handle disconnects gracefully)
"""
from datetime import datetime, UTC
import logging

from .session_manager import get_session_manager, DeviceMode, DeviceStatus
from .schemas import (
    StatusChangeEvent,
    ModeChangeEvent,
    RegisterWaitingEvent,
    RegisterWritingEvent,
    RegisterSuccessEvent,
    RegisterErrorEvent,
    AuthWaitingEvent,
    AuthTagDetectedEvent,
    AuthProcessingEvent,
    AuthSuccessEvent,
    AuthFailedEvent,
    AuthErrorEvent,
    ReadWaitingEvent,
    ReadSuccessEvent,
    ReadErrorEvent,
)

logger = logging.getLogger("tapservice.mqtt")


# ============================================================================
# DEVICE STATE CHANGE HANDLERS
# ============================================================================

async def on_device_status_change(device_id: str, status: str):
    """
    Handle device status changes (online/offline).
    
    MQTT Topic: devices/{device_id}/status
    Payload: {"status": "online" | "offline", "timestamp": "..."}
    """
    session_mgr = get_session_manager()
    
    # Auto-register device if it doesn't exist
    if not session_mgr.get_device_state(device_id):
        session_mgr.register_device(device_id)
        logger.info(f"Auto-registered new device: {device_id}")
    
    # Update device status based on actual device state
    device_status = DeviceStatus(status)
    session_mgr.update_device_status(device_id, device_status)
    
    # Broadcast event to WebSocket clients
    event = StatusChangeEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        status=status
    )
    await session_mgr.publish_event(device_id, event.model_dump())
    
    logger.info(f"Device status changed to {status}", extra={"device_id": device_id})


async def on_device_mode_change(device_id: str, mode: str, session_id: str | None = None):
    """
    Handle device mode changes (idle/auth/read/register).
    
    MQTT Topic: devices/{device_id}/mode
    Payload: {"mode": "idle" | "auth" | "read" | "register", "session_id": "...", "timestamp": "..."}
    
    This is the authoritative state update - device confirms it has entered the requested mode.
    """
    session_mgr = get_session_manager()
    
    device_state = session_mgr.get_device_state(device_id)
    if not device_state:
        logger.warning(f"Received mode change for unknown device {device_id}")
        return
    
    # Update device mode based on device confirmation
    device_mode = DeviceMode(mode)
    session_mgr.update_device_mode(device_id, device_mode, session_id=session_id)
    
    # If device went idle and had an active session, finalize cancellation
    if mode == "idle" and device_state.current_session_id:
        session = session_mgr.get_operation_session(device_state.current_session_id)
        if session and session.status == "cancelled":
            # Session was marked for cancellation, now device confirms it's idle
            logger.info(
                f"Device confirmed cancellation of {session.operation} operation",
                extra={"device_id": device_id, "request_id": device_state.current_session_id}
            )
    
    # Broadcast event to WebSocket clients
    event = ModeChangeEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        mode=mode
    )
    await session_mgr.publish_event(device_id, event.model_dump())
    
    logger.info(f"Device mode changed to {mode}", extra={"device_id": device_id, "session_id": session_id})


# ============================================================================
# REGISTER OPERATION HANDLERS
# ============================================================================

async def on_register_waiting(device_id: str, request_id: str, message: str):
    """
    MQTT Topic: devices/{device_id}/register/waiting
    Payload: {"request_id": "...", "message": "...", "timestamp": "..."}
    """
    session_mgr = get_session_manager()
    session_mgr.update_operation_session(request_id, status="waiting")
    
    event = RegisterWaitingEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        message=message
    )
    await session_mgr.publish_event(device_id, event.model_dump())


async def on_register_writing(device_id: str, request_id: str, message: str):
    """
    MQTT Topic: devices/{device_id}/register/writing
    Payload: {"request_id": "...", "message": "...", "timestamp": "..."}
    """
    session_mgr = get_session_manager()
    session_mgr.update_operation_session(request_id, status="writing")
    
    event = RegisterWritingEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        message=message
    )
    await session_mgr.publish_event(device_id, event.model_dump())


async def on_register_success(device_id: str, request_id: str, tag_uid: str):
    """
    MQTT Topic: devices/{device_id}/register/success
    Payload: {"request_id": "...", "tag_uid": "...", "timestamp": "..."}
    """
    logger.info("Processing register_success event", extra={"device_id": device_id, "request_id": request_id, "tag_uid": tag_uid})
    
    session_mgr = get_session_manager()
    session_mgr.update_operation_session(request_id, status="completed", tag_uid=tag_uid)
    
    event = RegisterSuccessEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        tag_uid=tag_uid
    )
    await session_mgr.publish_event(device_id, event.model_dump())
    
    logger.info("Register operation completed successfully", extra={"device_id": device_id, "request_id": request_id})


async def on_register_error(device_id: str, request_id: str, error: str, error_code: str):
    """
    MQTT Topic: devices/{device_id}/register/error
    Payload: {"request_id": "...", "error": "...", "error_code": "...", "timestamp": "..."}
    """
    session_mgr = get_session_manager()
    session_mgr.update_operation_session(request_id, status="error", error=error, error_code=error_code)
    
    event = RegisterErrorEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        error=error,
        error_code=error_code
    )
    await session_mgr.publish_event(device_id, event.model_dump())


# ============================================================================
# AUTH OPERATION HANDLERS
# ============================================================================

async def on_auth_waiting(device_id: str, request_id: str, message: str):
    """
    MQTT Topic: devices/{device_id}/auth/waiting
    Payload: {"request_id": "...", "message": "...", "timestamp": "..."}
    """
    session_mgr = get_session_manager()
    session_mgr.update_operation_session(request_id, status="waiting")
    
    event = AuthWaitingEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        message=message
    )
    await session_mgr.publish_event(device_id, event.model_dump())


async def on_auth_tag_detected(device_id: str, request_id: str, tag_uid: str):
    """
    MQTT Topic: devices/{device_id}/auth/tag_detected
    Payload: {"request_id": "...", "tag_uid": "...", "timestamp": "..."}
    """
    logger.info("Processing auth_tag_detected event", extra={"device_id": device_id, "request_id": request_id, "tag_uid": tag_uid})
    
    session_mgr = get_session_manager()
    session_mgr.update_operation_session(request_id, status="tag_detected", tag_uid=tag_uid)
    
    event = AuthTagDetectedEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        tag_uid=tag_uid
    )
    await session_mgr.publish_event(device_id, event.model_dump())
    
    logger.info("Auth tag detected", extra={"device_id": device_id, "request_id": request_id})


async def on_auth_processing(device_id: str, request_id: str, message: str):
    """
    MQTT Topic: devices/{device_id}/auth/processing
    Payload: {"request_id": "...", "message": "...", "timestamp": "..."}
    """
    session_mgr = get_session_manager()
    session_mgr.update_operation_session(request_id, status="processing")
    
    event = AuthProcessingEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        message=message
    )
    await session_mgr.publish_event(device_id, event.model_dump())


async def on_auth_success(device_id: str, request_id: str, tag_uid: str, user_data: dict):
    """
    MQTT Topic: devices/{device_id}/auth/success
    Payload: {"request_id": "...", "tag_uid": "...", "user_data": {...}, "timestamp": "..."}
    """
    logger.info("Processing auth_success event", extra={"device_id": device_id, "request_id": request_id, "tag_uid": tag_uid})
    
    session_mgr = get_session_manager()
    session_mgr.update_operation_session(request_id, status="completed", tag_uid=tag_uid, user_data=user_data)
    
    event = AuthSuccessEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        tag_uid=tag_uid,
        user_data=user_data
    )
    await session_mgr.publish_event(device_id, event.model_dump())
    
    logger.info("Auth operation completed successfully", extra={"device_id": device_id, "request_id": request_id})


async def on_auth_failed(device_id: str, request_id: str, reason: str):
    """
    MQTT Topic: devices/{device_id}/auth/failed
    Payload: {"request_id": "...", "reason": "...", "timestamp": "..."}
    """
    session_mgr = get_session_manager()
    session_mgr.update_operation_session(request_id, status="failed", reason=reason)
    
    event = AuthFailedEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        reason=reason
    )
    await session_mgr.publish_event(device_id, event.model_dump())


async def on_auth_error(device_id: str, request_id: str, error: str, error_code: str):
    """
    MQTT Topic: devices/{device_id}/auth/error
    Payload: {"request_id": "...", "error": "...", "error_code": "...", "timestamp": "..."}
    """
    session_mgr = get_session_manager()
    session_mgr.update_operation_session(request_id, status="error", error=error, error_code=error_code)
    
    event = AuthErrorEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        error=error,
        error_code=error_code
    )
    await session_mgr.publish_event(device_id, event.model_dump())


# ============================================================================
# READ OPERATION HANDLERS
# ============================================================================

async def on_read_waiting(device_id: str, request_id: str, message: str):
    """
    MQTT Topic: devices/{device_id}/read/waiting
    Payload: {"request_id": "...", "message": "...", "timestamp": "..."}
    """
    session_mgr = get_session_manager()
    session_mgr.update_operation_session(request_id, status="waiting")
    
    event = ReadWaitingEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        message=message
    )
    await session_mgr.publish_event(device_id, event.model_dump())


async def on_read_success(device_id: str, request_id: str, tag_uid: str, data: dict):
    """
    MQTT Topic: devices/{device_id}/read/success
    Payload: {"request_id": "...", "tag_uid": "...", "data": {...}, "timestamp": "..."}
    """
    session_mgr = get_session_manager()
    session_mgr.update_operation_session(request_id, status="completed", tag_uid=tag_uid, data=data)
    
    event = ReadSuccessEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        tag_uid=tag_uid,
        data=data
    )
    await session_mgr.publish_event(device_id, event.model_dump())


async def on_read_error(device_id: str, request_id: str, error: str, error_code: str):
    """
    MQTT Topic: devices/{device_id}/read/error
    Payload: {"request_id": "...", "error": "...", "error_code": "...", "timestamp": "..."}
    """
    session_mgr = get_session_manager()
    session_mgr.update_operation_session(request_id, status="error", error=error, error_code=error_code)
    
    event = ReadErrorEvent(
        device_id=device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        error=error,
        error_code=error_code
    )
    await session_mgr.publish_event(device_id, event.model_dump())
