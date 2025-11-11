"""
FastAPI routes implementing HTTP command endpoints and WebSocket event streaming.

HTTP endpoints handle short-lived commands (POST /register, POST /auth/start, etc.)
WebSocket endpoint (/events) streams real-time device events from all devices.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Query
from datetime import datetime, UTC
import logging
import math

from .session_manager import get_session_manager
from .mqtt_client import get_mqtt_client
from .schemas import (
    # HTTP schemas
    RegisterRequest,
    RegisterResponse,
    AuthStartRequest,
    AuthStartResponse,
    AuthUserDataRequest,
    AuthUserDataResponse,
    ReadRequest,
    ReadResponse,
    DeviceStatusResponse,
    DeviceListResponse,
    ResetDeviceResponse,
    RequestStatusResponse,
    RequestListResponse,
    CancelResponse,
    ErrorResponse,
    NFCError,
    # WebSocket event schemas (imported for MQTT integration)
    StatusChangeEvent,  # noqa: F401 - used in MQTT handlers
    ModeChangeEvent,  # noqa: F401 - used in MQTT handlers
    RegisterWaitingEvent,
    RegisterWritingEvent,  # noqa: F401 - used in MQTT handlers
    RegisterSuccessEvent,  # noqa: F401 - used in MQTT handlers
    RegisterErrorEvent,  # noqa: F401 - used in MQTT handlers
    AuthWaitingEvent,
    AuthTagDetectedEvent,  # noqa: F401 - used in MQTT handlers
    AuthProcessingEvent,
    AuthSuccessEvent,  # noqa: F401 - used in MQTT handlers
    AuthFailedEvent,  # noqa: F401 - used in MQTT handlers
    AuthErrorEvent,  # noqa: F401 - used in MQTT handlers
    ReadWaitingEvent,
    ReadSuccessEvent,  # noqa: F401 - used in MQTT handlers
    ReadErrorEvent,  # noqa: F401 - used in MQTT handlers
)

router = APIRouter()
logger = logging.getLogger("tapservice")

# Common error responses for NFC device endpoints
COMMON_NFC_RESPONSES = {
    400: {"model": NFCError, "description": "NFC operation error (tag write failed, no tag present, etc.)"},
    404: {"model": ErrorResponse, "description": "NFC device not found"},
    500: {"model": ErrorResponse, "description": "Internal server error"},
    503: {"model": NFCError, "description": "NFC device unavailable or busy"},
}


# ============================================================================
# HTTP COMMAND ENDPOINTS
# ============================================================================

@router.post("/register", response_model=RegisterResponse, responses=COMMON_NFC_RESPONSES)
async def register_tag(request: RegisterRequest):
    """
    Start tag registration/writing process on an NFC device.
    
    API client sends device_id, tag_uid, and key. Service commands the NFC device to
    enter write mode and responds immediately. Client monitors progress via
    WebSocket /events.
    
    Flow:
    1. Client sends HTTP POST /register → returns {request_id: "...", status: "initiated"}
    2. Client receives via WebSocket: register_waiting, register_writing, register_success/error
    3. Client can poll GET /requests/{request_id}/status or cancel with POST /requests/{request_id}/cancel
    """
    session_mgr = get_session_manager()
    
    # Check if device exists and is available
    if not session_mgr.get_device_state(request.device_id):
        raise HTTPException(status_code=404, detail=f"Device {request.device_id} not found")
    
    if not session_mgr.is_device_available(request.device_id):
        raise HTTPException(status_code=503, detail=f"Device {request.device_id} is busy")
    
    # Create operation session
    request_id = session_mgr.create_operation_session(request.device_id, "register")
    
    # Store operation-specific metadata
    session_mgr.update_operation_session(request_id, tag_uid=request.tag_uid, key=request.key)
    
    # Publish command to device via MQTT
    mqtt_client = get_mqtt_client()
    await mqtt_client.publish_command(
        device_id=request.device_id,
        operation="register",
        action="start",
        request_id=request_id,
        payload={
            "tag_uid": request.tag_uid,
            "key": request.key,
            "timeout_seconds": 30  # Default timeout
        }
    )
    
    # Send initial event via WebSocket
    event = RegisterWaitingEvent(
        device_id=request.device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        message="Present tag to writer"
    )
    await session_mgr.publish_event(request.device_id, event.model_dump())
    
    logger.info("Registration initiated", extra={
        "device_id": request.device_id, 
        "request_id": request_id,
        "tag_uid": request.tag_uid
    })
    
    return RegisterResponse(request_id=request_id, device_id=request.device_id)


@router.post("/auth/start", response_model=AuthStartResponse, responses=COMMON_NFC_RESPONSES)
async def auth_start(request: AuthStartRequest):
    """
    Start authentication session on an NFC device.
    
    Creates ephemeral request_id and sets NFC device in auth mode. API client uses
    request_id to correlate WebSocket events and provide user data.
    
    Flow:
    1. Client sends HTTP POST /auth/start → returns {request_id: "..."}
    2. Client receives via WebSocket /events: auth_waiting, auth_tag_detected
    3. Client sends HTTP POST /auth/{request_id}/user_data → provide key
    4. Client receives via WebSocket /events: auth_processing, auth_success/failed/error
    """
    session_mgr = get_session_manager()
    
    # Check device availability
    if not session_mgr.get_device_state(request.device_id):
        raise HTTPException(status_code=404, detail=f"Device {request.device_id} not found")
    
    if not session_mgr.is_device_available(request.device_id):
        raise HTTPException(status_code=503, detail=f"Device {request.device_id} is busy")
    
    # Create auth session
    request_id = session_mgr.create_operation_session(request.device_id, "auth")
    
    # Publish command to device via MQTT
    mqtt_client = get_mqtt_client()
    await mqtt_client.publish_command(
        device_id=request.device_id,
        operation="auth",
        action="start",
        request_id=request_id,
        payload={
            "timeout_seconds": 30  # Default timeout
        }
    )
    
    # Send initial event via WebSocket
    event = AuthWaitingEvent(
        device_id=request.device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        message="Present tag to reader"
    )
    await session_mgr.publish_event(request.device_id, event.model_dump())
    
    logger.info("Auth session created", extra={"device_id": request.device_id, "request_id": request_id})
    
    return AuthStartResponse(request_id=request_id, device_id=request.device_id)


@router.post("/auth/{request_id}/user_data", response_model=AuthUserDataResponse, responses=COMMON_NFC_RESPONSES)
async def auth_user_data(request_id: str, request: AuthUserDataRequest):
    """
    Provide user credentials for authentication verification.
    
    Called after API client receives auth_tag_detected event. Service generates
    challenge and verifies NFC device response. Result streamed via WebSocket.
    
    Flow:
    1. Client receives via WebSocket /events: auth_tag_detected with tag_uid
    2. Client sends HTTP POST /auth/{request_id}/user_data → provide key
    3. Client receives via WebSocket /events: auth_processing, auth_success/failed
    """
    session_mgr = get_session_manager()
    
    # Retrieve auth session
    session = session_mgr.get_operation_session(request_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Auth session {request_id} not found")
    
    if session.status != "tag_detected":
        raise HTTPException(status_code=400, detail=f"Auth session not ready for user data (status: {session.status})")
    
    # Update session status
    session_mgr.update_operation_session(request_id, status="processing")
    
    # Publish command to device via MQTT
    mqtt_client = get_mqtt_client()
    await mqtt_client.publish_command(
        device_id=session.device_id,
        operation="auth",
        action="verify",
        request_id=request_id,
        payload={
            "tag_uid": session.metadata.get("tag_uid", ""),
            "key": request.key,
            "user_data": request.user_data
        }
    )
    
    # Send processing event via WebSocket
    event = AuthProcessingEvent(
        device_id=session.device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        message="Verifying credentials..."
    )
    await session_mgr.publish_event(session.device_id, event.model_dump())
    
    logger.info("Auth user data received", extra={"request_id": request_id})
    
    return AuthUserDataResponse(request_id=request_id)


@router.post("/read", response_model=ReadResponse, responses=COMMON_NFC_RESPONSES)
async def read_tag(request: ReadRequest):
    """
    Trigger tag read operation on an NFC device.
    
    NFC device enters read mode and waits for tag. Result streamed via WebSocket.
    
    Flow:
    1. Client sends HTTP POST /read → returns {request_id: "...", status: "initiated"}
    2. Client receives via WebSocket /events: read_waiting, read_success/error
    3. Client can poll GET /requests/{request_id}/status or cancel with POST /requests/{request_id}/cancel
    """
    session_mgr = get_session_manager()
    
    # Check device availability
    if not session_mgr.get_device_state(request.device_id):
        raise HTTPException(status_code=404, detail=f"Device {request.device_id} not found")
    
    if not session_mgr.is_device_available(request.device_id):
        raise HTTPException(status_code=503, detail=f"Device {request.device_id} is busy")
    
    # Create operation session
    request_id = session_mgr.create_operation_session(request.device_id, "read")
    
    # Publish command to device via MQTT
    mqtt_client = get_mqtt_client()
    await mqtt_client.publish_command(
        device_id=request.device_id,
        operation="read",
        action="start",
        request_id=request_id,
        payload={
            "timeout_seconds": 30,  # Default timeout
            "read_blocks": request.read_blocks if hasattr(request, 'read_blocks') else []
        }
    )
    
    # Send initial event via WebSocket
    event = ReadWaitingEvent(
        device_id=request.device_id,
        timestamp=datetime.now(tz=UTC).isoformat(),
        request_id=request_id,
        message="Present tag to reader"
    )
    await session_mgr.publish_event(request.device_id, event.model_dump())
    
    logger.info("Read operation initiated", extra={
        "device_id": request.device_id,
        "request_id": request_id
    })
    
    return ReadResponse(request_id=request_id, device_id=request.device_id)


@router.get("/device/{device_id}/status", response_model=DeviceStatusResponse, responses=COMMON_NFC_RESPONSES)
async def get_device_status(device_id: str):
    """
    Get current NFC device status (one-time check).
    
    For continuous monitoring, API clients should connect to WebSocket /events
    and filter events by device_id.
    """
    session_mgr = get_session_manager()
    
    device_state = session_mgr.get_device_state(device_id)
    if not device_state:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    
    return DeviceStatusResponse(
        device_id=device_id,
        status=device_state.status.value,
        mode=device_state.mode.value,
        last_seen=device_state.last_seen.isoformat()
    )


@router.get("/devices", response_model=DeviceListResponse)
async def list_devices(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Number of items per page (max 100)")
):
    """
    List all tracked NFC devices with their current status.
    
    Returns all devices that have been registered with the service,
    including their online/offline status, current mode, and last seen time.
    
    Supports pagination with page and page_size query parameters.
    """
    session_mgr = get_session_manager()
    
    all_devices = session_mgr.list_devices()
    total = len(all_devices)
    total_pages = math.ceil(total / page_size) if total > 0 else 1
    
    # Calculate pagination
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_devices = all_devices[start_idx:end_idx]
    
    device_responses = [
        DeviceStatusResponse(
            device_id=device.device_id,
            status=device.status.value,
            mode=device.mode.value,
            last_seen=device.last_seen.isoformat()
        )
        for device in paginated_devices
    ]
    
    return DeviceListResponse(
        devices=device_responses,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@router.post("/device/{device_id}/reset", response_model=ResetDeviceResponse, responses=COMMON_NFC_RESPONSES)
async def reset_device(device_id: str):
    """
    Request an NFC device reset to idle state.
    
    Sends reset command to device via MQTT. Device will confirm mode change
    via event, which updates session manager state. Use this to recover from
    stuck states or force-cancel operations.
    
    Note: Device mode update happens asynchronously when device confirms.
    """
    session_mgr = get_session_manager()
    
    device_state = session_mgr.get_device_state(device_id)
    if not device_state:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    
    # If device has an active session, mark it for cancellation
    if device_state.current_session_id:
        session = session_mgr.get_operation_session(device_state.current_session_id)
        if session:
            session_mgr.cancel_operation_session(device_state.current_session_id)
            logger.info(
                f"Cancelled {session.operation} operation during device reset",
                extra={"device_id": device_id, "request_id": device_state.current_session_id}
            )
    
    # Publish reset command to device via MQTT
    # Reset uses special topic: devices/{device_id}/reset (not operation/action pattern)
    import uuid
    mqtt_client = get_mqtt_client()
    
    if mqtt_client.client:
        reset_request_id = str(uuid.uuid4())
        
        # Build envelope directly for reset
        envelope = {
            "version": "1.0",
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "device_id": device_id,
            "event_type": "reset",
            "request_id": reset_request_id,
            "payload": {}
        }
        
        import json
        topic = f"devices/{device_id}/reset"
        await mqtt_client.client.publish(topic, json.dumps(envelope), qos=1)
    
    logger.info("Device reset command sent", extra={"device_id": device_id})
    
    return ResetDeviceResponse(device_id=device_id)


# ============================================================================
# UNIFIED REQUEST MANAGEMENT ENDPOINTS
# ============================================================================

@router.get("/requests", response_model=RequestListResponse)
async def list_requests(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Number of items per page (max 100)"),
    device_id: str | None = Query(None, description="Filter by device ID"),
    operation: str | None = Query(None, description="Filter by operation type (auth, register, read)"),
    status: str | None = Query(None, description="Filter by status (waiting, processing, completed, error, cancelled)")
):
    """
    List all operation requests with optional filtering and pagination.
    
    Returns all tracked requests (auth, register, read operations) with their current status.
    Supports filtering by device_id, operation type, and status.
    """
    session_mgr = get_session_manager()
    
    all_sessions = session_mgr.list_operation_sessions()
    
    # Apply filters
    filtered_sessions = all_sessions
    if device_id:
        filtered_sessions = [s for s in filtered_sessions if s.device_id == device_id]
    if operation:
        filtered_sessions = [s for s in filtered_sessions if s.operation == operation]
    if status:
        filtered_sessions = [s for s in filtered_sessions if s.status == status]
    
    # Sort by created_at descending (newest first)
    filtered_sessions.sort(key=lambda s: s.created_at, reverse=True)
    
    total = len(filtered_sessions)
    total_pages = math.ceil(total / page_size) if total > 0 else 1
    
    # Calculate pagination
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_sessions = filtered_sessions[start_idx:end_idx]
    
    request_responses = [
        RequestStatusResponse(
            request_id=session.request_id,
            operation=session.operation,
            device_id=session.device_id,
            status=session.status,
            created_at=session.created_at.isoformat(),
            metadata=session.metadata
        )
        for session in paginated_sessions
    ]
    
    return RequestListResponse(
        requests=request_responses,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@router.get("/requests/{request_id}/status", response_model=RequestStatusResponse, responses=COMMON_NFC_RESPONSES)
async def get_request_status(request_id: str):
    """
    Get current status of any operation (auth, register, read) by request_id.
    
    This unified endpoint works for all async operations. Clients can poll this
    endpoint or monitor real-time updates via WebSocket /events.
    """
    session_mgr = get_session_manager()
    
    session = session_mgr.get_operation_session(request_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Request {request_id} not found")
    
    return RequestStatusResponse(
        request_id=session.request_id,
        operation=session.operation,
        device_id=session.device_id,
        status=session.status,
        created_at=session.created_at.isoformat(),
        metadata=session.metadata
    )


@router.post("/requests/{request_id}/cancel", response_model=CancelResponse, responses=COMMON_NFC_RESPONSES)
async def cancel_request(request_id: str):
    """
    Request cancellation of any ongoing operation (auth, register, read).
    
    Sends cancel command to device via MQTT. Device will confirm mode change
    via event, which updates session manager state.
    
    Note: Device mode update happens asynchronously when device confirms.
    """
    session_mgr = get_session_manager()
    
    session = session_mgr.get_operation_session(request_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Request {request_id} not found")
    
    # Mark session as cancelled
    session_mgr.cancel_operation_session(request_id)
    
    # Publish cancel command to device via MQTT
    mqtt_client = get_mqtt_client()
    await mqtt_client.publish_command(
        device_id=session.device_id,
        operation=session.operation,
        action="cancel",
        request_id=request_id,
        payload={}
    )
    
    logger.info(f"{session.operation.capitalize()} operation cancel requested", 
                extra={"request_id": request_id, "operation": session.operation})
    
    return CancelResponse(
        request_id=request_id, 
        message=f"{session.operation.capitalize()} operation cancelled"
    )


# ============================================================================
# WEBSOCKET EVENT STREAMING ENDPOINT
# ============================================================================

# Track active WebSocket connections (all devices)
active_connections: list[WebSocket] = []


@router.websocket("/events")
async def device_events_stream(websocket: WebSocket):
    """
    WebSocket endpoint for streaming NFC device events in real-time.
    
    Streams events from all NFC reader devices to all connected API clients.
    
    Event types:
    - Device status changes (online/offline/busy)
    - Device mode changes (idle/auth/read/register)
    - Tag events (detected, read success/error)
    - Registration events (waiting, writing, success/error)
    - Authentication events (waiting, tag_detected, processing, success/failed/error)
    - Read events (waiting, success/error)
    
    Events are JSON objects with event_type, device_id, timestamp, and event-specific fields.
    
    Usage:
    1. API client connects to WebSocket
    2. API client sends HTTP commands (POST /register, POST /auth/start, etc.) to control NFC devices
    3. Service pushes NFC device events to WebSocket as they occur
    4. API client filters events by device_id if only monitoring specific NFC readers
    5. Connection stays open for continuous updates
    """
    await websocket.accept()
    
    # Register connection
    active_connections.append(websocket)
    
    ws_logger = logging.getLogger("tapservice.ws")
    ws_logger.info("WebSocket connected")
    
    session_mgr = get_session_manager()
    
    try:
        # Get global event queue
        event_queue = session_mgr.get_event_queue()
        
        if event_queue:
            # Stream events from queue
            while True:
                # Wait for events from MQTT or internal triggers
                event = await event_queue.get()
                
                # Broadcast to all connections
                await broadcast_to_all(event)
                
    except WebSocketDisconnect:
        ws_logger.info("WebSocket disconnected")
    except Exception as e:
        ws_logger.error("WebSocket error", exc_info=True)
        await websocket.close(code=1011, reason=str(e))
    finally:
        # Unregister connection
        if websocket in active_connections:
            active_connections.remove(websocket)


async def broadcast_to_all(event: dict):
    """Broadcast an event to all WebSocket clients."""
    disconnected = []
    
    for connection in active_connections:
        try:
            await connection.send_json(event)
        except Exception:
            # Mark connection for removal if send fails
            disconnected.append(connection)
    
    # Remove disconnected clients
    for connection in disconnected:
        if connection in active_connections:
            active_connections.remove(connection)


