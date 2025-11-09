from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Set
import asyncio
from pydantic import ValidationError
import logging

from .enums import FlowStatus
from .ws_helpers import receive_validated

from .schemas import (
    ErrorResponse,
    NFCError,
    AuthInitMessage,
    AuthWaitingMessage,
    AuthTagDetectedMessage,
    AuthKeyMessage,
    AuthResultMessage,
    AuthErrorMessage,
    ReadInitMessage,
    ReadWaitingMessage,
    ReadTagDetectedMessage,
    ReadErrorMessage,
    RegisterInitMessage,
    RegisterWaitingMessage,
    RegisterWritingMessage,
    RegisterSuccessMessage,
    RegisterErrorMessage,
)

router = APIRouter()

# Store active WebSocket connections
active_connections: Set[WebSocket] = set()

# Common error responses for all NFC device endpoints
COMMON_NFC_RESPONSES = {
    400: {"model": NFCError, "description": "NFC operation error (tag write failed, no tag present, etc.)"},
    404: {"model": ErrorResponse, "description": "NFC device not found"},
    500: {"model": ErrorResponse, "description": "Internal server error"},
    503: {"model": NFCError, "description": "NFC device unavailable or busy"},
}


@router.websocket("/ws/register")
async def register_tag_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for registering/writing data to NFC tags.
    
    Flow:
    1. Client → Server: RegisterInitMessage {"device_id": "device_123", "tag_secret": "secret_data"}
    2. Server → Client: RegisterWaitingMessage {"status": "waiting_for_tag", "message": "..."}
    3. Server → Client: RegisterWritingMessage {"status": "writing", "message": "..."} (optional)
    4. Server → Client: RegisterSuccessMessage {"status": "success", "tag_id": "ABC123", "message": "..."}
    
    Error scenarios:
    - RegisterErrorMessage {"status": "error", "code": "...", "message": "..."}
    
    This endpoint sets the device in write mode, waits for a tag to be presented,
    writes the data, and returns the tag ID.
    """
    await websocket.accept()
    
    try:
        logger = logging.getLogger("tapservice.ws")
        # Step 1: Receive and validate initial registration request from client
        def reg_error_factory(code: str, ve: ValidationError):
            return RegisterErrorMessage(code=code, message=str(ve))
        register_init = await receive_validated(websocket, RegisterInitMessage, reg_error_factory)
        device_id = register_init.device_id  # retained for future logic
        _tag_secret = register_init.tag_secret  # placeholder until MQTT integration
        logger.info("Register flow started", extra={"device_id": device_id})
        
        # TODO: Validate device exists and is available
        # if not device_available:
        #     error_msg = RegisterErrorMessage(
        #         code="DEVICE_NOT_FOUND",
        #         message=f"Device {device_id} not found or unavailable"
        #     )
        #     await websocket.send_json(error_msg.model_dump())
        #     await websocket.close(code=1008)
        #     return
        
        # TODO: Publish to MQTT to set device in write mode
        # mqtt_client.publish(f"devices/{device_id}/register/start", {"tag_secret": tag_secret})
        
        # Step 2: Send waiting status to client
        waiting_msg = RegisterWaitingMessage(message="Present tag to writer")
        await websocket.send_json(waiting_msg.model_dump())
        
        # TODO: Subscribe to MQTT topic for tag detection and write status
        # Listen for: devices/{device_id}/register/tag_detected
        # Listen for: devices/{device_id}/register/writing
        # Listen for: devices/{device_id}/register/success
        # For now, simulate the process
        
        # Simulate waiting for tag (replace with actual MQTT listener)
        await asyncio.sleep(1)  # Placeholder for MQTT event
        
        # Step 3: Optional - Send writing status
        writing_msg = RegisterWritingMessage(message="Writing data to tag...")
        await websocket.send_json(writing_msg.model_dump())
        
        # Simulate write operation (replace with actual MQTT response)
        await asyncio.sleep(1)  # Placeholder for write operation
        written_tag_id = "PLACEHOLDER_TAG_ID"  # This would come from MQTT
        
        # TODO: Handle write failure scenarios:
        # if write_failed:
        #     error_msg = RegisterErrorMessage(
        #         code="TAG_WRITE_FAILED",
        #         message="Failed to write data to NFC tag"
        #     )
        #     await websocket.send_json(error_msg.model_dump())
        #     await websocket.close(code=1011)
        #     return
        
        # Step 4: Send success message
        success_msg = RegisterSuccessMessage(tag_id=written_tag_id, message="Tag registered successfully")
        await websocket.send_json(success_msg.model_dump())
        
        # Close connection after successful registration
        await websocket.close(code=1000)
        
    except WebSocketDisconnect:
        logger.info("Register WebSocket client disconnected")
        # TODO: Cleanup - cancel write mode on device via MQTT
        # mqtt_client.publish(f"devices/{device_id}/register/cancel", {})
    except Exception as e:
        logger.error("Register WebSocket error", exc_info=True)
        try:
            error_msg = RegisterErrorMessage(
                code="INTERNAL_ERROR",
                message=str(e)
            )
            await websocket.send_json(error_msg.model_dump())
            await websocket.close(code=1011)
        except Exception:
            pass


@router.websocket("/ws/auth")
async def authenticate_tag_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for interactive tag authentication with Pydantic validation.
    
    Message Schemas (validated with Pydantic):
    1. Client → Server: AuthInitMessage {"device_id": "device_123"}
    2. Server → Client: AuthWaitingMessage {"status": "waiting_for_tag", "message": "..."}
    3. Server → Client: AuthTagDetectedMessage {"status": "tag_detected", "tag_id": "ABC123"}
    4. Client → Server: AuthKeyMessage {"key": "decryption_key_here"}
    5. Server → Client: AuthResultMessage {"status": "success"/"failed", "authenticated": true/false, "message": "..."}
    
    Error scenarios:
    - AuthErrorMessage {"status": "error", "code": "...", "message": "..."}
    """
    await websocket.accept()
    
    try:
        logger = logging.getLogger("tapservice.ws")
        def auth_error_factory(code: str, ve: ValidationError):
            return AuthErrorMessage(code=code, message=str(ve))
        auth_init = await receive_validated(websocket, AuthInitMessage, auth_error_factory)
        device_id = auth_init.device_id  # retained for future logic
        logger.info("Auth flow started", extra={"device_id": device_id})
        
        # TODO: Publish to MQTT to set device in auth mode
        # mqtt_client.publish(f"devices/{device_id}/auth/start", payload)
        
        # Step 2: Send validated waiting status to client
        waiting_msg = AuthWaitingMessage(message="Present tag to reader")
        await websocket.send_json(waiting_msg.model_dump())
        
        # TODO: Subscribe to MQTT topic for tag detection
        # Listen for: devices/{device_id}/auth/tag_detected
        # For now, simulate waiting for tag detection
        
        # Simulate tag detection (replace with actual MQTT listener)
        await asyncio.sleep(1)  # Placeholder for MQTT event
        detected_tag_id = "PLACEHOLDER_TAG_ID"  # This would come from MQTT
        
        # Step 3: Send validated tag_detected message to client
        tag_detected_msg = AuthTagDetectedMessage(tag_id=detected_tag_id)
        await websocket.send_json(tag_detected_msg.model_dump())
        
        # Step 4: Receive and validate decryption key from client
        def auth_key_error_factory(code: str, ve: ValidationError):
            return AuthErrorMessage(code=code, message=str(ve))
        auth_key = await receive_validated(websocket, AuthKeyMessage, auth_key_error_factory)
        _decryption_key = auth_key.key  # placeholder until MQTT integration
        
        # TODO: Publish key to MQTT for device to verify
        # mqtt_client.publish(f"devices/{device_id}/auth/verify", {"key": decryption_key})
        
        # TODO: Wait for verification result from MQTT
        # Listen for: devices/{device_id}/auth/result
        
        # Simulate verification (replace with actual MQTT response)
        await asyncio.sleep(1)  # Placeholder for MQTT verification
        authenticated = True  # This would come from MQTT
        
        # Step 5: Send validated final result to client
        if authenticated:
            result_msg = AuthResultMessage(
                status=FlowStatus.success,
                authenticated=True,
                message="Tag authenticated successfully"
            )
        else:
            result_msg = AuthResultMessage(
                status=FlowStatus.failed,
                authenticated=False,
                message="Authentication failed - invalid key or tag"
            )
        
        await websocket.send_json(result_msg.model_dump())
        
        # Close connection after authentication complete
        await websocket.close(code=1000)
        
    except WebSocketDisconnect:
        logger.info("Auth WebSocket client disconnected")
        # TODO: Cleanup - cancel any pending MQTT operations
    except Exception as e:
        logger.error("Auth WebSocket error", exc_info=True)
        try:
            error_msg = AuthErrorMessage(
                code="INTERNAL_ERROR",
                message=str(e)
            )
            await websocket.send_json(error_msg.model_dump())
            await websocket.close(code=1011)
        except Exception:
            pass


@router.websocket("/ws/read")
async def read_tag_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for reading NFC tag IDs.
    
    Flow:
    1. Client → Server: ReadInitMessage {"device_id": "device_123"}
    2. Server → Client: ReadWaitingMessage {"status": "waiting_for_tag", "message": "..."}
    3. Server → Client: ReadTagDetectedMessage {"status": "tag_detected", "tag_id": "ABC123", "message": "..."}
    
    Error scenarios:
    - ReadErrorMessage {"status": "error", "code": "...", "message": "..."}
    
    This endpoint sets the device in read mode and waits for a tag to be presented.
    Once a tag is detected, it returns the tag ID and closes the connection.
    """
    await websocket.accept()
    
    try:
        logger = logging.getLogger("tapservice.ws")
        def read_error_factory(code: str, ve: ValidationError):
            return ReadErrorMessage(code=code, message=str(ve))
        read_init = await receive_validated(websocket, ReadInitMessage, read_error_factory)
        device_id = read_init.device_id  # retained for future logic
        logger.info("Read flow started", extra={"device_id": device_id})
        
        # TODO: Publish to MQTT to set device in read mode
        # mqtt_client.publish(f"devices/{device_id}/read/start", payload)
        
        # TODO: Check if device exists and is available
        # if not device_available:
        #     error_msg = ReadErrorMessage(
        #         code="DEVICE_NOT_FOUND",
        #         message=f"Device {device_id} not found or unavailable"
        #     )
        #     await websocket.send_json(error_msg.model_dump())
        #     await websocket.close(code=1008)
        #     return
        
        # Step 2: Send waiting status to client
        waiting_msg = ReadWaitingMessage(message="Present tag to reader")
        await websocket.send_json(waiting_msg.model_dump())
        
        # TODO: Subscribe to MQTT topic for tag detection
        # Listen for: devices/{device_id}/read/tag_detected
        # For now, simulate waiting for tag detection
        
        # Simulate tag detection (replace with actual MQTT listener)
        await asyncio.sleep(2)  # Placeholder for MQTT event
        detected_tag_id = "PLACEHOLDER_TAG_ID"  # This would come from MQTT
        
        # Step 3: Send tag_detected message to client
        tag_detected_msg = ReadTagDetectedMessage(tag_id=detected_tag_id, message="Tag read successfully")
        await websocket.send_json(tag_detected_msg.model_dump())
        
        # Close connection after tag is read
        await websocket.close(code=1000)
        
    except WebSocketDisconnect:
        logger.info("Read WebSocket client disconnected")
        # TODO: Cleanup - cancel read mode on device via MQTT
        # mqtt_client.publish(f"devices/{device_id}/read/cancel", {})
    except Exception as e:
        logger.error("Read WebSocket error", exc_info=True)
        try:
            error_msg = ReadErrorMessage(
                code="INTERNAL_ERROR",
                message=str(e)
            )
            await websocket.send_json(error_msg.model_dump())
            await websocket.close(code=1011)
        except Exception:
            pass


@router.websocket("/ws/devices")
async def device_registration_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for real-time device registration status.
    
    Connects to MQTT and streams device online/offline events to connected clients.
    
    Example message format:
    {
        "event_type": "online",  // or "offline"
        "device_id": "device_123",
        "timestamp": "2025-11-09T12:34:56.789Z",
        "message": "Device connected"  // optional
    }
    """
    await websocket.accept()
    active_connections.add(websocket)
    
    try:
        # TODO: Implement MQTT subscription and message forwarding logic here.
        while True:
            # Keep the connection alive
            await asyncio.sleep(10)
                    
    except WebSocketDisconnect:
        logging.getLogger("tapservice.ws").info("Device status WebSocket client disconnected")
    except Exception as e:
        logging.getLogger("tapservice.ws").error("Device status WebSocket error", exc_info=True)
        await websocket.close(code=1011, reason=str(e))
    finally:
        active_connections.discard(websocket)


async def broadcast_to_all(message: str):
    """Broadcast a message to all connected WebSocket clients."""
    disconnected = set()
    
    for connection in active_connections:
        try:
            await connection.send_text(message)
        except Exception:
            # Mark connection for removal if send fails
            disconnected.add(connection)
    
    # Remove disconnected clients
    for connection in disconnected:
        active_connections.discard(connection)


