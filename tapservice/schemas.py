from pydantic import BaseModel, Field
from typing import Optional

# ============================================================================
# HTTP COMMAND SCHEMAS (Request/Response for short-lived actions)
# ============================================================================

# --- Registration Command ---
class RegisterRequest(BaseModel):
    """HTTP POST request to start tag registration."""
    device_id: str = Field(..., description="Device ID to use for writing")
    tag_uid: str = Field(..., description="Tag UID to register")
    key: str = Field(..., description="Encryption key to write to tag")


class RegisterResponse(BaseModel):
    """HTTP response after initiating registration."""
    request_id: str = Field(..., description="Unique request ID for tracking this operation")
    device_id: str
    status: str = Field(default="initiated", description="Command accepted")
    message: str = Field(default="Registration started. Monitor events via WebSocket.")


# --- Authentication Command ---
class AuthStartRequest(BaseModel):
    """HTTP POST request to start authentication session."""
    device_id: str = Field(..., description="Device ID to use for authentication")


class AuthStartResponse(BaseModel):
    """HTTP response with ephemeral request_id."""
    request_id: str = Field(..., description="Unique session ID for this auth flow")
    device_id: str
    status: str = Field(default="initiated")
    message: str = Field(default="Auth session created. Monitor events via WebSocket.")


class AuthUserDataRequest(BaseModel):
    """HTTP POST request to provide key and user data for verification."""
    key: str = Field(..., description="Decryption key for tag verification")
    user_data: Optional[dict] = Field(None, description="Optional user-provided data")


class AuthUserDataResponse(BaseModel):
    """HTTP response confirming receipt of user data."""
    request_id: str
    status: str = Field(default="processing")
    message: str = Field(default="User data received. Verification in progress.")


# --- Read Command ---
class ReadRequest(BaseModel):
    """HTTP POST request to trigger tag read."""
    device_id: str = Field(..., description="Device ID to use for reading")


class ReadResponse(BaseModel):
    """HTTP response after initiating read."""
    request_id: str = Field(..., description="Unique request ID for tracking this operation")
    device_id: str
    status: str = Field(default="initiated")
    message: str = Field(default="Read started. Monitor events via WebSocket.")


# --- Device Status Query ---
class DeviceStatusResponse(BaseModel):
    """HTTP GET response for device status."""
    device_id: str
    status: str = Field(..., description="online, offline, busy")
    mode: str = Field(..., description="idle, auth, read, register")
    last_seen: str = Field(..., description="ISO 8601 timestamp")


# --- Device List Query ---
class DeviceListResponse(BaseModel):
    """HTTP GET response for listing all devices."""
    devices: list[DeviceStatusResponse] = Field(..., description="List of all tracked devices")
    total: int = Field(..., description="Total number of devices")
    page: int = Field(..., description="Current page number (1-indexed)")
    page_size: int = Field(..., description="Number of items per page")
    total_pages: int = Field(..., description="Total number of pages")


# --- Device Reset ---
class ResetDeviceResponse(BaseModel):
    """HTTP POST response for device reset."""
    device_id: str
    status: str = Field(default="reset")
    message: str = Field(default="Device reset to idle state")


# --- Cancellation ---
class CancelResponse(BaseModel):
    """HTTP response for cancellation request."""
    request_id: str
    status: str = Field(default="cancelled")
    message: str


# --- Request Status Query (unified for all operations) ---
class RequestStatusResponse(BaseModel):
    """HTTP GET response for request status query."""
    request_id: str = Field(..., description="The request ID being queried")
    operation: str = Field(..., description="Operation type: auth, register, read")
    device_id: str = Field(..., description="Device handling this operation")
    status: str = Field(..., description="Current status: waiting, tag_detected, processing, completed, error, cancelled")
    created_at: str = Field(..., description="ISO 8601 timestamp when request was created")
    metadata: dict = Field(default_factory=dict, description="Operation-specific metadata")


# --- Request List Query ---
class RequestListResponse(BaseModel):
    """HTTP GET response for listing all requests."""
    requests: list[RequestStatusResponse] = Field(..., description="List of operation requests")
    total: int = Field(..., description="Total number of requests")
    page: int = Field(..., description="Current page number (1-indexed)")
    page_size: int = Field(..., description="Number of items per page")
    total_pages: int = Field(..., description="Total number of pages")


# ============================================================================
# WEBSOCKET EVENT SCHEMAS (Real-time event streaming)
# ============================================================================

# Base event structure
class DeviceEvent(BaseModel):
    """Base class for all device events."""
    event_type: str = Field(..., description="Event type identifier")
    device_id: str = Field(..., description="Device that generated the event")
    timestamp: str = Field(..., description="ISO 8601 timestamp")


# --- Status Events ---
class StatusChangeEvent(DeviceEvent):
    """Event when device status changes (online/offline/busy)."""
    event_type: str = Field(default="status_change")
    status: str = Field(..., description="online, offline, busy")


class ModeChangeEvent(DeviceEvent):
    """Event when device mode changes (idle/auth/read/register)."""
    event_type: str = Field(default="mode_change")
    mode: str = Field(..., description="idle, auth, read, register")
    session_id: Optional[str] = Field(None, description="Associated session/request ID")


# --- Registration Events ---
class RegisterWaitingEvent(DeviceEvent):
    """Device is waiting for tag to register."""
    event_type: str = Field(default="register_waiting")
    request_id: str = Field(..., description="Request ID for this registration operation")
    message: str = Field(default="Present tag to writer")


class RegisterWritingEvent(DeviceEvent):
    """Device is writing data to tag."""
    event_type: str = Field(default="register_writing")
    tag_uid: str
    message: str = Field(default="Writing data to tag...")


class RegisterSuccessEvent(DeviceEvent):
    """Tag registration completed successfully."""
    event_type: str = Field(default="register_success")
    tag_uid: str
    message: str = Field(default="Tag registered successfully")


class RegisterErrorEvent(DeviceEvent):
    """Tag registration failed."""
    event_type: str = Field(default="register_error")
    error_code: str
    message: str


# --- Authentication Events ---
class AuthWaitingEvent(DeviceEvent):
    """Device is waiting for tag during auth."""
    event_type: str = Field(default="auth_waiting")
    request_id: str
    message: str = Field(default="Present tag to reader")


class AuthTagDetectedEvent(DeviceEvent):
    """Tag detected during auth - client should provide user data."""
    event_type: str = Field(default="auth_tag_detected")
    request_id: str
    tag_uid: str
    message: str = Field(default="Tag detected. Awaiting user data.")


class AuthProcessingEvent(DeviceEvent):
    """Device is verifying authentication."""
    event_type: str = Field(default="auth_processing")
    request_id: str
    message: str = Field(default="Verifying credentials...")


class AuthSuccessEvent(DeviceEvent):
    """Authentication succeeded."""
    event_type: str = Field(default="auth_success")
    request_id: str
    tag_uid: str
    authenticated: bool = Field(default=True)
    message: str = Field(default="Authentication successful")


class AuthFailedEvent(DeviceEvent):
    """Authentication failed (invalid key)."""
    event_type: str = Field(default="auth_failed")
    request_id: str
    tag_uid: Optional[str] = None
    authenticated: bool = Field(default=False)
    message: str = Field(default="Authentication failed")


class AuthErrorEvent(DeviceEvent):
    """Authentication encountered an error."""
    event_type: str = Field(default="auth_error")
    request_id: str
    error_code: str
    message: str


# --- Read Events ---
class ReadWaitingEvent(DeviceEvent):
    """Device is waiting for tag to read."""
    event_type: str = Field(default="read_waiting")
    request_id: str = Field(..., description="Request ID for this read operation")
    message: str = Field(default="Present tag to reader")


class ReadSuccessEvent(DeviceEvent):
    """Tag read completed successfully."""
    event_type: str = Field(default="read_success")
    tag_uid: str
    data: Optional[dict] = Field(None, description="Tag data if available")
    message: str = Field(default="Tag read successfully")


class ReadErrorEvent(DeviceEvent):
    """Tag read failed."""
    event_type: str = Field(default="read_error")
    error_code: str
    message: str


# ============================================================================
# ERROR RESPONSE SCHEMAS (for HTTP endpoints)
# ============================================================================

class ErrorDetail(BaseModel):
    """Detailed error information."""
    code: str = Field(..., description="Error code for programmatic handling")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[dict] = Field(None, description="Additional error context")


class ErrorResponse(BaseModel):
    """Standard error response format."""
    error: ErrorDetail


class NFCError(BaseModel):
    """Error response for NFC-related operations."""
    error_code: str = Field(..., description="Specific NFC error code")
    message: str = Field(..., description="Error description")
    tag_id: Optional[str] = Field(None, description="Tag ID if available")
    retry_possible: bool = Field(True, description="Whether the operation can be retried")

