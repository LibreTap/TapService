from pydantic import BaseModel, Field
from typing import Optional
from .enums import FlowStatus

# Schemas for NFC tag registration
class TagRegistrationRequest(BaseModel):
    """Request schema for registering a tag."""
    device_id: str
    tag_secret: str


class TagRegistrationResponse(BaseModel):
    """Response schema after successfully registering a tag."""
    message: str
    tag_id: str


# Error response schemas
class ErrorDetail(BaseModel):
    """Detailed error information."""
    code: str = Field(..., description="Error code for programmatic handling")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[dict] = Field(None, description="Additional error context")


class ErrorResponse(BaseModel):
    """Standard error response format."""
    error: ErrorDetail


# Specific error types for NFC operations
class NFCError(BaseModel):
    """Error response for NFC-related operations."""
    error_code: str = Field(..., description="Specific NFC error code")
    message: str = Field(..., description="Error description")
    tag_id: Optional[str] = Field(None, description="Tag ID if available")
    retry_possible: bool = Field(True, description="Whether the operation can be retried")


# WebSocket message schemas for device registration
class DeviceStatusMessage(BaseModel):
    """Message sent via WebSocket when device status changes."""
    event_type: str = Field(..., description="Type of event: 'online' or 'offline'")
    device_id: str = Field(..., description="Unique identifier for the device")
    timestamp: str = Field(..., description="ISO 8601 timestamp of the event")
    message: Optional[str] = Field(None, description="Additional message from device")


# WebSocket message schemas for authentication flow
class AuthInitMessage(BaseModel):
    """Initial message from client to start authentication."""
    device_id: str = Field(..., description="Device ID to authenticate with")


class AuthWaitingMessage(BaseModel):
    """Server response indicating waiting for tag."""
    status: FlowStatus = Field(default=FlowStatus.waiting_for_tag, description="Current status")
    message: str = Field(..., description="User-facing message")


class AuthTagDetectedMessage(BaseModel):
    """Server message when tag is detected."""
    status: FlowStatus = Field(default=FlowStatus.tag_detected, description="Current status")
    tag_id: str = Field(..., description="Detected tag ID")


class AuthKeyMessage(BaseModel):
    """Client message providing decryption key."""
    key: str = Field(..., description="Decryption key for tag verification")


class AuthResultMessage(BaseModel):
    """Final authentication result from server."""
    status: FlowStatus = Field(..., description="Result status: FlowStatus.success or FlowStatus.failed")
    authenticated: bool = Field(..., description="Whether authentication succeeded")
    message: str = Field(..., description="Result message")


class AuthErrorMessage(BaseModel):
    """Error message during authentication."""
    status: FlowStatus = Field(default=FlowStatus.error, description="Status indicating error")
    code: str = Field(..., description="Error code")
    message: str = Field(..., description="Error message")


# WebSocket message schemas for tag reading flow
class ReadInitMessage(BaseModel):
    """Initial message from client to start reading a tag."""
    device_id: str = Field(..., description="Device ID to use for reading")


class ReadWaitingMessage(BaseModel):
    """Server response indicating waiting for tag."""
    status: FlowStatus = Field(default=FlowStatus.waiting_for_tag, description="Current status")
    message: str = Field(..., description="User-facing message")


class ReadTagDetectedMessage(BaseModel):
    """Server message when tag is detected and read."""
    status: FlowStatus = Field(default=FlowStatus.tag_detected, description="Current status")
    tag_id: str = Field(..., description="Detected tag ID")
    message: str = Field(..., description="Success message")


class ReadErrorMessage(BaseModel):
    """Error message during tag reading."""
    status: FlowStatus = Field(default=FlowStatus.error, description="Status indicating error")
    code: str = Field(..., description="Error code")
    message: str = Field(..., description="Error message")


# WebSocket message schemas for tag registration/writing flow
class RegisterInitMessage(BaseModel):
    """Initial message from client to start registering/writing a tag."""
    device_id: str = Field(..., description="Device ID to use for writing")
    tag_secret: str = Field(..., description="Secret data to write to the tag")


class RegisterWaitingMessage(BaseModel):
    """Server response indicating waiting for tag to write."""
    status: FlowStatus = Field(default=FlowStatus.waiting_for_tag, description="Current status")
    message: str = Field(..., description="User-facing message")


class RegisterWritingMessage(BaseModel):
    """Server message when writing to tag."""
    status: FlowStatus = Field(default=FlowStatus.writing, description="Current status")
    message: str = Field(..., description="Status message")


class RegisterSuccessMessage(BaseModel):
    """Server message when tag is successfully written."""
    status: FlowStatus = Field(default=FlowStatus.success, description="Current status")
    tag_id: str = Field(..., description="Written tag ID")
    message: str = Field(..., description="Success message")


class RegisterErrorMessage(BaseModel):
    """Error message during tag registration."""
    status: FlowStatus = Field(default=FlowStatus.error, description="Status indicating error")
    code: str = Field(..., description="Error code")
    message: str = Field(..., description="Error message")
