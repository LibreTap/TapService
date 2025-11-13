"""
Tests for MQTT protocol schema compliance.

Validates that:
1. Incoming MQTT event payloads match JSON schema definitions
2. Outgoing MQTT command payloads match JSON schema definitions
3. Message envelopes follow protocol spec
"""
import pytest
from datetime import datetime, UTC
from uuid import uuid4
from pydantic import ValidationError

from tapservice.mqtt_protocol_models import (
    MqttMessageEnvelope,
    EventType,
    # Command payloads
    RegisterStart,
    AuthStart,
    AuthVerify,
    ReadStart,
    Cancel,
    Reset,
    # Event payloads
    StatusChange,
    Status,
    ModeChange,
    Mode,
    PreviousMode,
    TagDetected,
    SuccessRegisterRead,
    SuccessAuth,
    FailedAuth,
    Error as MqttError,
    ErrorCode,
    Component,
    Heartbeat,
)


class TestMessageEnvelope:
    """Test MQTT message envelope validation."""
    
    def test_valid_envelope(self):
        """Valid envelope should pass validation."""
        envelope = {
            "version": "1.0",
            "timestamp": datetime.now(UTC).isoformat(),
            "device_id": "reader-001",
            "event_type": "status_change",
            "request_id": str(uuid4()),
            "payload": {"status": "online", "firmware_version": "1.0.0", "ip_address": "192.168.1.100"}
        }
        
        validated = MqttMessageEnvelope.model_validate(envelope)
        assert validated.version == "1.0"
        assert validated.device_id == "reader-001"
        assert validated.event_type == EventType.status_change
    
    def test_missing_required_field(self):
        """Envelope missing required field should fail."""
        envelope = {
            "version": "1.0",
            "device_id": "reader-001",
            # missing timestamp
            "event_type": "status_change",
            "request_id": str(uuid4()),
            "payload": {}
        }
        
        with pytest.raises(ValidationError) as exc_info:
            MqttMessageEnvelope.model_validate(envelope)
        
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("timestamp",) for error in errors)
    
    def test_invalid_version(self):
        """Envelope with wrong version should fail."""
        envelope = {
            "version": "2.0",  # only 1.0 supported
            "timestamp": datetime.now(UTC).isoformat(),
            "device_id": "reader-001",
            "event_type": "status_change",
            "request_id": str(uuid4()),
            "payload": {}
        }
        
        with pytest.raises(ValidationError):
            MqttMessageEnvelope.model_validate(envelope)
    
    def test_invalid_device_id_pattern(self):
        """Device ID with invalid characters should fail."""
        envelope = {
            "version": "1.0",
            "timestamp": datetime.now(UTC).isoformat(),
            "device_id": "reader@001!",  # invalid characters
            "event_type": "status_change",
            "request_id": str(uuid4()),
            "payload": {}
        }
        
        with pytest.raises(ValidationError):
            MqttMessageEnvelope.model_validate(envelope)
    
    def test_invalid_event_type(self):
        """Unknown event type should fail."""
        envelope = {
            "version": "1.0",
            "timestamp": datetime.now(UTC).isoformat(),
            "device_id": "reader-001",
            "event_type": "unknown_event",
            "request_id": str(uuid4()),
            "payload": {}
        }
        
        with pytest.raises(ValidationError):
            MqttMessageEnvelope.model_validate(envelope)


class TestCommandPayloads:
    """Test outgoing command payload validation."""
    
    def test_register_start_valid(self):
        """Valid register_start command."""
        payload = {
            "tag_uid": "04:1A:2B:3C:4D:5E:6F",
            "key": "0123456789ABCDEF0123456789ABCDEF",
            "timeout_seconds": 30
        }
        
        validated = RegisterStart.model_validate(payload)
        assert validated.tag_uid == "04:1A:2B:3C:4D:5E:6F"
        assert validated.timeout_seconds == 30
    
    def test_register_start_invalid_tag_uid(self):
        """Invalid tag UID format should fail."""
        payload = {
            "tag_uid": "invalid-uid",  # wrong format
            "key": "0123456789ABCDEF0123456789ABCDEF",
            "timeout_seconds": 30
        }
        
        with pytest.raises(ValidationError):
            RegisterStart.model_validate(payload)
    
    def test_register_start_invalid_key(self):
        """Invalid key format should fail."""
        payload = {
            "tag_uid": "04:1A:2B:3C:4D:5E:6F",
            "key": "TOOLONG0123456789ABCDEF0123456789ABCDEF",  # wrong length
            "timeout_seconds": 30
        }
        
        with pytest.raises(ValidationError):
            RegisterStart.model_validate(payload)
    
    def test_register_start_timeout_out_of_range(self):
        """Timeout outside valid range should fail."""
        payload = {
            "tag_uid": "04:1A:2B:3C:4D:5E:6F",
            "key": "0123456789ABCDEF0123456789ABCDEF",
            "timeout_seconds": 500  # max is 300
        }
        
        with pytest.raises(ValidationError):
            RegisterStart.model_validate(payload)
    
    def test_auth_start_valid(self):
        """Valid auth_start command."""
        payload = {"timeout_seconds": 60}
        
        validated = AuthStart.model_validate(payload)
        assert validated.timeout_seconds == 60
    
    def test_auth_verify_valid(self):
        """Valid auth_verify command."""
        payload = {
            "tag_uid": "04:1A:2B:3C:4D:5E:6F",
            "key": "0123456789ABCDEF0123456789ABCDEF",
            "user_data": {
                "username": "john_doe",
                "context": "login"
            }
        }
        
        validated = AuthVerify.model_validate(payload)
        assert validated.user_data.username == "john_doe"
    
    def test_read_start_valid(self):
        """Valid read_start command."""
        payload = {
            "timeout_seconds": 45,
        }
        
        validated = ReadStart.model_validate(payload)
        assert validated.timeout_seconds == 45
    
    def test_cancel_valid(self):
        """Valid cancel command (empty payload)."""
        payload = {}
        validated = Cancel.model_validate(payload)
        assert validated is not None
    
    def test_reset_valid(self):
        """Valid reset command (empty payload)."""
        payload = {}
        validated = Reset.model_validate(payload)
        assert validated is not None


class TestEventPayloads:
    """Test incoming event payload validation."""
    
    def test_status_change_online(self):
        """Valid status_change (online) event."""
        payload = {
            "status": "online",
            "firmware_version": "1.2.3",
            "ip_address": "192.168.1.100"
        }
        
        validated = StatusChange.model_validate(payload)
        assert validated.status == Status.online
        assert validated.firmware_version == "1.2.3"
    
    def test_status_change_invalid_version(self):
        """Invalid firmware version format should fail."""
        payload = {
            "status": "online",
            "firmware_version": "v1.2",  # wrong format
            "ip_address": "192.168.1.100"
        }
        
        with pytest.raises(ValidationError):
            StatusChange.model_validate(payload)
    
    def test_status_change_invalid_ip(self):
        """Invalid IP address should fail."""
        payload = {
            "status": "online",
            "firmware_version": "1.2.3",
            "ip_address": "999.999.999.999"
        }
        
        with pytest.raises(ValidationError):
            StatusChange.model_validate(payload)
    
    def test_mode_change_valid(self):
        """Valid mode_change event."""
        payload = {
            "mode": "auth",
            "previous_mode": "idle"
        }
        
        validated = ModeChange.model_validate(payload)
        assert validated.mode == Mode.auth
        assert validated.previous_mode == PreviousMode.idle
    
    def test_tag_detected_valid(self):
        """Valid tag_detected event."""
        payload = {
            "tag_uid": "04:1A:2B:3C:4D:5E:6F",
            "message": "Tag detected successfully"
        }
        
        validated = TagDetected.model_validate(payload)
        assert validated.tag_uid == "04:1A:2B:3C:4D:5E:6F"
    
    def test_success_register_read_valid(self):
        """Valid register success event."""
        payload = {
            "tag_uid": "04:1A:2B:3C:4D:5E:6F",
            "blocks_written": 8,
            "message": "Tag registered successfully"
        }
        
        validated = SuccessRegisterRead.model_validate(payload)
        assert validated.blocks_written == 8
    
    def test_success_auth_valid(self):
        """Valid auth success event."""
        payload = {
            "tag_uid": "04:1A:2B:3C:4D:5E:6F",
            "authenticated": True,
            "message": "Authentication successful",
            "user_data": {"role": "admin"}
        }
        
        validated = SuccessAuth.model_validate(payload)
        assert validated.authenticated is True
        assert validated.user_data == {"role": "admin"}
    
    def test_success_auth_invalid_authenticated_value(self):
        """Auth success with False authenticated should fail."""
        payload = {
            "tag_uid": "04:1A:2B:3C:4D:5E:6F",
            "authenticated": False,  # must be True for success
            "message": "Authentication successful"
        }
        
        with pytest.raises(ValidationError):
            SuccessAuth.model_validate(payload)
    
    def test_failed_auth_valid(self):
        """Valid auth failed event."""
        payload = {
            "tag_uid": "04:1A:2B:3C:4D:5E:6F",
            "authenticated": False,
            "reason": "Invalid credentials"
        }
        
        validated = FailedAuth.model_validate(payload)
        assert validated.authenticated is False
    
    def test_error_event_valid(self):
        """Valid error event."""
        payload = {
            "error": "NFC read timeout occurred",
            "error_code": "NFC_TIMEOUT",
            "retry_possible": True,
            "component": "nfc"
        }
        
        validated = MqttError.model_validate(payload)
        assert validated.error_code == ErrorCode.NFC_TIMEOUT
        assert validated.component == Component.nfc
        assert validated.retry_possible is True
    
    def test_error_event_invalid_code(self):
        """Error event with unknown error code should fail."""
        payload = {
            "error": "Something went wrong",
            "error_code": "UNKNOWN_ERROR",  # not in enum
            "retry_possible": False,
            "component": "device"
        }
        
        with pytest.raises(ValidationError):
            MqttError.model_validate(payload)
    
    def test_heartbeat_valid(self):
        """Valid heartbeat event."""
        payload = {
            "uptime_seconds": 3600,
            "memory_usage_percent": 45.5,
            "operations_completed": 127
        }
        
        validated = Heartbeat.model_validate(payload)
        assert validated.uptime_seconds == 3600
        assert validated.memory_usage_percent == 45.5
    
    def test_heartbeat_invalid_memory_percent(self):
        """Heartbeat with memory > 100% should fail."""
        payload = {
            "uptime_seconds": 3600,
            "memory_usage_percent": 150.0,  # > 100
            "operations_completed": 127
        }
        
        with pytest.raises(ValidationError):
            Heartbeat.model_validate(payload)


class TestEndToEndValidation:
    """Test complete message validation (envelope + payload)."""
    
    def test_complete_status_change_message(self):
        """Validate complete status_change message."""
        message = {
            "version": "1.0",
            "timestamp": datetime.now(UTC).isoformat(),
            "device_id": "reader-001",
            "event_type": "status_change",
            "request_id": str(uuid4()),
            "payload": {
                "status": "online",
                "firmware_version": "1.0.0",
                "ip_address": "192.168.1.100"
            }
        }
        
        # Validate envelope
        envelope = MqttMessageEnvelope.model_validate(message)
        assert envelope.event_type == EventType.status_change
        
        # Validate payload
        status_payload = StatusChange.model_validate(envelope.payload)
        assert status_payload.status == Status.online
    
    def test_complete_auth_success_message(self):
        """Validate complete auth_success message."""
        message = {
            "version": "1.0",
            "timestamp": datetime.now(UTC).isoformat(),
            "device_id": "reader-002",
            "event_type": "auth_success",
            "request_id": str(uuid4()),
            "payload": {
                "tag_uid": "04:1A:2B:3C:4D:5E:6F",
                "authenticated": True,
                "message": "Authentication successful",
                "user_data": {"username": "alice"}
            }
        }
        
        # Validate envelope
        envelope = MqttMessageEnvelope.model_validate(message)
        
        # Validate payload
        auth_payload = SuccessAuth.model_validate(envelope.payload)
        assert auth_payload.tag_uid == "04:1A:2B:3C:4D:5E:6F"
        assert auth_payload.user_data == {"username": "alice"}
