"""
Integration tests for MQTT flows - simulates real device behavior.

These tests cover the full lifecycle of operations:
1. HTTP API receives command
2. TapService publishes MQTT command to device
3. Simulated device publishes response events
4. MQTT handlers update session state
5. WebSocket broadcasts events to clients

Each test scenario mirrors the manual tests in MQTT_TESTING.md.
"""
import asyncio
import json
import pytest
import pytest_asyncio
from datetime import datetime, UTC
from uuid import uuid4

from aiomqtt import Client as MQTTClient
import httpx

from tapservice.main import app
from tapservice.session_manager import get_session_manager
from tapservice.mqtt_client import MQTTClient as ServiceMQTTClient
from tapservice.settings import get_settings


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture(scope="session")
def mqtt_broker_available():
    """
    Check if MQTT broker is available for integration tests.
    Skip tests if broker is not running.
    """
    import socket
    settings = get_settings()
    try:
        # Quick TCP connection check
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((settings.mqtt_host, settings.mqtt_port))
        sock.close()
        if result != 0:
            pytest.skip(f"MQTT broker not available at {settings.mqtt_host}:{settings.mqtt_port}")
        return True
    except Exception as e:
        pytest.skip(f"MQTT broker not available at {settings.mqtt_host}:{settings.mqtt_port}: {e}")


@pytest_asyncio.fixture
async def mqtt_device_client(mqtt_broker_available):
    """
    MQTT client simulating a device for integration tests.
    """
    settings = get_settings()
    client = MQTTClient(hostname=settings.mqtt_host, port=settings.mqtt_port)
    await client.__aenter__()
    yield client
    await client.__aexit__(None, None, None)


@pytest_asyncio.fixture
async def service_mqtt_client(mqtt_broker_available):
    """
    Start the TapService MQTT client for integration tests.
    """
    client = ServiceMQTTClient()
    await client.connect()
    
    # Give time for subscriptions to be ready
    await asyncio.sleep(0.1)
    
    yield client
    
    await client.disconnect()


@pytest_asyncio.fixture
async def http_client(service_mqtt_client):
    """
    Async HTTP client for testing FastAPI endpoints.
    Uses the ASGI app directly without creating a server.
    """
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        yield client


@pytest.fixture
def session_manager():
    """Get session manager instance."""
    return get_session_manager()


@pytest.fixture(autouse=True)
def reset_session_manager():
    """Reset session manager state before each test."""
    manager = get_session_manager()
    manager._operation_sessions.clear()
    manager._device_states.clear()
    manager._event_queue = None
    yield
    manager._operation_sessions.clear()
    manager._device_states.clear()
    manager._event_queue = None


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def create_mqtt_envelope(device_id: str, event_type: str, request_id: str, payload: dict) -> dict:
    """Create a properly formatted MQTT message envelope."""
    return {
        "version": "1.0",
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "device_id": device_id,
        "event_type": event_type,
        "request_id": request_id,
        "payload": payload
    }


async def publish_device_status(mqtt_client: MQTTClient, device_id: str, status: str, request_id: str = None):
    """Publish device status change event."""
    if request_id is None:
        request_id = str(uuid4())
    
    message = create_mqtt_envelope(
        device_id=device_id,
        event_type="status_change",
        request_id=request_id,
        payload={
            "status": status,
            "firmware_version": "1.0.0",
            "ip_address": "192.168.1.100"
        }
    )
    await mqtt_client.publish(f"devices/{device_id}/status", json.dumps(message))


async def publish_device_mode(mqtt_client: MQTTClient, device_id: str, mode: str, request_id: str = None, previous_mode: str = None):
    """Publish device mode change event."""
    if request_id is None:
        request_id = str(uuid4())
    if previous_mode is None:
        previous_mode = "idle"
    
    message = create_mqtt_envelope(
        device_id=device_id,
        event_type="mode_change",
        request_id=request_id,
        payload={
            "mode": mode,
            "previous_mode": previous_mode
        }
    )
    await mqtt_client.publish(f"devices/{device_id}/mode", json.dumps(message))


async def wait_for_condition(condition, timeout: float = 2.0, check_interval: float = 0.05):
    """Wait for a condition to become true or timeout."""
    elapsed = 0.0
    while elapsed < timeout:
        if condition():
            return True
        await asyncio.sleep(check_interval)
        elapsed += check_interval
    return False


# ============================================================================
# TEST SCENARIOS
# ============================================================================

@pytest.mark.asyncio
class TestDeviceRegistration:
    """Test Scenario 1: Device Registration (Status & Mode)"""
    
    async def test_device_comes_online(self, mqtt_device_client, http_client, session_manager):
        """Test device registration when coming online."""
        device_id = "test_reader_001"
        
        # Publish device status (online)
        await publish_device_status(mqtt_device_client, device_id, "online")
        
        # Wait for handler to process
        await asyncio.sleep(0.2)
        
        # Verify device is registered
        device_state = session_manager.get_device_state(device_id)
        assert device_state is not None, "Device should be auto-registered"
        assert device_state.status.value == "online"
        
        # Publish device mode (idle)
        await publish_device_mode(mqtt_device_client, device_id, "idle", "test-mode-001")
        
        # Wait for handler to process
        await asyncio.sleep(0.2)
        
        # Verify device mode updated
        device_state = session_manager.get_device_state(device_id)
        assert device_state.mode.value == "idle"
    
    async def test_device_goes_offline(self, mqtt_device_client, http_client, session_manager):
        """Test device going offline."""
        device_id = "test_reader_002"
        
        # Bring device online first
        await publish_device_status(mqtt_device_client, device_id, "online")
        await asyncio.sleep(0.2)
        
        # Now take it offline
        await publish_device_status(mqtt_device_client, device_id, "offline")
        await asyncio.sleep(0.2)
        
        # Verify status updated
        device_state = session_manager.get_device_state(device_id)
        assert device_state.status.value == "offline"


@pytest.mark.asyncio
class TestRegisterOperation:
    """Test Scenario 2: Register Operation Flow"""
    
    async def test_successful_register_flow(self, mqtt_device_client, http_client, session_manager):
        """Test complete successful registration flow."""
        device_id = "test_reader_reg"
        tag_uid = "AA:BB:CC:DD"
        key = "0123456789ABCDEF0123456789ABCDEF"
        
        # 1. Bring device online
        await publish_device_status(mqtt_device_client, device_id, "online")
        await publish_device_mode(mqtt_device_client, device_id, "idle")
        await asyncio.sleep(0.2)
        
        # 2. Start register operation via HTTP
        response = await http_client.post(
            "/register",
            json={"device_id": device_id, "tag_uid": tag_uid, "key": key}
        )
        assert response.status_code == 200
        data = response.json()
        request_id = data["request_id"]
        
        # 3. Simulate device confirming mode change to register
        await publish_device_mode(mqtt_device_client, device_id, "register", request_id, "idle")
        await asyncio.sleep(0.2)
        
        # Verify session is waiting
        session = session_manager.get_operation_session(request_id)
        assert session is not None
        assert session.operation == "register"
        
        # 4. Simulate device sending success event
        success_message = create_mqtt_envelope(
            device_id=device_id,
            event_type="register_success",
            request_id=request_id,
            payload={
                "tag_uid": tag_uid,
                "blocks_written": 4,
                "message": "Tag registered successfully"
            }
        )
        await mqtt_device_client.publish(
            f"devices/{device_id}/register/success",
            json.dumps(success_message)
        )
        await asyncio.sleep(0.2)
        
        # Verify session marked as completed (not success)
        session = session_manager.get_operation_session(request_id)
        assert session.status == "completed"
        assert session.metadata.get("tag_uid") == tag_uid
        # Note: blocks_written is not saved to metadata by handler
        
        # 5. Simulate device returning to idle
        await publish_device_mode(mqtt_device_client, device_id, "idle", request_id, "register")
        await asyncio.sleep(0.2)
        
        # Verify device is idle
        device_state = session_manager.get_device_state(device_id)
        assert device_state.mode.value == "idle"
    
    async def test_register_error_flow(self, mqtt_device_client, http_client, session_manager):
        """Test registration failure flow."""
        device_id = "test_reader_reg_err"
        
        # 1. Bring device online
        await publish_device_status(mqtt_device_client, device_id, "online")
        await publish_device_mode(mqtt_device_client, device_id, "idle")
        await asyncio.sleep(0.2)
        
        # 2. Start register operation
        response = await http_client.post(
            "/register",
            json={
                "device_id": device_id,
                "tag_uid": "AA:BB:CC:DD",
                "key": "0123456789ABCDEF0123456789ABCDEF"
            }
        )
        request_id = response.json()["request_id"]
        
        # 3. Simulate device mode change
        await publish_device_mode(mqtt_device_client, device_id, "register", request_id, "idle")
        await asyncio.sleep(0.2)
        
        # 4. Simulate device sending error event
        error_message = create_mqtt_envelope(
            device_id=device_id,
            event_type="register_error",
            request_id=request_id,
            payload={
                "error": "Failed to write to tag",
                "error_code": "NFC_WRITE_ERROR",
                "retry_possible": True,
                "component": "nfc"
            }
        )
        await mqtt_device_client.publish(
            f"devices/{device_id}/register/error",
            json.dumps(error_message)
        )
        await asyncio.sleep(0.2)
        
        # Verify session marked as error (handler uses "error" status)
        session = session_manager.get_operation_session(request_id)
        assert session.status == "error"
        assert session.metadata.get("error_code") == "NFC_WRITE_ERROR"


@pytest.mark.asyncio
class TestAuthenticationFlow:
    """Test Scenario 3: Authentication Flow"""
    
    async def test_successful_auth_flow(self, mqtt_device_client, http_client, session_manager):
        """Test complete successful authentication flow."""
        device_id = "test_reader_auth"
        tag_uid = "AA:BB:CC:DD"
        user_data = {"user_id": "john.doe", "access_level": 2}
        key = "0123456789ABCDEF0123456789ABCDEF"
        
        # 1. Bring device online
        await publish_device_status(mqtt_device_client, device_id, "online")
        await publish_device_mode(mqtt_device_client, device_id, "idle")
        await asyncio.sleep(0.2)
        
        # 2. Start auth session
        response = await http_client.post("/auth/start", json={"device_id": device_id})
        assert response.status_code == 200
        request_id = response.json()["request_id"]
        
        # 3. Simulate device entering auth mode
        await publish_device_mode(mqtt_device_client, device_id, "auth", request_id, "idle")
        await asyncio.sleep(0.2)
        
        # 4. Simulate tag detection
        tag_detected_message = create_mqtt_envelope(
            device_id=device_id,
            event_type="auth_tag_detected",
            request_id=request_id,
            payload={
                "tag_uid": tag_uid,
                "message": "Tag detected and ready for authentication"
            }
        )
        await mqtt_device_client.publish(
            f"devices/{device_id}/auth/tag_detected",
            json.dumps(tag_detected_message)
        )
        await asyncio.sleep(0.2)
        
        # Verify session updated with tag_uid (handler uses "tag_detected" status)
        session = session_manager.get_operation_session(request_id)
        assert session.status == "tag_detected"
        assert session.metadata.get("tag_uid") == tag_uid
        
        # 5. Send user data via HTTP
        response = await http_client.post(
            f"/auth/{request_id}/user_data",
            json={"key": key, "user_data": user_data}
        )
        assert response.status_code == 200
        
        await asyncio.sleep(0.1)
        
        # 6. Simulate auth success from device
        auth_success_message = create_mqtt_envelope(
            device_id=device_id,
            event_type="auth_success",
            request_id=request_id,
            payload={
                "tag_uid": tag_uid,
                "authenticated": True,
                "message": "Authentication successful",
                "user_data": user_data
            }
        )
        await mqtt_device_client.publish(
            f"devices/{device_id}/auth/success",
            json.dumps(auth_success_message)
        )
        await asyncio.sleep(0.2)
        
        # Verify session marked as completed
        session = session_manager.get_operation_session(request_id)
        assert session.status == "completed"
        # Note: authenticated field is not saved to metadata by handler
        assert session.metadata.get("user_data") == user_data
        
        # 7. Device returns to idle
        await publish_device_mode(mqtt_device_client, device_id, "idle", request_id, "auth")
        await asyncio.sleep(0.2)
        
        device_state = session_manager.get_device_state(device_id)
        assert device_state.mode.value == "idle"
    
    async def test_auth_failed_flow(self, mqtt_device_client, http_client, session_manager):
        """Test authentication failure (wrong key)."""
        device_id = "test_reader_auth_fail"
        tag_uid = "AA:BB:CC:DD"
        
        # 1. Setup device
        await publish_device_status(mqtt_device_client, device_id, "online")
        await publish_device_mode(mqtt_device_client, device_id, "idle")
        await asyncio.sleep(0.2)
        
        # 2. Start auth session
        response = await http_client.post("/auth/start", json={"device_id": device_id})
        request_id = response.json()["request_id"]
        
        # 3. Mode change + tag detected
        await publish_device_mode(mqtt_device_client, device_id, "auth", request_id, "idle")
        await asyncio.sleep(0.1)
        
        tag_detected = create_mqtt_envelope(
            device_id=device_id,
            event_type="auth_tag_detected",
            request_id=request_id,
            payload={"tag_uid": tag_uid}
        )
        await mqtt_device_client.publish(
            f"devices/{device_id}/auth/tag_detected",
            json.dumps(tag_detected)
        )
        await asyncio.sleep(0.2)
        
        # 4. Send user data
        await http_client.post(
            f"/auth/{request_id}/user_data",
            json={"key": "WRONG_KEY", "user_data": {}}
        )
        await asyncio.sleep(0.1)
        
        # 5. Simulate auth failed from device
        auth_failed = create_mqtt_envelope(
            device_id=device_id,
            event_type="auth_failed",
            request_id=request_id,
            payload={
                "tag_uid": tag_uid,
                "authenticated": False,
                "reason": "Invalid key"
            }
        )
        await mqtt_device_client.publish(
            f"devices/{device_id}/auth/failed",
            json.dumps(auth_failed)
        )
        await asyncio.sleep(0.2)
        
        # Verify session marked as failed
        session = session_manager.get_operation_session(request_id)
        assert session.status == "failed"
        # Note: authenticated field is not saved to metadata by handler
        assert "Invalid key" in session.metadata.get("reason", "")


@pytest.mark.asyncio
class TestReadOperation:
    """Test read operation flow."""
    
    async def test_successful_read_flow(self, mqtt_device_client, http_client, session_manager):
        """Test complete successful read flow."""
        device_id = "test_reader_read"
        tag_uid = "AA:BB:CC:DD"
        tag_data = {"block_0": "01020304", "block_1": "05060708"}
        
        # 1. Setup device
        await publish_device_status(mqtt_device_client, device_id, "online")
        await publish_device_mode(mqtt_device_client, device_id, "idle")
        await asyncio.sleep(0.2)
        
        # 2. Start read operation
        response = await http_client.post("/read", json={"device_id": device_id})
        assert response.status_code == 200
        request_id = response.json()["request_id"]
        
        # 3. Device enters read mode
        await publish_device_mode(mqtt_device_client, device_id, "read", request_id, "idle")
        await asyncio.sleep(0.2)
        
        # 4. Simulate read success
        read_success = create_mqtt_envelope(
            device_id=device_id,
            event_type="read_success",
            request_id=request_id,
            payload={
                "tag_uid": tag_uid,
                "message": "Tag read successfully",
                "data": tag_data
            }
        )
        await mqtt_device_client.publish(
            f"devices/{device_id}/read/success",
            json.dumps(read_success)
        )
        await asyncio.sleep(0.2)
        
        # Verify session completed
        session = session_manager.get_operation_session(request_id)
        assert session.status == "completed"
        assert session.metadata.get("tag_uid") == tag_uid
        assert session.metadata.get("data") == tag_data
        
        # 5. Device returns to idle
        await publish_device_mode(mqtt_device_client, device_id, "idle", request_id, "read")
        await asyncio.sleep(0.2)
        
        device_state = session_manager.get_device_state(device_id)
        assert device_state.mode.value == "idle"


@pytest.mark.asyncio
class TestOperationCancellation:
    """Test operation cancellation flows."""
    
    async def test_cancel_waiting_operation(self, mqtt_device_client, http_client, session_manager):
        """Test cancelling an operation before it completes."""
        device_id = "test_reader_cancel"
        
        # 1. Setup device
        await publish_device_status(mqtt_device_client, device_id, "online")
        await publish_device_mode(mqtt_device_client, device_id, "idle")
        await asyncio.sleep(0.2)
        
        # 2. Start read operation
        response = await http_client.post("/read", json={"device_id": device_id})
        request_id = response.json()["request_id"]
        
        # 3. Device enters read mode
        await publish_device_mode(mqtt_device_client, device_id, "read", request_id, "idle")
        await asyncio.sleep(0.2)
        
        # 4. Cancel the operation
        response = await http_client.post(f"/requests/{request_id}/cancel")
        assert response.status_code == 200
        
        await asyncio.sleep(0.1)
        
        # Verify session marked as cancelled
        session = session_manager.get_operation_session(request_id)
        assert session.status == "cancelled"
        
        # 5. Device confirms return to idle
        await publish_device_mode(mqtt_device_client, device_id, "idle", request_id, "read")
        await asyncio.sleep(0.2)
        
        # Verify device is idle
        device_state = session_manager.get_device_state(device_id)
        assert device_state.mode.value == "idle"


@pytest.mark.asyncio
class TestDeviceAvailability:
    """Test device availability checks."""
    
    async def test_cannot_start_operation_on_offline_device(self, mqtt_device_client, http_client):
        """Test that operations fail when device is offline."""
        device_id = "test_reader_offline"
        
        # Device is registered but offline
        session_manager = get_session_manager()
        session_manager.register_device(device_id)
        session_manager.update_device_status(device_id, "offline")
        
        # Try to start read operation
        response = await http_client.post("/read", json={"device_id": device_id})
        # Should fail because device is offline
        assert response.status_code == 503
    
    async def test_cannot_start_operation_on_busy_device(self, mqtt_device_client, http_client, session_manager):
        """Test that operations fail when device is busy."""
        device_id = "test_reader_busy"
        
        # 1. Setup device
        await publish_device_status(mqtt_device_client, device_id, "online")
        await publish_device_mode(mqtt_device_client, device_id, "idle")
        await asyncio.sleep(0.2)
        
        # 2. Start first operation
        response = await http_client.post("/read", json={"device_id": device_id})
        assert response.status_code == 200
        request_id = response.json()["request_id"]
        
        # 3. Device enters read mode
        await publish_device_mode(mqtt_device_client, device_id, "read", request_id, "idle")
        await asyncio.sleep(0.2)
        
        # 4. Try to start second operation while first is in progress
        response = await http_client.post("/register", json={
            "device_id": device_id,
            "tag_uid": "AA:BB:CC:DD",
            "key": "0123456789ABCDEF0123456789ABCDEF"
        })
        # Should fail because device is busy
        assert response.status_code == 503
