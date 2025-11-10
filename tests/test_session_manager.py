"""
Tests for session management functionality.
"""
import pytest
from tapservice.session_manager import (
    SessionManager,
    DeviceMode,
    DeviceStatus,
)


def test_create_auth_session():
    """Test creating an authentication session."""
    manager = SessionManager()
    device_id = "test_device"
    
    request_id = manager.create_operation_session(device_id, "auth")
    
    assert request_id is not None
    session = manager.get_operation_session(request_id)
    assert session is not None
    assert session.device_id == device_id
    assert session.operation == "auth"
    assert session.status == "waiting"


def test_update_auth_session():
    """Test updating an authentication session."""
    manager = SessionManager()
    request_id = manager.create_operation_session("test_device", "auth")
    
    manager.update_operation_session(request_id, status="tag_detected", tag_uid="ABC123")
    
    session = manager.get_operation_session(request_id)
    assert session.metadata.get("tag_uid") == "ABC123"
    assert session.status == "tag_detected"


def test_delete_auth_session():
    """Test deleting an authentication session."""
    manager = SessionManager()
    request_id = manager.create_operation_session("test_device", "auth")
    
    manager.delete_operation_session(request_id)
    
    assert manager.get_operation_session(request_id) is None


def test_register_device():
    """Test registering a device."""
    manager = SessionManager()
    device_id = "test_device"
    
    manager.register_device(device_id)
    
    device_state = manager.get_device_state(device_id)
    assert device_state is not None
    assert device_state.device_id == device_id
    assert device_state.status == DeviceStatus.offline
    assert device_state.mode == DeviceMode.idle


def test_update_device_status():
    """Test updating device status."""
    manager = SessionManager()
    device_id = "test_device"
    manager.register_device(device_id)
    
    manager.update_device_status(device_id, DeviceStatus.online)
    
    device_state = manager.get_device_state(device_id)
    assert device_state.status == DeviceStatus.online


def test_update_device_mode():
    """Test updating device mode."""
    manager = SessionManager()
    device_id = "test_device"
    manager.register_device(device_id)
    
    manager.update_device_mode(device_id, DeviceMode.auth, session_id="test_session")
    
    device_state = manager.get_device_state(device_id)
    assert device_state.mode == DeviceMode.auth
    assert device_state.current_session_id == "test_session"


def test_is_device_available():
    """Test checking if device is available."""
    manager = SessionManager()
    device_id = "test_device"
    manager.register_device(device_id)
    
    # Device is offline and idle - not available
    assert not manager.is_device_available(device_id)
    
    # Device is online but busy - not available
    manager.update_device_status(device_id, DeviceStatus.online)
    manager.update_device_mode(device_id, DeviceMode.auth)
    assert not manager.is_device_available(device_id)
    
    # Device is online and idle - available
    manager.update_device_mode(device_id, DeviceMode.idle)
    assert manager.is_device_available(device_id)


def test_list_devices():
    """Test listing all devices."""
    manager = SessionManager()
    
    manager.register_device("device_1")
    manager.register_device("device_2")
    
    devices = manager.list_devices()
    assert len(devices) == 2
    device_ids = [d.device_id for d in devices]
    assert "device_1" in device_ids
    assert "device_2" in device_ids


def test_get_event_queue():
    """Test getting global event queue."""
    manager = SessionManager()
    
    queue = manager.get_event_queue()
    
    assert queue is not None
    assert queue.empty()


@pytest.mark.asyncio
async def test_publish_event():
    """Test publishing an event to global queue."""
    manager = SessionManager()
    
    event = {"event_type": "test_event", "device_id": "test_device", "data": "test"}
    await manager.publish_event("test_device", event)
    
    queue = manager.get_event_queue()
    received_event = await queue.get()
    assert received_event == event
