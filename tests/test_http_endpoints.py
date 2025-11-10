"""
Tests for HTTP command endpoints.
"""
from fastapi.testclient import TestClient
from tapservice.session_manager import DeviceMode, DeviceStatus


def test_register_device_not_found(client: TestClient):
    """Test register endpoint with non-existent device."""
    response = client.post("/register", json={
        "device_id": "nonexistent_device",
        "tag_uid": "ABC123",
        "key": "secret_key"
    })
    
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_register_device_success(client: TestClient, session_manager):
    """Test register endpoint with available device."""
    # Setup: Register and make device available
    session_manager.register_device("test_device")
    session_manager.update_device_status("test_device", DeviceStatus.online)
    
    response = client.post("/register", json={
        "device_id": "test_device",
        "tag_uid": "ABC123",
        "key": "secret_key"
    })
    
    assert response.status_code == 200
    data = response.json()
    assert "request_id" in data
    assert data["device_id"] == "test_device"
    assert data["status"] == "initiated"
    
    # Verify operation session was created
    operation_session = session_manager.get_operation_session(data["request_id"])
    assert operation_session is not None
    assert operation_session.operation == "register"
    assert operation_session.device_id == "test_device"


def test_register_device_busy(client: TestClient, session_manager):
    """Test register endpoint when device is busy."""
    # Setup: Register device and set it to busy mode
    session_manager.register_device("test_device")
    session_manager.update_device_status("test_device", DeviceStatus.online)
    session_manager.update_device_mode("test_device", DeviceMode.auth)
    
    response = client.post("/register", json={
        "device_id": "test_device",
        "tag_uid": "ABC123",
        "key": "secret_key"
    })
    
    assert response.status_code == 503
    assert "busy" in response.json()["detail"].lower()


def test_auth_start_device_not_found(client: TestClient):
    """Test auth start with non-existent device."""
    response = client.post("/auth/start", json={
        "device_id": "nonexistent_device"
    })
    
    assert response.status_code == 404


def test_auth_start_success(client: TestClient, session_manager):
    """Test auth start with available device."""
    # Setup: Register and make device available
    session_manager.register_device("test_device")
    session_manager.update_device_status("test_device", DeviceStatus.online)
    
    response = client.post("/auth/start", json={
        "device_id": "test_device"
    })
    
    assert response.status_code == 200
    data = response.json()
    assert "request_id" in data
    assert data["device_id"] == "test_device"
    assert data["status"] == "initiated"
    
    # Verify session was created
    auth_session = session_manager.get_operation_session(data["request_id"])
    assert auth_session is not None
    assert auth_session.device_id == "test_device"
    assert auth_session.operation == "auth"


def test_auth_user_data_session_not_found(client: TestClient):
    """Test auth user_data with invalid request_id."""
    response = client.post("/auth/invalid_id/user_data", json={
        "key": "test_key"
    })
    
    assert response.status_code == 404


def test_auth_user_data_session_not_ready(client: TestClient, session_manager):
    """Test auth user_data when session is not in tag_detected status."""
    # Create session in waiting state
    request_id = session_manager.create_operation_session("test_device", "auth")
    
    response = client.post(f"/auth/{request_id}/user_data", json={
        "key": "test_key"
    })
    
    assert response.status_code == 400
    assert "not ready" in response.json()["detail"].lower()


def test_auth_user_data_success(client: TestClient, session_manager):
    """Test auth user_data with valid session."""
    # Setup: Create session and mark tag as detected
    request_id = session_manager.create_operation_session("test_device", "auth")
    session_manager.update_operation_session(request_id, status="tag_detected", tag_uid="ABC123")
    session_manager.register_device("test_device")
    
    response = client.post(f"/auth/{request_id}/user_data", json={
        "key": "test_key",
        "user_data": {"username": "test_user"}
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data["request_id"] == request_id
    assert data["status"] == "processing"


def test_auth_cancel_session_not_found(client: TestClient):
    """Test auth cancel with invalid request_id using unified cancel endpoint."""
    response = client.post("/requests/invalid_id/cancel")
    
    assert response.status_code == 404


def test_auth_cancel_success(client: TestClient, session_manager):
    """Test auth cancel with valid session using unified cancel endpoint."""
    # Setup: Create session (but don't update device mode - event-driven pattern)
    request_id = session_manager.create_operation_session("test_device", "auth")
    session_manager.register_device("test_device")
    
    response = client.post(f"/requests/{request_id}/cancel")
    
    assert response.status_code == 200
    data = response.json()
    assert data["request_id"] == request_id
    assert "cancelled" in data["message"].lower()
    
    # Verify session was marked as cancelled (not deleted)
    session = session_manager.get_operation_session(request_id)
    assert session is not None
    assert session.status == "cancelled"
    
    # Note: Device mode would be reset to idle by MQTT handler when device confirms
    # In event-driven pattern, HTTP endpoint doesn't update device mode immediately


def test_read_device_not_found(client: TestClient):
    """Test read endpoint with non-existent device."""
    response = client.post("/read", json={
        "device_id": "nonexistent_device"
    })
    
    assert response.status_code == 404


def test_read_success(client: TestClient, session_manager):
    """Test read endpoint with available device."""
    # Setup: Register and make device available
    session_manager.register_device("test_device")
    session_manager.update_device_status("test_device", DeviceStatus.online)
    
    response = client.post("/read", json={
        "device_id": "test_device"
    })
    
    assert response.status_code == 200
    data = response.json()
    assert "request_id" in data
    assert data["device_id"] == "test_device"
    assert data["status"] == "initiated"
    
    # Verify operation session was created
    operation_session = session_manager.get_operation_session(data["request_id"])
    assert operation_session is not None
    assert operation_session.operation == "read"
    assert operation_session.device_id == "test_device"


def test_get_device_status_not_found(client: TestClient):
    """Test get device status with non-existent device."""
    response = client.get("/device/nonexistent_device/status")
    
    assert response.status_code == 404


def test_get_device_status_success(client: TestClient, session_manager):
    """Test get device status with existing device."""
    # Setup: Register device
    session_manager.register_device("test_device")
    session_manager.update_device_status("test_device", DeviceStatus.online)
    
    response = client.get("/device/test_device/status")
    
    assert response.status_code == 200
    data = response.json()
    assert data["device_id"] == "test_device"
    assert data["status"] == "online"
    assert data["mode"] == "idle"
    assert "last_seen" in data


def test_get_request_status_not_found(client: TestClient):
    """Test get request status with non-existent request_id."""
    response = client.get("/requests/nonexistent_request/status")
    
    assert response.status_code == 404


def test_get_request_status_success(client: TestClient, session_manager):
    """Test get request status with existing operation."""
    # Setup: Create an operation session
    session_manager.register_device("test_device")
    session_manager.update_device_status("test_device", DeviceStatus.online)
    
    # Create a register operation
    response = client.post("/register", json={
        "device_id": "test_device",
        "tag_uid": "ABC123",
        "key": "secret_key"
    })
    request_id = response.json()["request_id"]
    
    # Query status
    status_response = client.get(f"/requests/{request_id}/status")
    
    assert status_response.status_code == 200
    data = status_response.json()
    assert data["request_id"] == request_id
    assert data["operation"] == "register"
    assert data["device_id"] == "test_device"
    assert data["status"] == "waiting"
    assert "created_at" in data
    assert "metadata" in data


def test_cancel_request_not_found(client: TestClient):
    """Test cancel request with non-existent request_id."""
    response = client.post("/requests/nonexistent_request/cancel")
    
    assert response.status_code == 404


def test_cancel_request_success(client: TestClient, session_manager):
    """Test cancel request for any operation type."""
    # Setup: Create a read operation
    session_manager.register_device("test_device")
    session_manager.update_device_status("test_device", DeviceStatus.online)
    
    response = client.post("/read", json={
        "device_id": "test_device"
    })
    request_id = response.json()["request_id"]
    
    # Cancel the operation
    cancel_response = client.post(f"/requests/{request_id}/cancel")
    
    assert cancel_response.status_code == 200
    data = cancel_response.json()
    assert data["request_id"] == request_id
    assert data["status"] == "cancelled"
    assert "read" in data["message"].lower()
    
    # Verify session was marked as cancelled
    session = session_manager.get_operation_session(request_id)
    assert session.status == "cancelled"
    
    # Verify device mode was reset
    device_state = session_manager.get_device_state("test_device")
    assert device_state.mode == DeviceMode.idle


def test_list_devices_empty(client: TestClient):
    """Test list devices when no devices are registered."""
    response = client.get("/devices")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["devices"] == []
    assert data["page"] == 1
    assert data["page_size"] == 20
    assert data["total_pages"] == 1


def test_list_devices_with_devices(client: TestClient, session_manager):
    """Test list devices with multiple registered devices."""
    # Setup: Register multiple devices
    session_manager.register_device("device_1")
    session_manager.update_device_status("device_1", DeviceStatus.online)
    
    session_manager.register_device("device_2")
    session_manager.update_device_status("device_2", DeviceStatus.offline)
    
    session_manager.register_device("device_3")
    session_manager.update_device_status("device_3", DeviceStatus.online)
    session_manager.update_device_mode("device_3", DeviceMode.auth)
    
    response = client.get("/devices")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert len(data["devices"]) == 3
    assert data["page"] == 1
    assert data["page_size"] == 20
    assert data["total_pages"] == 1
    
    # Verify device data
    devices_by_id = {d["device_id"]: d for d in data["devices"]}
    
    assert devices_by_id["device_1"]["status"] == "online"
    assert devices_by_id["device_1"]["mode"] == "idle"
    
    assert devices_by_id["device_2"]["status"] == "offline"
    assert devices_by_id["device_2"]["mode"] == "idle"
    
    assert devices_by_id["device_3"]["status"] == "online"
    assert devices_by_id["device_3"]["mode"] == "auth"


def test_reset_device_not_found(client: TestClient):
    """Test reset device with non-existent device."""
    response = client.post("/device/nonexistent_device/reset")
    
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_reset_device_idle(client: TestClient, session_manager):
    """Test reset device that is already idle."""
    # Setup: Register device in idle state
    session_manager.register_device("test_device")
    session_manager.update_device_status("test_device", DeviceStatus.online)
    
    response = client.post("/device/test_device/reset")
    
    assert response.status_code == 200
    data = response.json()
    assert data["device_id"] == "test_device"
    assert data["status"] == "reset"
    
    # Verify device is still in idle mode
    device_state = session_manager.get_device_state("test_device")
    assert device_state.mode == DeviceMode.idle
    assert device_state.current_session_id is None


def test_reset_device_with_active_operation(client: TestClient, session_manager):
    """Test reset device that has an active operation running."""
    # Setup: Register device and start an auth operation
    session_manager.register_device("test_device")
    session_manager.update_device_status("test_device", DeviceStatus.online)
    
    auth_response = client.post("/auth/start", json={
        "device_id": "test_device"
    })
    request_id = auth_response.json()["request_id"]
    
    # Note: In event-driven pattern, device mode is NOT immediately updated
    # It would be updated when MQTT handler receives device confirmation
    # For this test, manually set the mode to simulate device having entered auth mode
    session_manager.update_device_mode("test_device", DeviceMode.auth, session_id=request_id)
    
    # Verify device is in auth mode
    device_state = session_manager.get_device_state("test_device")
    assert device_state.mode == DeviceMode.auth
    assert device_state.current_session_id == request_id
    
    # Reset the device
    reset_response = client.post("/device/test_device/reset")
    
    assert reset_response.status_code == 200
    data = reset_response.json()
    assert data["device_id"] == "test_device"
    assert data["status"] == "reset"
    
    # Verify operation was cancelled
    session = session_manager.get_operation_session(request_id)
    assert session.status == "cancelled"
    
    # Note: Device mode would be reset to idle by MQTT handler when device confirms
    # In event-driven pattern, HTTP endpoint doesn't update device mode immediately
    device_state = session_manager.get_device_state("test_device")
    assert device_state.mode == DeviceMode.auth  # Still in auth mode until MQTT confirms



def test_list_devices_pagination(client: TestClient, session_manager):
    """Test devices endpoint pagination."""
    # Setup: Register 5 devices
    for i in range(1, 6):
        session_manager.register_device(f"device_{i}")
        session_manager.update_device_status(f"device_{i}", DeviceStatus.online)
    
    # Get first page with page_size=2
    response = client.get("/devices?page=1&page_size=2")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 5
    assert len(data["devices"]) == 2
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert data["total_pages"] == 3
    
    # Get second page
    response = client.get("/devices?page=2&page_size=2")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 5
    assert len(data["devices"]) == 2
    assert data["page"] == 2
    assert data["page_size"] == 2
    
    # Get last page
    response = client.get("/devices?page=3&page_size=2")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 5
    assert len(data["devices"]) == 1  # Only 1 device on last page
    assert data["page"] == 3


def test_list_requests_empty(client: TestClient):
    """Test list requests when no requests exist."""
    response = client.get("/requests")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["requests"] == []
    assert data["page"] == 1
    assert data["page_size"] == 20
    assert data["total_pages"] == 1


def test_list_requests_with_requests(client: TestClient, session_manager):
    """Test list requests with multiple operations."""
    # Setup: Create multiple operations
    session_manager.register_device("device_1")
    session_manager.update_device_status("device_1", DeviceStatus.online)
    
    session_manager.register_device("device_2")
    session_manager.update_device_status("device_2", DeviceStatus.online)
    
    # Create different types of operations
    auth_response = client.post("/auth/start", json={"device_id": "device_1"})
    auth_request_id = auth_response.json()["request_id"]
    
    client.post("/read", json={"device_id": "device_2"})
    
    # Reset device_1 to idle for register operation
    session_manager.update_device_mode("device_1", DeviceMode.idle, session_id=None)
    register_response = client.post("/register", json={
        "device_id": "device_1",
        "tag_uid": "ABC123",
        "key": "secret"
    })
    register_request_id = register_response.json()["request_id"]
    
    # List all requests
    response = client.get("/requests")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert len(data["requests"]) == 3
    assert data["page"] == 1
    assert data["total_pages"] == 1
    
    # Verify requests are sorted by created_at descending (newest first)
    request_ids = [r["request_id"] for r in data["requests"]]
    assert register_request_id == request_ids[0]  # Most recent
    assert auth_request_id == request_ids[2]  # Oldest


def test_list_requests_filter_by_device(client: TestClient, session_manager):
    """Test list requests filtered by device_id."""
    # Setup
    session_manager.register_device("device_1")
    session_manager.update_device_status("device_1", DeviceStatus.online)
    
    session_manager.register_device("device_2")
    session_manager.update_device_status("device_2", DeviceStatus.online)
    
    # Create operations on different devices
    client.post("/auth/start", json={"device_id": "device_1"})
    client.post("/read", json={"device_id": "device_2"})
    
    # Reset device_1 to idle for second operation
    session_manager.update_device_mode("device_1", DeviceMode.idle, session_id=None)
    client.post("/auth/start", json={"device_id": "device_1"})
    
    # Filter by device_1
    response = client.get("/requests?device_id=device_1")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["requests"]) == 2
    assert all(r["device_id"] == "device_1" for r in data["requests"])


def test_list_requests_filter_by_operation(client: TestClient, session_manager):
    """Test list requests filtered by operation type."""
    # Setup
    session_manager.register_device("device_1")
    session_manager.update_device_status("device_1", DeviceStatus.online)
    
    # Create different operations
    client.post("/auth/start", json={"device_id": "device_1"})
    
    # Reset device to idle for second operation
    session_manager.update_device_mode("device_1", DeviceMode.idle, session_id=None)
    client.post("/read", json={"device_id": "device_1"})
    
    # Reset device to idle for third operation
    session_manager.update_device_mode("device_1", DeviceMode.idle, session_id=None)
    client.post("/auth/start", json={"device_id": "device_1"})
    
    # Filter by auth
    response = client.get("/requests?operation=auth")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert all(r["operation"] == "auth" for r in data["requests"])


def test_list_requests_filter_by_status(client: TestClient, session_manager):
    """Test list requests filtered by status."""
    # Setup
    session_manager.register_device("device_1")
    session_manager.update_device_status("device_1", DeviceStatus.online)
    
    # Create operations and modify status
    auth_response = client.post("/auth/start", json={"device_id": "device_1"})
    auth_request_id = auth_response.json()["request_id"]
    
    # Reset device to idle for second operation
    session_manager.update_device_mode("device_1", DeviceMode.idle, session_id=None)
    read_response = client.post("/read", json={"device_id": "device_1"})
    read_request_id = read_response.json()["request_id"]
    
    # Cancel one operation
    client.post(f"/requests/{read_request_id}/cancel")
    
    # Filter by waiting status
    response = client.get("/requests?status=waiting")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["requests"][0]["request_id"] == auth_request_id
    assert data["requests"][0]["status"] == "waiting"
    
    # Filter by cancelled status
    response = client.get("/requests?status=cancelled")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["requests"][0]["request_id"] == read_request_id
    assert data["requests"][0]["status"] == "cancelled"


def test_list_requests_pagination(client: TestClient, session_manager):
    """Test requests endpoint pagination."""
    # Setup: Create 5 operations
    session_manager.register_device("device_1")
    session_manager.update_device_status("device_1", DeviceStatus.online)
    
    for i in range(5):
        if i > 0:
            # Reset device to idle for subsequent operations
            session_manager.update_device_mode("device_1", DeviceMode.idle, session_id=None)
        client.post("/auth/start", json={"device_id": "device_1"})
    
    # Get first page with page_size=2
    response = client.get("/requests?page=1&page_size=2")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 5
    assert len(data["requests"]) == 2
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert data["total_pages"] == 3
    
    # Get second page
    response = client.get("/requests?page=2&page_size=2")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 5
    assert len(data["requests"]) == 2
    assert data["page"] == 2
    
    # Get last page
    response = client.get("/requests?page=3&page_size=2")
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 5
    assert len(data["requests"]) == 1  # Only 1 request on last page
    assert data["page"] == 3
