"""
Pytest configuration and fixtures for TapService tests.
"""
import pytest
from fastapi.testclient import TestClient
from tapservice.main import app
from tapservice.session_manager import get_session_manager


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


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
