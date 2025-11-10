"""
In-memory session management for tracking device states and authentication flows.

Provides correlation IDs for auth requests and tracks device modes/status.
"""
import uuid
from typing import Dict, Optional
from datetime import datetime, UTC
from enum import Enum
from dataclasses import dataclass, field
import asyncio


class DeviceMode(str, Enum):
    """Device operation modes."""
    idle = "idle"
    auth = "auth"
    read = "read"
    register = "register"


class DeviceStatus(str, Enum):
    """Device connection status."""
    online = "online"
    offline = "offline"
    busy = "busy"


@dataclass
class OperationSession:
    """Tracks any async operation (auth, register, read)."""
    request_id: str
    device_id: str
    operation: str  # "auth", "register", "read"
    created_at: datetime
    status: str = "waiting"  # waiting, tag_detected, processing, completed, error, cancelled
    metadata: dict = field(default_factory=dict)  # operation-specific data (tag_uid, key, etc.)


@dataclass
class DeviceState:
    """Tracks the state of a single NFC device."""
    device_id: str
    status: DeviceStatus = DeviceStatus.offline
    mode: DeviceMode = DeviceMode.idle
    last_seen: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    current_session_id: Optional[str] = None


class SessionManager:
    """
    Manages ephemeral sessions for auth flows and device states.
    
    No persistence - all state is in-memory and lost on restart.
    Future: can be backed by Redis for multi-instance deployments.
    """
    
    def __init__(self):
        self._operation_sessions: Dict[str, OperationSession] = {}
        self._device_states: Dict[str, DeviceState] = {}
        # Single event queue for all devices - broadcasts to all WebSocket clients
        self._event_queue: Optional[asyncio.Queue] = None
        
    # ---- Operation Session Management (unified for auth/register/read) ----
    
    def create_operation_session(self, device_id: str, operation: str) -> str:
        """Create a new operation session and return the request_id."""
        request_id = str(uuid.uuid4())
        session = OperationSession(
            request_id=request_id,
            device_id=device_id,
            operation=operation,
            created_at=datetime.now(tz=UTC)
        )
        self._operation_sessions[request_id] = session
        return request_id
    
    def get_operation_session(self, request_id: str) -> Optional[OperationSession]:
        """Retrieve an operation session by request_id."""
        return self._operation_sessions.get(request_id)
    
    def update_operation_session(
        self, 
        request_id: str, 
        status: Optional[str] = None,
        **metadata
    ):
        """Update an operation session with new status and/or metadata."""
        session = self._operation_sessions.get(request_id)
        if session:
            if status is not None:
                session.status = status
            if metadata:
                session.metadata.update(metadata)
    
    def cancel_operation_session(self, request_id: str):
        """Cancel an operation session and mark it as cancelled."""
        session = self._operation_sessions.get(request_id)
        if session:
            session.status = "cancelled"
    
    def delete_operation_session(self, request_id: str):
        """Remove an operation session (cleanup after completion)."""
        self._operation_sessions.pop(request_id, None)
    
    def list_operation_sessions(self) -> list[OperationSession]:
        """List all operation sessions."""
        return list(self._operation_sessions.values())
    
    # ---- Device State Management ----
    
    def register_device(self, device_id: str):
        """Register a new device or update its last_seen time."""
        if device_id not in self._device_states:
            self._device_states[device_id] = DeviceState(device_id=device_id)
            # Create global event queue if not exists
            if self._event_queue is None:
                self._event_queue = asyncio.Queue()
        else:
            self._device_states[device_id].last_seen = datetime.now(tz=UTC)
    
    def get_device_state(self, device_id: str) -> Optional[DeviceState]:
        """Get the current state of a device."""
        return self._device_states.get(device_id)
    
    def update_device_status(self, device_id: str, status: DeviceStatus):
        """Update device connection status."""
        if device_id in self._device_states:
            self._device_states[device_id].status = status
            self._device_states[device_id].last_seen = datetime.now(tz=UTC)
    
    def update_device_mode(self, device_id: str, mode: DeviceMode, session_id: Optional[str] = None):
        """Update device operation mode."""
        if device_id in self._device_states:
            self._device_states[device_id].mode = mode
            self._device_states[device_id].current_session_id = session_id
            self._device_states[device_id].last_seen = datetime.now(tz=UTC)
    
    def is_device_available(self, device_id: str) -> bool:
        """Check if device is online and idle."""
        state = self._device_states.get(device_id)
        if not state:
            return False
        return state.status == DeviceStatus.online and state.mode == DeviceMode.idle
    
    def list_devices(self) -> list[DeviceState]:
        """List all tracked devices."""
        return list(self._device_states.values())
    
    # ---- Event Queue Management (for WebSocket streaming) ----
    
    def get_event_queue(self) -> Optional[asyncio.Queue]:
        """Get the global event queue (used by WebSocket to stream events from all devices)."""
        if self._event_queue is None:
            self._event_queue = asyncio.Queue()
        return self._event_queue
    
    async def publish_event(self, device_id: str, event: dict):
        """Publish an event to all subscribers (all WebSocket clients)."""
        if self._event_queue is None:
            self._event_queue = asyncio.Queue()
        await self._event_queue.put(event)


# Global singleton instance
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get the global SessionManager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
