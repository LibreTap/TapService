"""
MQTT client for TapService - connects to broker and routes device messages.

This module implements the MQTT Protocol Specification for TapService:
- Subscribes to device topics using wildcards (devices/+/...)
- Routes incoming messages to appropriate handlers
- Publishes commands to devices
- Validates message envelopes according to spec

Based on MQTT_PROTOCOL_SPEC.md from mqtt-protocol directory.
"""
import asyncio
import json
import logging
from datetime import datetime, UTC
from typing import Optional
from contextlib import asynccontextmanager

from aiomqtt import Client, MqttError
from pydantic import ValidationError

from .settings import get_settings
from .mqtt_protocol_models import (
    MqttMessageEnvelope,
    StatusChange,
    ModeChange,
    TagDetected,
    SuccessRegisterRead,
    SuccessAuth,
    FailedAuth,
    Error as MqttError_,
)
from .mqtt_handlers import (
    on_device_status_change,
    on_device_mode_change,
    on_register_success,
    on_register_error,
    on_auth_tag_detected,
    on_auth_success,
    on_auth_failed,
    on_auth_error,
    on_read_success,
    on_read_error,
)

logger = logging.getLogger("tapservice.mqtt")


class MQTTClient:
    """
    Async MQTT client for TapService.
    
    Manages connection to MQTT broker, subscribes to device topics,
    and routes messages to appropriate handlers.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.client: Optional[Client] = None
        self._running = False
        self._tasks = []
    
    async def connect(self):
        """Connect to MQTT broker and start message processing."""
        try:
            # Create MQTT client with settings
            hostname = self.settings.mqtt_host
            port = self.settings.mqtt_port
            
            logger.info(f"Connecting to MQTT broker at {hostname}:{port}")
            
            # Create client with authentication if provided
            if self.settings.mqtt_username and self.settings.mqtt_password:
                self.client = Client(
                    hostname=hostname,
                    port=port,
                    username=self.settings.mqtt_username,
                    password=self.settings.mqtt_password,
                )
            else:
                self.client = Client(
                    hostname=hostname,
                    port=port,
                )
            
            # Connect to broker
            await self.client.__aenter__()
            
            # Subscribe to all device topics using wildcards
            await self._subscribe_to_topics()
            
            # Start message processing task
            self._running = True
            task = asyncio.create_task(self._process_messages())
            self._tasks.append(task)
            
            logger.info("MQTT client connected and subscribed to device topics")
            
        except MqttError as e:
            logger.error(f"Failed to connect to MQTT broker: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during MQTT connection: {e}")
            raise
    
    async def disconnect(self):
        """Disconnect from MQTT broker and cleanup."""
        self._running = False
        
        # Cancel all tasks
        for task in self._tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        
        # Disconnect client
        if self.client:
            try:
                await self.client.__aexit__(None, None, None)
                logger.info("MQTT client disconnected")
            except Exception as e:
                logger.error(f"Error disconnecting MQTT client: {e}")
    
    async def _subscribe_to_topics(self):
        """Subscribe to device event topics (not command topics).
        
        Note: We only subscribe to events FROM devices, not commands TO devices.
        Commands we publish (start, cancel, verify, reset) should not trigger our handlers.
        """
        if not self.client:
            return
        
        topics = [
            "devices/+/status",              # Device online/offline status
            "devices/+/mode",                # Device mode changes
            "devices/+/heartbeat",           # Device heartbeat
            # Register events (not start/cancel commands)
            "devices/+/register/success",
            "devices/+/register/error",
            # Auth events (not start/verify/cancel commands)
            "devices/+/auth/tag_detected",
            "devices/+/auth/success",
            "devices/+/auth/failed",
            "devices/+/auth/error",
            # Read events (not start/cancel commands)
            "devices/+/read/success",
            "devices/+/read/error",
        ]
        
        for topic in topics:
            await self.client.subscribe(topic)
            logger.debug(f"Subscribed to MQTT topic: {topic}")
    
    async def _process_messages(self):
        """Process incoming MQTT messages."""
        if not self.client:
            return
        
        try:
            async for message in self.client.messages:
                try:
                    await self._route_message(message)
                except Exception as e:
                    logger.error(f"Error processing MQTT message: {e}", exc_info=True)
        except asyncio.CancelledError:
            logger.info("MQTT message processing cancelled")
        except Exception as e:
            logger.error(f"Error in MQTT message loop: {e}", exc_info=True)
    
    async def _route_message(self, message):
        """Route MQTT message to appropriate handler based on topic."""
        topic = str(message.topic)
        topic_parts = topic.split("/")
        
        if len(topic_parts) < 3:
            logger.warning(f"Invalid topic format: {topic}")
            return
        
        device_id = topic_parts[1]
        operation = topic_parts[2]
        
        # Parse message payload
        try:
            payload = json.loads(message.payload.decode())
        except json.JSONDecodeError:
            logger.error(f"Failed to decode JSON payload from topic {topic}")
            return
        
        # Validate envelope using generated Pydantic model
        try:
            envelope = MqttMessageEnvelope.model_validate(payload)
        except ValidationError as e:
            logger.error(
                f"Invalid MQTT envelope from {device_id} on topic {topic}: {e}",
                extra={"device_id": device_id, "validation_errors": e.errors()}
            )
            return
        
        # Verify device_id matches topic
        if envelope.device_id != device_id:
            logger.warning(
                f"Device ID mismatch: topic has {device_id}, envelope has {envelope.device_id}"
            )
            return
        
        # Extract common fields
        request_id = str(envelope.request_id)
        event_payload = envelope.payload
        
        logger.info(
            f"Received MQTT message on topic: {topic}",
            extra={"device_id": device_id, "request_id": request_id, "event_type": envelope.event_type.value}
        )
        
        # Route to appropriate handler with payload validation
        try:
            if operation == "status":
                # Validate status_change payload
                try:
                    status_payload = StatusChange.model_validate(event_payload)
                    await on_device_status_change(device_id, status_payload.status.value)
                except ValidationError as e:
                    logger.error(f"Invalid status_change payload from {device_id}: {e}")
                    return
            
            elif operation == "mode":
                # Validate mode_change payload
                try:
                    mode_payload = ModeChange.model_validate(event_payload)
                    await on_device_mode_change(
                        device_id,
                        mode_payload.mode.value,
                        session_id=event_payload.get("session_id")
                    )
                except ValidationError as e:
                    logger.error(f"Invalid mode_change payload from {device_id}: {e}")
                    return
            
            elif operation == "register":
                action = topic_parts[3] if len(topic_parts) > 3 else None
                logger.info(f"Routing register event: {action}", extra={"device_id": device_id, "request_id": request_id})
                await self._handle_register_event(device_id, action, request_id, event_payload)
            
            elif operation == "auth":
                action = topic_parts[3] if len(topic_parts) > 3 else None
                logger.info(f"Routing auth event: {action}", extra={"device_id": device_id, "request_id": request_id})
                await self._handle_auth_event(device_id, action, request_id, event_payload)
            
            elif operation == "read":
                action = topic_parts[3] if len(topic_parts) > 3 else None
                logger.info(f"Routing read event: {action}", extra={"device_id": device_id, "request_id": request_id})
                await self._handle_read_event(device_id, action, request_id, event_payload)
            
            elif operation == "heartbeat":
                # Heartbeat events - log for now
                logger.debug(f"Heartbeat from {device_id}: {payload}")
            
            else:
                logger.warning(f"Unknown operation: {operation} from {device_id}")
        
        except Exception as e:
            logger.error(f"Error handling {operation} event from {device_id}: {e}", exc_info=True)
    
    async def _handle_register_event(self, device_id: str, action: Optional[str], request_id: str, payload: dict):
        """Route register operation events to handlers with payload validation."""
        if action == "success":
            try:
                success_payload = SuccessRegisterRead.model_validate(payload)
                await on_register_success(device_id, request_id, success_payload.tag_uid)
            except ValidationError as e:
                logger.error(f"Invalid register_success payload from {device_id}: {e}")
        elif action == "error":
            try:
                error_payload = MqttError_.model_validate(payload)
                await on_register_error(
                    device_id,
                    request_id,
                    error_payload.error,
                    error_payload.error_code.value
                )
            except ValidationError as e:
                logger.error(f"Invalid register_error payload from {device_id}: {e}")
        else:
            logger.warning(f"Unknown register action: {action}")
    
    async def _handle_auth_event(self, device_id: str, action: Optional[str], request_id: str, payload: dict):
        """Route auth operation events to handlers with payload validation."""
        if action == "tag_detected":
            try:
                tag_payload = TagDetected.model_validate(payload)
                await on_auth_tag_detected(device_id, request_id, tag_payload.tag_uid)
            except ValidationError as e:
                logger.error(f"Invalid auth_tag_detected payload from {device_id}: {e}")
        elif action == "success":
            try:
                success_payload = SuccessAuth.model_validate(payload)
                await on_auth_success(
                    device_id,
                    request_id,
                    success_payload.tag_uid,
                    success_payload.user_data or {}
                )
            except ValidationError as e:
                logger.error(f"Invalid auth_success payload from {device_id}: {e}")
        elif action == "failed":
            try:
                failed_payload = FailedAuth.model_validate(payload)
                await on_auth_failed(device_id, request_id, failed_payload.reason)
            except ValidationError as e:
                logger.error(f"Invalid auth_failed payload from {device_id}: {e}")
        elif action == "error":
            try:
                error_payload = MqttError_.model_validate(payload)
                await on_auth_error(
                    device_id,
                    request_id,
                    error_payload.error,
                    error_payload.error_code.value
                )
            except ValidationError as e:
                logger.error(f"Invalid auth_error payload from {device_id}: {e}")
        else:
            logger.warning(f"Unknown auth action: {action}")
    
    async def _handle_read_event(self, device_id: str, action: Optional[str], request_id: str, payload: dict):
        """Route read operation events to handlers with payload validation."""
        if action == "success":
            # Read success uses same schema as register success (SuccessRegisterRead)
            # but for read operations, we expect "data" instead of "blocks_written"
            # For now, validate basic structure
            tag_uid = payload.get("tag_uid", "")
            data = payload.get("data", {})
            if tag_uid:
                await on_read_success(device_id, request_id, tag_uid, data)
            else:
                logger.error(f"Missing tag_uid in read_success payload from {device_id}")
        elif action == "error":
            try:
                error_payload = MqttError_.model_validate(payload)
                await on_read_error(
                    device_id,
                    request_id,
                    error_payload.error,
                    error_payload.error_code.value
                )
            except ValidationError as e:
                logger.error(f"Invalid read_error payload from {device_id}: {e}")
        else:
            logger.warning(f"Unknown read action: {action}")
    
    async def publish_command(
        self,
        device_id: str,
        operation: str,
        action: str,
        request_id: str,
        payload: dict,
    ):
        """
        Publish a command to a device.
        
        Args:
            device_id: Target device ID
            operation: Operation type (register, auth, read)
            action: Action to perform (start, cancel, verify)
            request_id: Request ID for tracking
            payload: Command-specific payload
        """
        if not self.client:
            logger.warning(
                "Cannot publish command: MQTT client not connected",
                extra={"device_id": device_id, "request_id": request_id}
            )
            return
        
        # Build topic
        topic = f"devices/{device_id}/{operation}/{action}"
        
        # Create message envelope according to protocol spec
        envelope = {
            "version": "1.0",
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "device_id": device_id,
            "event_type": f"{operation}_{action}",
            "request_id": request_id,
            "payload": payload
        }
        
        # Publish with QoS 1 (delivery guarantee)
        try:
            message = json.dumps(envelope)
            await self.client.publish(topic, message, qos=1)
            logger.info(
                f"Published command to {topic}",
                extra={"device_id": device_id, "request_id": request_id}
            )
        except Exception as e:
            logger.error(
                f"Failed to publish command to {topic}: {e}",
                extra={"device_id": device_id, "request_id": request_id}
            )


# Global MQTT client instance
_mqtt_client: Optional[MQTTClient] = None


def get_mqtt_client() -> MQTTClient:
    """Get the global MQTT client instance."""
    global _mqtt_client
    if _mqtt_client is None:
        _mqtt_client = MQTTClient()
    return _mqtt_client


@asynccontextmanager
async def mqtt_lifespan():
    """
    Context manager for MQTT client lifecycle.
    
    Use with FastAPI lifespan to manage connection.
    """
    client = get_mqtt_client()
    try:
        await client.connect()
        yield client
    finally:
        await client.disconnect()
