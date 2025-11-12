# Contributing to TapService

Thank you for contributing to TapService! This guide covers development workflows, testing, and maintenance tasks.

## Development Setup

```bash
git clone <repo-url>
cd TapService
uv sync                       # Install dependencies
uv run uvicorn tapservice.main:app --reload  # Run development server
```

## Running Tests

```bash
uv run pytest                                        # Run all tests
uv run pytest --cov=tapservice --cov-report=html    # With coverage report
uv run pytest tests/test_schema_compliance.py -v    # Run schema validation tests
```

## Project Structure

- `tapservice/main.py` - FastAPI application setup
- `tapservice/routes.py` - HTTP endpoints
- `tapservice/mqtt_client.py` - MQTT connection management
- `tapservice/mqtt_handlers.py` - MQTT event handlers (state updates)
- `tapservice/schemas.py` - Pydantic models for HTTP API
- `tapservice/session_manager.py` - In-memory state management
- `tapservice/settings.py` - Configuration
- `tapservice/mqtt_protocol_models.py` - **Auto-generated, DO NOT EDIT**

## MQTT Protocol Schema Updates

TapService uses auto-generated Pydantic models from the [mqtt-protocol repository](https://github.com/LibreTap/mqtt-protocol) JSON schemas. When the mqtt-protocol schemas are updated, follow this workflow:

### Regenerating Models

```bash
# Download latest schemas from GitHub and regenerate models
uv run python scripts/generate_mqtt_models.py

# Run tests to verify compatibility
uv run pytest tests/test_schema_compliance.py -v

# If tests pass, commit the regenerated models
git add tapservice/mqtt_protocol_models.py
git commit -m "chore: regenerate MQTT protocol models"
```

### Important Notes

- **Never edit** `tapservice/mqtt_protocol_models.py` manually - it will be overwritten
- Always run schema compliance tests after regenerating
- The CI/CD pipeline will validate models are up-to-date on PRs
- Weekly automated checks run Mondays at 9 AM UTC

### When Schema Changes Break Tests

If regenerating models causes test failures:

1. Check `tests/test_schema_compliance.py` for validation errors
2. Review the mqtt-protocol CHANGELOG for breaking changes
3. Update message handling in `mqtt_handlers.py` if needed
4. Update HTTP schemas in `schemas.py` if API contracts changed
5. Update tests to match new schema requirements

## Commit Message Conventions

We use conventional commits for clarity:

- `feat:` - New features
- `fix:` - Bug fixes
- `chore:` - Maintenance (deps, generated files, config)
- `docs:` - Documentation updates
- `test:` - Test updates
- `refactor:` - Code restructuring without behavior changes

Examples:
```
chore: regenerate MQTT protocol models
feat: add device heartbeat monitoring
fix: handle missing request_id in auth flow
docs: update MQTT integration examples
```

## Testing Local MQTT Integration

For local development, we recommend EMQX (simpler than Mosquitto for testing):

```bash
# Start EMQX broker with Docker
docker run -d --name emqx -p 1883:1883 -p 18083:18083 emqx/emqx:latest

# Configure TapService (or use .env file)
export TAPSERVICE_MQTT_HOST=localhost
export TAPSERVICE_MQTT_PORT=1883

# Run TapService
uv run uvicorn tapservice.main:app --reload

# Simulate device messages using EMQX WebSocket client
# Visit http://localhost:18083 → WebSocket → Connect → Publish
# Or use mosquitto-clients:
docker exec emqx mosquitto_pub -t 'devices/test_reader/status' \
  -m '{"version":"1.0","timestamp":"2025-11-11T12:00:00Z","device_id":"test_reader","event_type":"status_change","request_id":"test","payload":{"status":"online"}}'
```

**EMQX Dashboard**: http://localhost:18083 (credentials: `admin` / `public`)
- Monitor connections, subscriptions, and message flow
- Use built-in WebSocket client for testing
- View real-time metrics and logs

## Adding New Operations

When adding a new operation type (like register/auth/read):

1. Add endpoint to `routes.py` following existing patterns
2. Add MQTT command topic to `mqtt_client.py`
3. Add event handlers to `mqtt_handlers.py`
4. Update `COMMON_NFC_RESPONSES` in `routes.py` for error handling
5. Extend `OperationSession.metadata` in `session_manager.py` if needed
6. Add comprehensive tests to `tests/test_http_endpoints.py` and `tests/test_mqtt_integration.py`
7. Update API documentation in README.md

## Code Style

- Use type hints for all function parameters and returns
- Follow existing patterns (dataclasses, `typing.Optional`)
- Include `request_id` in log messages with `extra={"request_id": request_id}`
- Keep device as authoritative source of truth - HTTP never mutates state directly

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with clear commit messages
3. Run all tests and ensure they pass
4. Update documentation if needed
5. Submit PR with description of changes
6. CI/CD will validate tests, schema compliance, and model freshness

## Questions?

- Review the [MQTT Protocol Specification](https://github.com/LibreTap/mqtt-protocol)
- Check existing tests for usage examples
- Open an issue for clarification on architecture decisions
