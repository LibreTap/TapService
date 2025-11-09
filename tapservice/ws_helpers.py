from typing import Type, TypeVar, Callable
from fastapi import WebSocket
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)
E = TypeVar("E", bound=BaseModel)

async def receive_validated(
    websocket: WebSocket,
    model: Type[T],
    error_factory: Callable[[str, ValidationError], E],
) -> T:
    """Receive JSON from a websocket and validate it into the given model.

    error_factory: function taking (code, validation_error) returning an error model instance
    """
    data = await websocket.receive_json()
    try:
        return model(**data)
    except ValidationError as ve:
        error_instance = error_factory("INVALID_REQUEST", ve)
        await websocket.send_json(error_instance.model_dump())
        await websocket.close(code=1008)
        raise
