from contextlib import asynccontextmanager
from fastapi import FastAPI
from .logging_config import setup_logging
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
import logging

from .routes import router
from .mqtt_client import get_mqtt_client

logger = logging.getLogger("tapservice")


def custom_generate_unique_id(route: APIRoute):
    return f"{route.name}"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle - startup and shutdown events."""
    # Startup: Connect to MQTT broker
    logger.info("Starting TapService...")
    mqtt_client = get_mqtt_client()
    try:
        await mqtt_client.connect()
        logger.info("TapService started successfully")
        yield
    finally:
        # Shutdown: Disconnect from MQTT broker
        logger.info("Shutting down TapService...")
        await mqtt_client.disconnect()
        logger.info("TapService shutdown complete")


setup_logging()

app = FastAPI(
    title='TapService',
    generate_unique_id_function=custom_generate_unique_id,
    lifespan=lifespan,
)


origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)

app.include_router(router)
