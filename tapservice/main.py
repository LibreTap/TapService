from fastapi import FastAPI
from .logging_config import setup_logging
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute

from .routes import router

def custom_generate_unique_id(route: APIRoute):
    return f"{route.name}"


setup_logging()

app = FastAPI(
    title='TapService',
    generate_unique_id_function=custom_generate_unique_id,
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
