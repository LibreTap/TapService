import logging
from logging.config import dictConfig


def setup_logging() -> None:
    """Configure application-wide structured logging.
    Uses a simple dictConfig; can be extended later for JSON formatting.
    """
    dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
            }
        },
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "formatter": "standard",
            }
        },
        "loggers": {
            "tapservice": {
                "handlers": ["default"],
                "level": "INFO",
                "propagate": False
            },
            "tapservice.ws": {
                "handlers": ["default"],
                "level": "INFO",
                "propagate": False
            },
            "tapservice.mqtt": {
                "handlers": ["default"],
                "level": "INFO",
                "propagate": False
            }
        },
        "root": {
            "handlers": ["default"],
            "level": "WARNING"
        },
    })

    logging.getLogger("tapservice").info("Logging configured")
