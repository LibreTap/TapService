# Install uv
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Change the working directory to the `app` directory
WORKDIR /app

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-editable

# Copy the requirements files into the intermediate image
ADD pyproject.toml uv.lock /app/

# Sync the project
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable

FROM python:3.12-slim

# Create non-root user with explicit UID/GID for volume permissions
RUN groupadd -g 1000 app && useradd -u 1000 -g app -m app

# Copy the environment, but not the source code
COPY --from=builder --chown=app:app /app/.venv /app/.venv

# Copy the application code and scripts
COPY --chown=app:app ./tapservice /app/tapservice
COPY --chown=app:app ./scripts /app/scripts

# Set the working directory
WORKDIR /app

# Switch to non-root user
USER app

# Expose port 80
EXPOSE 80

# Run the application
CMD ["/app/.venv/bin/python3", "-m", "fastapi", "run", "tapservice/main.py", "--port", "80"]