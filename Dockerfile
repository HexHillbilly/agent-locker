# Minimal runtime image for the Agent Locker daemon (FastAPI + aiosqlite).
# Plain uvicorn (no [standard] extras) so nothing needs to compile on musl.
FROM python:3.11-alpine

# Non-root user
RUN addgroup -S locker && adduser -S locker -G locker

WORKDIR /app

COPY pyproject.toml ./
COPY lockerd/ lockerd/
RUN pip install --no-cache-dir .

# WAL-mode SQLite lives here (see docker-compose volume)
RUN mkdir -p /data && chown -R locker:locker /data /app

USER locker

ENV LOCKER_DB_PATH=/data/locker.db \
    LOCKER_MODE=local \
    LOCKER_HOST=0.0.0.0 \
    LOCKER_PORT=8000

EXPOSE 8000

CMD ["python", "-m", "lockerd"]
