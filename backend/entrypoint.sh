#!/bin/bash
# ==============================================================================
# UniVex Backend Entrypoint
# Purpose: Run Prisma migrations then start the FastAPI application
# ==============================================================================

set -e

echo "=== UniVex Backend Startup ==="

# Run Prisma migrations to ensure the database schema is up to date.
# 'migrate deploy' is idempotent: it applies only pending migrations and is
# safe to run on every container start.
echo "Running Prisma database migrations..."
python -m prisma migrate deploy
echo "Migrations complete."

# Start the FastAPI application
echo "Starting UniVex API server..."
exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --proxy-headers \
    --forwarded-allow-ips "*"
