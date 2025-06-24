#!/usr/bin/env python3
"""Entry-point script for the univex-oob-listener container.

Starts the OOBListener which opens raw asyncio servers for HTTP, DNS, and SMTP
out-of-band callback channels.  Does not require uvicorn or FastAPI.

Environment variables (all optional):
    OOB_EXTERNAL_IP  — public/routable IP reported in callback URLs (default 127.0.0.1)
    OOB_HTTP_PORT    — HTTP callback port (default 8080)
    OOB_DNS_PORT     — DNS callback port, UDP (default 5353)
    OOB_SMTP_PORT    — SMTP callback port (default 2525)
    OOB_TOKEN_TTL    — seconds before callbacks are pruned (default 3600)
"""

import asyncio
import logging
import sys

# Ensure /app is importable when running directly inside the container
sys.path.insert(0, "/app")

from app.oob.oob_listener import OOBListener  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("univex.oob")


async def main() -> None:
    listener = OOBListener()
    await listener.start()
    logger.info("OOB listener running — waiting for callbacks …")
    stop_event = asyncio.Event()
    try:
        # Block until the process is killed / cancelled
        await stop_event.wait()
    except asyncio.CancelledError:
        logger.info("Shutdown requested — stopping OOB listener …")
        await listener.stop()


if __name__ == "__main__":
    asyncio.run(main())
