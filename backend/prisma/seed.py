"""
Database Seed Script
Populates the development database with:
  - An admin user
  - A sample regular user
  - Two sample projects
  - Sample tasks with results and logs

Usage:
    cd backend
    python -m prisma.seed          # if configured in pyproject.toml
    # or directly:
    python prisma/seed.py
"""
import asyncio
import logging
import os
import sys

# Ensure backend/ is on the Python path when run as a script
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from prisma import Prisma

from app.core.security import get_password_hash

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


async def seed() -> None:
    db = Prisma()
    await db.connect()

    try:
        logger.info("Seeding database …")

        # ----------------------------------------------------------------
        # Admin user
        # ----------------------------------------------------------------
        admin = await db.user.upsert(
            where={"email": "admin@univex.local"},
            data={
                "create": {
                    "email": "admin@univex.local",
                    "username": "admin",
                    "hashed_password": get_password_hash("Admin@12345"),
                    "full_name": "System Administrator",
                    "is_admin": True,
                },
                "update": {},
            },
        )
        logger.info("Admin user: %s (%s)", admin.id, admin.username)

        # ----------------------------------------------------------------
        # Sample regular user
        # ----------------------------------------------------------------
        demo_user = await db.user.upsert(
            where={"email": "demo@univex.local"},
            data={
                "create": {
                    "email": "demo@univex.local",
                    "username": "demo",
                    "hashed_password": get_password_hash("Demo@12345"),
                    "full_name": "Demo User",
                    "is_admin": False,
                },
                "update": {},
            },
        )
        logger.info("Demo user: %s (%s)", demo_user.id, demo_user.username)

        # ----------------------------------------------------------------
        # Sample projects
        # ----------------------------------------------------------------
        project_alpha = await db.project.create(
            data={
                "user_id": demo_user.id,
                "name": "Alpha Assessment",
                "target": "example.com",
                "description": "Demo full-stack assessment against example.com",
                "project_type": "full_assessment",
                "status": "draft",
            }
        )
        logger.info("Project: %s ('%s')", project_alpha.id, project_alpha.name)

        project_beta = await db.project.create(
            data={
                "user_id": demo_user.id,
                "name": "Beta Port Survey",
                "target": "192.0.2.0/24",
                "description": "Port survey of the test subnet",
                "project_type": "port_scan_only",
                "status": "draft",
                "enable_subdomain_enum": False,
                "enable_web_crawl": False,
                "enable_tech_detection": False,
                "enable_vuln_scan": False,
                "enable_nuclei": False,
            }
        )
        logger.info("Project: %s ('%s')", project_beta.id, project_beta.name)

        # ----------------------------------------------------------------
        # Sample tasks for project_alpha
        # ----------------------------------------------------------------
        recon_task = await db.task.create(
            data={
                "project_id": project_alpha.id,
                "type": "recon",
                "status": "completed",
            }
        )
        await db.recontask.create(
            data={
                "task_id": recon_task.id,
                "domain": "example.com",
                "subdomains_found": 3,
                "dns_records_found": 5,
                "subdomains": ["www.example.com", "mail.example.com", "api.example.com"],
            }
        )
        await db.tasklog.create(
            data={
                "task_id": recon_task.id,
                "level": "info",
                "message": "Domain discovery completed: 3 subdomains found",
            }
        )
        await db.taskmetrics.create(
            data={
                "task_id": recon_task.id,
                "duration_seconds": 12.4,
                "items_processed": 3,
                "error_count": 0,
            }
        )

        port_task = await db.task.create(
            data={
                "project_id": project_alpha.id,
                "type": "port_scan",
                "status": "pending",
            }
        )
        await db.portscantask.create(
            data={
                "task_id": port_task.id,
                "target": "example.com",
                "scan_profile": "default",
            }
        )
        logger.info(
            "Created %d tasks for project %s", 2, project_alpha.id
        )

        logger.info("Seed complete ✓")

    finally:
        await db.disconnect()


if __name__ == "__main__":
    asyncio.run(seed())
