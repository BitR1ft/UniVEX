"""

Schedules pentest campaigns with configurable concurrency limits,
priority queuing, and time-window restrictions.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from .campaign_engine import CampaignEngine, CampaignStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Priority
# ---------------------------------------------------------------------------

class Priority(int, Enum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


# ---------------------------------------------------------------------------
# Scheduled Job
# ---------------------------------------------------------------------------

@dataclass
class ScheduledJob:
    """A campaign that has been queued for execution."""
    campaign_id: str
    priority: Priority = Priority.NORMAL
    run_at: Optional[datetime] = None          # None means run immediately
    created_at: datetime = field(default_factory=datetime.utcnow)
    scan_fn: Optional[Callable] = None
    # Execution tracking
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    attempts: int = 0

    @property
    def is_ready(self) -> bool:
        """True if this job is ready to execute (past its run_at time)."""
        if self.run_at is None:
            return True
        return datetime.utcnow() >= self.run_at

    def sort_key(self) -> tuple:
        """Higher priority & earlier run_at sorts first."""
        ts = self.run_at or datetime.min
        return (-self.priority.value, ts)


# ---------------------------------------------------------------------------
# CampaignScheduler
# ---------------------------------------------------------------------------

class CampaignScheduler:
    """
    Priority-based campaign scheduler with concurrency control.

    Usage::

        engine = CampaignEngine()
        scheduler = CampaignScheduler(engine, max_concurrent=2)

        scheduler.schedule(campaign_id, priority=Priority.HIGH)
        scheduler.schedule(campaign_id2, run_at=datetime.utcnow() + timedelta(hours=1))

        await scheduler.run_all()
    """

    def __init__(
        self,
        engine: CampaignEngine,
        max_concurrent: int = 3,
        poll_interval: float = 1.0,
    ) -> None:
        self._engine = engine
        self.max_concurrent = max_concurrent
        self._poll_interval = poll_interval
        self._queue: List[ScheduledJob] = []
        self._running: Dict[str, ScheduledJob] = {}   # campaign_id → job
        self._history: List[ScheduledJob] = []

    # ------------------------------------------------------------------
    # Queue management
    # ------------------------------------------------------------------

    def schedule(
        self,
        campaign_id: str,
        priority: Priority = Priority.NORMAL,
        run_at: Optional[datetime] = None,
        scan_fn: Optional[Callable] = None,
    ) -> ScheduledJob:
        """Add a campaign to the scheduler queue."""
        job = ScheduledJob(
            campaign_id=campaign_id,
            priority=priority,
            run_at=run_at,
            scan_fn=scan_fn,
        )
        self._queue.append(job)
        self._sort_queue()
        campaign = self._engine.get_campaign(campaign_id)
        if campaign:
            campaign.status = CampaignStatus.SCHEDULED
            if run_at:
                campaign.scheduled_at = run_at
        logger.info(
            "Campaign scheduled: id=%s priority=%s run_at=%s",
            campaign_id, priority.name, run_at,
        )
        return job

    def cancel_scheduled(self, campaign_id: str) -> bool:
        """Remove a campaign from the queue before it starts."""
        before = len(self._queue)
        self._queue = [j for j in self._queue if j.campaign_id != campaign_id]
        return len(self._queue) < before

    def get_queue(self) -> List[ScheduledJob]:
        """Return jobs sorted by priority (highest first)."""
        self._sort_queue()
        return list(self._queue)

    def get_history(self) -> List[ScheduledJob]:
        return list(self._history)

    def queue_depth(self) -> int:
        return len(self._queue)

    def running_count(self) -> int:
        return len(self._running)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def run_all(self) -> List[ScheduledJob]:
        """
        Process all queued jobs, respecting concurrency limits and run_at times.

        Returns the list of completed jobs.
        """
        completed: List[ScheduledJob] = []

        while self._queue or self._running:
            # Start ready jobs up to concurrency limit
            slots_available = self.max_concurrent - len(self._running)
            ready = [j for j in self._queue if j.is_ready][:slots_available]

            tasks = []
            for job in ready:
                self._queue.remove(job)
                self._running[job.campaign_id] = job
                tasks.append(self._execute_job(job))

            if tasks:
                done = await asyncio.gather(*tasks, return_exceptions=True)
                for job, result in zip(ready, done):
                    self._running.pop(job.campaign_id, None)
                    self._history.append(job)
                    completed.append(job)
                    if isinstance(result, Exception):
                        job.error = str(result)
                        logger.error("Scheduler job failed: %s — %s", job.campaign_id, result)
            elif not self._running and self._queue:
                # All pending jobs have future run_at — wait
                await asyncio.sleep(self._poll_interval)
            elif not tasks and not self._running:
                break

        return completed

    async def run_next(self) -> Optional[ScheduledJob]:
        """Execute the next ready job from the queue."""
        ready = [j for j in self._queue if j.is_ready]
        if not ready:
            return None
        job = ready[0]
        self._queue.remove(job)
        await self._execute_job(job)
        self._history.append(job)
        return job

    async def _execute_job(self, job: ScheduledJob) -> None:
        job.started_at = datetime.utcnow()
        job.attempts += 1
        try:
            await self._engine.run_campaign(
                campaign_id=job.campaign_id,
                scan_fn=job.scan_fn,
            )
            job.completed_at = datetime.utcnow()
        except Exception as exc:
            job.error = str(exc)
            job.completed_at = datetime.utcnow()
            raise

    # ------------------------------------------------------------------
    # Scheduling utilities
    # ------------------------------------------------------------------

    def schedule_in(
        self,
        campaign_id: str,
        delay: timedelta,
        priority: Priority = Priority.NORMAL,
        scan_fn: Optional[Callable] = None,
    ) -> ScheduledJob:
        """Schedule a campaign to run after a delay."""
        run_at = datetime.utcnow() + delay
        return self.schedule(campaign_id, priority=priority, run_at=run_at, scan_fn=scan_fn)

    def schedule_daily(
        self,
        campaign_id: str,
        hour: int = 2,
        minute: int = 0,
        priority: Priority = Priority.NORMAL,
    ) -> ScheduledJob:
        """Schedule a campaign to run at a specific time today (or tomorrow if past)."""
        now = datetime.utcnow()
        run_at = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if run_at <= now:
            run_at += timedelta(days=1)
        return self.schedule(campaign_id, priority=priority, run_at=run_at)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _sort_queue(self) -> None:
        self._queue.sort(key=lambda j: j.sort_key())

    def stats(self) -> Dict[str, Any]:
        return {
            "queued": len(self._queue),
            "running": len(self._running),
            "completed": len(self._history),
            "max_concurrent": self.max_concurrent,
        }
