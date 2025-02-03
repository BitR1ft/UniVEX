"""
Distributed JobQueue backed by Redis with in-memory fallback.

"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable, Dict, List, Optional

from app.core.redis_client import RedisClient

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobPriority(int, Enum):
    LOW = 0
    NORMAL = 5
    HIGH = 10
    CRITICAL = 20


@dataclass
class Job:
    name: str
    payload: Dict[str, Any]
    priority: int = JobPriority.NORMAL
    max_retries: int = 3
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: str = JobStatus.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    retries: int = 0
    result: Optional[Any] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Job":
        return cls(**data)


class JobQueue:
    """
    Distributed job queue using Redis sorted sets (priority) and hashes (job data).

    When Redis is unavailable the queue degrades gracefully to in-memory storage.

    Redis key layout:
        {prefix}:queue          — sorted set, score = priority (higher = sooner)
        {prefix}:job:{id}       — hash with job fields
        {prefix}:channel        — pub/sub channel for state-change events
    """

    QUEUE_KEY = "jobqueue:queue"
    JOB_PREFIX = "jobqueue:job:"
    CHANNEL = "jobqueue:events"

    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        prefix: str = "jobqueue",
    ) -> None:
        self._redis = redis_client
        self._prefix = prefix
        # Override keys with prefix
        self.QUEUE_KEY = f"{prefix}:queue"
        self.JOB_PREFIX = f"{prefix}:job:"
        self.CHANNEL = f"{prefix}:events"

        # In-memory fallback
        self._memory_queue: List[Job] = []
        self._memory_jobs: Dict[str, Job] = {}

        # Worker state
        self._running = False
        self._worker_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _save_job(self, job: Job) -> None:
        if self._redis is not None:
            try:
                await self._redis.hset(
                    f"{self.JOB_PREFIX}{job.id}",
                    mapping={k: json.dumps(v, default=str) for k, v in job.to_dict().items()},
                )
                return
            except Exception as exc:
                logger.warning("Redis hset failed: %s", exc)
        self._memory_jobs[job.id] = job

    async def _load_job(self, job_id: str) -> Optional[Job]:
        if self._redis is not None:
            try:
                raw = await self._redis.hgetall(f"{self.JOB_PREFIX}{job_id}")
                if not raw:
                    return None
                data = {k: json.loads(v) for k, v in raw.items()}
                return Job.from_dict(data)
            except Exception as exc:
                logger.warning("Redis hgetall failed: %s", exc)
        return self._memory_jobs.get(job_id)

    async def _broadcast(self, event: str, job: Job) -> None:
        if self._redis is not None:
            try:
                await self._redis.publish(self.CHANNEL, {"event": event, "job_id": job.id, "status": job.status})
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def enqueue(
        self,
        job_name: str,
        payload: Dict[str, Any],
        priority: int = JobPriority.NORMAL,
        max_retries: int = 3,
    ) -> Job:
        """Create and enqueue a new job. Returns the created Job."""
        job = Job(name=job_name, payload=payload, priority=priority, max_retries=max_retries)
        await self._save_job(job)

        if self._redis is not None:
            try:
                await self._redis.zadd(self.QUEUE_KEY, {job.id: priority})
                await self._broadcast("enqueued", job)
                return job
            except Exception as exc:
                logger.warning("Redis enqueue failed, falling back: %s", exc)

        # In-memory fallback — insert sorted by priority desc
        self._memory_queue.append(job)
        self._memory_queue.sort(key=lambda j: j.priority, reverse=True)
        self._memory_jobs[job.id] = job
        return job

    async def dequeue(self) -> Optional[Job]:
        """Pop the highest-priority pending job atomically. Returns None if queue is empty."""
        if self._redis is not None:
            try:
                # ZPOPMAX atomically removes and returns the highest-score member,
                # eliminating the race condition between zrange + zrem.
                items = await self._redis.zpopmax(self.QUEUE_KEY, 1)
                if not items:
                    return None
                job_id, _ = items[0]
                job = await self._load_job(job_id)
                if job:
                    job.status = JobStatus.RUNNING
                    job.started_at = time.time()
                    await self._save_job(job)
                    await self._broadcast("started", job)
                return job
            except Exception as exc:
                logger.warning("Redis dequeue failed, falling back: %s", exc)

        # In-memory fallback
        if not self._memory_queue:
            return None
        job = self._memory_queue.pop(0)
        job.status = JobStatus.RUNNING
        job.started_at = time.time()
        self._memory_jobs[job.id] = job
        return job

    async def complete(self, job_id: str, result: Any = None) -> Optional[Job]:
        """Mark job as COMPLETED with optional *result*."""
        job = await self._load_job(job_id)
        if job is None:
            return None
        job.status = JobStatus.COMPLETED
        job.completed_at = time.time()
        job.result = result
        await self._save_job(job)
        await self._broadcast("completed", job)
        return job

    async def fail(self, job_id: str, error: str) -> Optional[Job]:
        """Mark job as FAILED with *error* message."""
        job = await self._load_job(job_id)
        if job is None:
            return None
        job.status = JobStatus.FAILED
        job.completed_at = time.time()
        job.error = error
        await self._save_job(job)
        await self._broadcast("failed", job)
        return job

    async def cancel(self, job_id: str) -> Optional[Job]:
        """Cancel a job (only PENDING or RUNNING jobs can be cancelled)."""
        job = await self._load_job(job_id)
        if job is None:
            return None
        if job.status in (JobStatus.COMPLETED, JobStatus.CANCELLED):
            return job
        job.status = JobStatus.CANCELLED
        job.completed_at = time.time()
        await self._save_job(job)
        if self._redis is not None:
            try:
                await self._redis.zrem(self.QUEUE_KEY, job_id)
            except Exception:
                pass
        else:
            self._memory_queue = [j for j in self._memory_queue if j.id != job_id]
        await self._broadcast("cancelled", job)
        return job

    async def get_status(self, job_id: str) -> Optional[Job]:
        """Return the current state of a job."""
        return await self._load_job(job_id)

    async def get_all_jobs(self, status: Optional[str] = None) -> List[Job]:
        """Return all jobs, optionally filtered by *status*."""
        jobs: List[Job] = []

        if self._redis is not None:
            try:
                keys = await self._redis.keys(f"{self.JOB_PREFIX}*")
                for key in keys:
                    job_id = key.replace(self.JOB_PREFIX, "")
                    job = await self._load_job(job_id)
                    if job:
                        jobs.append(job)
            except Exception as exc:
                logger.warning("Redis get_all_jobs failed: %s", exc)
                jobs = list(self._memory_jobs.values())
        else:
            jobs = list(self._memory_jobs.values())

        if status is not None:
            jobs = [j for j in jobs if j.status == status]
        return jobs

    async def retry_failed(self) -> int:
        """Re-enqueue FAILED jobs that have retries remaining. Returns count re-queued."""
        failed = await self.get_all_jobs(status=JobStatus.FAILED)
        count = 0
        for job in failed:
            if job.retries < job.max_retries:
                job.retries += 1
                job.status = JobStatus.PENDING
                job.started_at = None
                job.completed_at = None
                job.error = None
                await self._save_job(job)
                if self._redis is not None:
                    try:
                        await self._redis.zadd(self.QUEUE_KEY, {job.id: job.priority})
                    except Exception:
                        self._memory_queue.append(job)
                else:
                    self._memory_queue.append(job)
                    self._memory_queue.sort(key=lambda j: j.priority, reverse=True)
                count += 1
        return count

    async def get_queue_stats(self) -> Dict[str, Any]:
        """Return queue statistics."""
        all_jobs = await self.get_all_jobs()
        stats: Dict[str, int] = {s.value: 0 for s in JobStatus}
        for job in all_jobs:
            stats[job.status] = stats.get(job.status, 0) + 1

        queue_depth = 0
        if self._redis is not None:
            try:
                queue_depth = await self._redis.zcard(self.QUEUE_KEY)
            except Exception:
                queue_depth = len(self._memory_queue)
        else:
            queue_depth = len(self._memory_queue)

        return {
            "queue_depth": queue_depth,
            "total_jobs": len(all_jobs),
            **stats,
        }

    # ------------------------------------------------------------------
    # Worker loop
    # ------------------------------------------------------------------

    async def start_worker(self, handler_fn: Callable[[Job], Awaitable[Any]]) -> None:
        """Start the background worker loop that processes jobs."""
        self._running = True
        self._worker_task = asyncio.create_task(self._worker_loop(handler_fn))
        logger.info("JobQueue worker started")

    async def stop_worker(self) -> None:
        """Signal the worker to stop and wait for it."""
        self._running = False
        if self._worker_task is not None:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None
        logger.info("JobQueue worker stopped")

    async def _worker_loop(self, handler_fn: Callable[[Job], Awaitable[Any]]) -> None:
        """Internal: poll queue and invoke *handler_fn* for each job."""
        while self._running:
            try:
                job = await self.dequeue()
                if job is None:
                    await asyncio.sleep(0.5)
                    continue
                try:
                    result = await handler_fn(job)
                    await self.complete(job.id, result)
                except Exception as exc:
                    logger.error("Job %s failed: %s", job.id, exc, exc_info=True)
                    await self.fail(job.id, str(exc))
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Worker loop error: %s", exc)
                await asyncio.sleep(1)
