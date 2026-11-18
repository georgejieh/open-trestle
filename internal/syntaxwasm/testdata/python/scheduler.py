"""Task scheduler and worker pool.

Jobs are queued with a priority, picked up by a pool of workers and
retried with a simple backoff when they fail.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import os.path as ospath
import time
from abc import ABCMeta
from collections import defaultdict, deque as Deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Generic, Optional, TypeVar, Union

from . import clock
from ..pkg.mod import thing
from .constants import *

__all__ = [
    "Job",
    "JobStatus",
    "Queue",
    "Scheduler",
    "WorkerPool",
    "retry",
    "timed",
]

DEFAULT_WORKERS = 4
MAX_RETRIES = 3
BACKOFF_BASE = 0.25
LOG_NAME = "scheduler"

low, high = 0, 10
first_name, *other_names = ("alpha", "beta", "gamma")
_registry: dict[str, "Job"] = {}
_started_at = time.monotonic()

type JobId = str
type Handler[T] = Callable[[T], Awaitable[Any]]

T = TypeVar("T")
R = TypeVar("R")


def get_logger() -> logging.Logger:
    return logging.getLogger(LOG_NAME)


def timed(func):
    """Log how long the wrapped callable takes to run."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        begin = time.perf_counter()
        try:
            return func(*args, **kwargs)
        finally:
            elapsed = time.perf_counter() - begin
            get_logger().info(f"{func.__name__} took {elapsed:.3f}s")

    return wrapper


def retry(times: int = MAX_RETRIES, delay: float = BACKOFF_BASE):
    """Retry an async callable a limited number of times."""

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            attempt = 0
            while True:
                try:
                    return await func(*args, **kwargs)
                except (OSError, TimeoutError) as exc:
                    attempt += 1
                    if attempt >= times:
                        raise
                    get_logger().warning(f"retry {attempt}/{times}: {exc!r}")
                    await asyncio.sleep(delay * 2**attempt)

        return wrapper

    return decorator


class JobStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class RegistryMeta(ABCMeta):
    """Metaclass that records every concrete subclass by name."""

    classes: dict[str, type] = {}

    def __new__(mcls, name, bases, namespace, **kwargs):
        cls = super().__new__(mcls, name, bases, namespace, **kwargs)
        mcls.classes[name] = cls
        return cls


class Component(metaclass=RegistryMeta):
    """Base class for pieces that can be started and stopped."""

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError


@dataclass(order=True)
class Job:
    priority: int
    name: str = field(compare=False)
    payload: dict[str, Any] = field(default_factory=dict, compare=False)
    job_id: JobId = field(default="", compare=False)
    status: JobStatus = field(default=JobStatus.PENDING, compare=False)
    attempts: int = field(default=0, compare=False)
    result: Optional[Any] = field(default=None, compare=False)

    class Meta:
        table = "jobs"
        ordering = ("priority", "name")

    def __post_init__(self) -> None:
        if not self.job_id:
            self.job_id = f"{self.name}-{id(self):x}"
        _registry[self.job_id] = self

    def __repr__(self) -> str:
        return f"Job({self.job_id!r}, priority={self.priority}, status={self.status.value})"

    @property
    def finished(self) -> bool:
        return self.status in (JobStatus.DONE, JobStatus.FAILED)


class Queue[T]:
    """A bounded priority queue backed by a sorted list."""

    def __init__(self, capacity: int = 100) -> None:
        self._items: list[T] = []
        self._capacity = capacity
        self._waiters: Deque[asyncio.Future] = Deque()

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self):
        return iter(sorted(self._items))

    @property
    def capacity(self) -> int:
        return self._capacity

    @capacity.setter
    def capacity(self, value: int) -> None:
        if value <= 0:
            raise ValueError("capacity must be positive")
        self._capacity = value

    def put(self, item: T) -> None:
        if len(self._items) >= self._capacity:
            raise OverflowError("queue is full")
        self._items.append(item)
        self._items.sort()
        self._wake_one()

    def _wake_one(self) -> None:
        while self._waiters:
            waiter = self._waiters.popleft()
            if not waiter.done():
                waiter.set_result(None)
                break

    async def get(self) -> T:
        while not self._items:
            loop = asyncio.get_running_loop()
            waiter = loop.create_future()
            self._waiters.append(waiter)
            await waiter
        return self._items.pop(0)


class Stats(Generic[T]):
    """Collects values of one type and reports simple summaries."""

    def __init__(self) -> None:
        self.samples: list[T] = []

    def add(self, value: T) -> None:
        self.samples.append(value)

    @staticmethod
    def mean(values: list[float]) -> float:
        return sum(values) / len(values) if values else 0.0


class Worker(Component):
    def __init__(self, name: str, queue: Queue[Job], handler: Handler[Job]) -> None:
        self.name = name
        self.queue = queue
        self.handler = handler
        self._task: Optional[asyncio.Task] = None
        self.processed = 0

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name=self.name)

    def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()

    async def _loop(self) -> None:
        while True:
            job = await self.queue.get()
            job.status = JobStatus.RUNNING
            try:
                job.result = await self._run(job)
            except Exception as exc:
                job.status = JobStatus.FAILED
                job.result = str(exc)
                get_logger().error(f"{job.job_id} failed: {exc}")
            else:
                job.status = JobStatus.DONE
            finally:
                job.attempts += 1
                self.processed += 1

    @retry(times=2, delay=0.1)
    async def _run(self, job: Job) -> Any:
        return await self.handler(job)


class WorkerPool(Component):
    def __init__(self, size: int = DEFAULT_WORKERS, handler: Optional[Handler[Job]] = None) -> None:
        self.size = size
        self.queue: Queue[Job] = Queue()
        self.workers: list[Worker] = []
        self._handler = handler or self._default_handler

    async def _default_handler(self, job: Job) -> str:
        await asyncio.sleep(0)
        return f"ran {job.name}"

    def start(self) -> None:
        self.workers = [Worker(f"worker-{i}", self.queue, self._handler) for i in range(self.size)]
        for worker in self.workers:
            worker.start()

    def stop(self) -> None:
        for worker in self.workers:
            worker.stop()

    def submit(self, job: Job) -> JobId:
        self.queue.put(job)
        return job.job_id

    def __enter__(self) -> "WorkerPool":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.stop()
        return False


class Scheduler:
    """Accepts jobs and hands them to a pool, tracking their progress."""

    _instances = 0

    def __init__(self, pool: Optional[WorkerPool] = None) -> None:
        self.pool = pool or WorkerPool()
        self._by_status: defaultdict[JobStatus, list[Job]] = defaultdict(list)
        self._hooks: list[Callable[[Job], None]] = []
        Scheduler._instances += 1

    @classmethod
    def with_workers(cls, count: int) -> "Scheduler":
        return cls(WorkerPool(size=count))

    @staticmethod
    def make_job(name: str, priority: int = low, **payload: Any) -> Job:
        return Job(priority, name, payload)

    def on_finish(self, hook: Callable[[Job], None]) -> None:
        self._hooks.append(hook)

    @timed
    def schedule(self, job: Job) -> JobId:
        job_id = self.pool.submit(job)
        self._by_status[job.status].append(job)
        get_logger().info(f"scheduled {job_id}")
        return job_id

    def schedule_many(self, jobs: list[Job]) -> list[JobId]:
        return [self.schedule(job) for job in sorted(jobs, key=lambda j: -j.priority)]

    def pending(self) -> list[Job]:
        return [j for j in _registry.values() if j.status is JobStatus.PENDING]

    def summary(self) -> dict[str, int]:
        return {status.value: len(jobs) for status, jobs in self._by_status.items()}

    def describe(self, job: Job | None) -> str:
        match job:
            case None:
                return "no job"
            case Job(status=JobStatus.DONE, result=str(text)):
                return f"done: {text}"
            case Job(status=JobStatus.FAILED):
                return "failed"
            case Job(priority=p) if p >= high:
                return "urgent"
            case _:
                return "waiting"

    async def run_until_empty(self, poll: float = 0.05) -> int:
        finished = 0
        with self.pool:
            while len(self.pool.queue) > 0:
                await asyncio.sleep(poll)
            for job in list(_registry.values()):
                if job.finished:
                    finished += 1
                    for hook in self._hooks:
                        hook(job)
        return finished

    async def stream_results(self, source):
        async for item in source:
            yield item

    async def drain(self, sources) -> list[Any]:
        collected: list[Any] = []
        async with asyncio.timeout(5):
            for source in sources:
                async for value in self.stream_results(source):
                    collected.append(await asyncio.sleep(0, value))
        return collected


def make_counter(start: int = 0):
    count = start

    def increment(step: int = 1) -> int:
        nonlocal count
        count += step
        return count

    return increment


def reset_clock() -> None:
    global _started_at
    _started_at = time.monotonic()


def load_config(path: str) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        handle = open(ospath.expanduser(path))
    except FileNotFoundError:
        get_logger().info("no config file found")
        return result
    else:
        with handle:
            for line in handle:
                key, _, value = line.partition("=")
                result[key.strip()] = value.strip()
    finally:
        get_logger().debug(f"config read from {path!r}")
    return result


async def main() -> None:
    scheduler = Scheduler.with_workers(DEFAULT_WORKERS)
    jobs = [Scheduler.make_job(f"task-{n}", priority=n % 5, index=n) for n in range(8)]
    scheduler.schedule_many(jobs)
    scheduler.on_finish(lambda job: get_logger().info(f"finished {job!r}"))
    done = await scheduler.run_until_empty()
    get_logger().info(f"done={done} pid={os.getpid() if (os := __import__('os')) else 0}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
