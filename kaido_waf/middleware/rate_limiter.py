"""
Kaido WAF — Rate Limiter
Limitação de taxa por IP com backend em memória ou Redis.
"""

import asyncio
import time
import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("kaido-waf.rate_limiter")


class RateLimitExceeded(Exception):
    """Exceção levantada quando o rate limit é excedido."""
    def __init__(self, client_ip: str, retry_after: int):
        self.client_ip = client_ip
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded for {client_ip}")


class MemoryBackend:
    """Backend de rate limiting em memória (Sliding Window)."""

    def __init__(self):
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def check(self, key: str, max_requests: int,
                    window_seconds: int = 60) -> tuple[bool, int]:
        """Verifica se o rate limit foi excedido.
        Retorna (permitido, retry_after_seconds).
        """
        now = time.time()
        window_start = now - window_seconds

        async with self._lock:
            # Limpa entradas expiradas
            self._buckets[key] = [
                t for t in self._buckets[key] if t > window_start
            ]

            if len(self._buckets[key]) >= max_requests:
                oldest = self._buckets[key][0]
                retry_after = int(window_seconds - (now - oldest))
                return False, max(retry_after, 1)

            self._buckets[key].append(now)
            return True, 0

    async def close(self):
        pass


class RedisBackend:
    """Backend de rate limiting em Redis."""

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._redis = None

    async def check(self, key: str, max_requests: int,
                    window_seconds: int = 60) -> tuple[bool, int]:
        try:
            import redis.asyncio as aioredis
            if self._redis is None:
                self._redis = aioredis.from_url(self.redis_url)

            now = time.time()
            window_start = now - window_seconds

            pipeline = self._redis.pipeline()
            pipeline.zremrangebyscore(key, 0, window_start)
            pipeline.zcard(key)
            pipeline.zadd(key, {str(now): now})
            pipeline.expire(key, window_seconds * 2)

            _, count, _, _ = await pipeline.execute()

            if count >= max_requests:
                oldest = await self._redis.zrange(key, 0, 0, withscores=True)
                if oldest:
                    retry_after = int(window_seconds - (now - oldest[0][1]))
                    return False, max(retry_after, 1)
                return False, 1

            return True, 0
        except ImportError:
            logger.warning("redis-py not installed, falling back to memory backend")
            return await MemoryBackend().check(key, max_requests, window_seconds)

    async def close(self):
        if self._redis:
            await self._redis.close()


class RateLimiter:
    """Rate limiter com suporte a sliding window."""

    def __init__(self, backend: str = "memory", redis_url: str = "",
                 requests_per_minute: int = 60, burst_size: int = 100,
                 block_duration: int = 300):
        self.rpm = requests_per_minute
        self.burst = burst_size
        self.block_duration = block_duration
        self._blocked: dict[str, float] = {}
        self._block_lock = asyncio.Lock()

        if backend == "redis" and redis_url:
            self._backend = RedisBackend(redis_url)
        else:
            self._backend = MemoryBackend()

    async def check(self, client_ip: str) -> tuple[bool, int, int]:
        """Verifica se o IP pode passar.
        Retorna: (permitido, status_code, retry_after)
        """
        # Verifica se está bloqueado
        async with self._block_lock:
            if client_ip in self._blocked:
                until = self._blocked[client_ip]
                if time.time() < until:
                    retry_after = int(until - time.time())
                    return False, 429, retry_after
                else:
                    del self._blocked[client_ip]

        # Rate limiting normal (RPM)
        allowed, retry_after = await self._backend.check(
            f"rl:{client_ip}", self.rpm, 60
        )
        if not allowed:
            return False, 429, retry_after

        # Burst check (por segundo)
        allowed, retry_after = await self._backend.check(
            f"burst:{client_ip}", self.burst, 1
        )
        if not allowed:
            return False, 429, 1

        return True, 200, 0

    async def block_ip(self, client_ip: str, duration: int = None):
        """Bloqueia um IP manualmente."""
        async with self._block_lock:
            self._blocked[client_ip] = time.time() + (duration or self.block_duration)

    async def unblock_ip(self, client_ip: str):
        """Desbloqueia um IP."""
        async with self._block_lock:
            self._blocked.pop(client_ip, None)

    async def close(self):
        await self._backend.close()
