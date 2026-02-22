"""Exponential backoff retry decorator for transient failures."""

import asyncio
import functools
import random
from typing import Callable, Tuple, Type

from app.utils.logger import get_logger

logger = get_logger(__name__)


def retry_with_backoff(
    max_retries: int = 3,
    backoff_factor: float = 2.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
) -> Callable:
    """Decorator that retries an async function with exponential backoff + jitter.

    Args:
        max_retries: Maximum number of retry attempts after the first failure.
        backoff_factor: Multiplier applied to the delay on each successive retry.
        exceptions: Tuple of exception types that trigger a retry.

    The wait between attempt N and N+1 is:
        backoff_factor^N + uniform(0, 1) seconds (jitter prevents thundering herd).
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception: Exception | None = None
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as exc:
                    last_exception = exc
                    if attempt == max_retries:
                        logger.warning(
                            "retry_exhausted",
                            func=func.__name__,
                            max_retries=max_retries,
                            error=str(exc),
                        )
                        raise
                    delay = (backoff_factor ** attempt) + random.uniform(0, 1)
                    logger.info(
                        "retry_attempt",
                        func=func.__name__,
                        attempt=attempt + 1,
                        max_retries=max_retries,
                        delay_seconds=round(delay, 2),
                        error=str(exc),
                    )
                    await asyncio.sleep(delay)
            # Should never reach here, but satisfies type checkers
            raise last_exception  # type: ignore[misc]

        return wrapper

    return decorator
