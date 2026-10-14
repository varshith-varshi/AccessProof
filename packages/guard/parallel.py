from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def bounded_map(items: Iterable[T], fn: Callable[[T], R], max_workers: int = 16) -> list[R | Exception]:
    """Process independent permission events without unbounded fan-out."""
    values = list(items)
    results: list[R | Exception | None] = [None] * len(values)
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(values) or 1))) as pool:
        futures = {pool.submit(fn, item): index for index, item in enumerate(values)}
        for future in as_completed(futures):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception as exc:  # isolate one employee/provider failure
                results[index] = exc
    return results  # type: ignore[return-value]
