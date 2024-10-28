from __future__ import annotations

import functools
import logging
import sys
from logging import CRITICAL, DEBUG, ERROR, INFO, WARNING
from time import perf_counter_ns as tick
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Sequence


_LOGGER = logging.getLogger("issp")


def _setup_logger() -> None:
    class ConditionalFormatter(logging.Formatter):
        def format(self, record: object) -> str:
            if getattr(record, "noformat", False):
                return record.getMessage()
            return logging.Formatter.format(self, record)

    fmt = "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ConditionalFormatter(fmt, datefmt=datefmt))
    _LOGGER.addHandler(handler)
    _LOGGER.setLevel(logging.INFO)


_setup_logger()


def set_level(log_level: int | str) -> None:
    _LOGGER.setLevel(log_level)


def with_level(log_level: int | str) -> Callable | None:
    return functools.partial(log, log_level) if _LOGGER.isEnabledFor(log_level) else None


def log(level: int | str, msg: str, *args: object, **kwargs: object) -> None:
    if title := kwargs.pop("title", None):
        _LOGGER.log(level, "\n=====[ Start %s ]=====", title)
        kwargs["extra"] = {"noformat": True}

    _LOGGER.log(level, msg, *args, **kwargs)

    if title:
        _LOGGER.log(level, "=====[ End %s ]=====", title, extra={"noformat": True})


def _format_time(interval: int) -> str:
    units = ("ns", "μs", "ms", "s")
    while interval >= 10**3 and len(units) > 1:
        interval /= 10**3
        units = units[1:]
    return f"{interval:.2f} {units[0]}"


def _format_progress(progress: str, current: str | None, desc: str | None) -> str:
    msg = f"{desc}: {progress}" if desc else progress
    if current:
        msg += f" (current: {current})"
    return msg


def percent[T](
    sequence: Sequence[T],
    desc: str | None = None,
    *,
    print_current: bool = True,
) -> Iterator[T]:
    first_timestamp = tick()
    last_timestamp = first_timestamp
    sequence_length = len(sequence)
    progress = 0
    for i, item in enumerate(sequence):
        cur_timestamp = tick()
        new_progress = int(i / sequence_length * 100)
        if cur_timestamp - last_timestamp > 10**9 and new_progress != progress:
            last_timestamp = cur_timestamp
            progress = new_progress
            info(_format_progress(f"{progress}%", item if print_current else None, desc))
        yield item
    info(_format_progress(f"100% ({_format_time(tick() - first_timestamp)})", None, desc))


def progress[T](
    iterable: Iterable[T],
    desc: str | None = None,
    *,
    print_current: bool = True,
) -> Iterator[T]:
    first_timestamp = tick()
    last_timestamp = first_timestamp
    progress = 0
    try:
        for i, item in enumerate(iterable):
            if (cur_timestamp := tick()) - last_timestamp > 10**9 and i != progress:
                last_timestamp = cur_timestamp
                info(_format_progress(f"{i}", item if print_current else None, desc))
            yield item
    finally:
        info(_format_progress(f"done ({i}, {_format_time(tick() - first_timestamp)})", None, desc))


def debug(msg: str, *args: object, **kwargs: object) -> None:
    log(DEBUG, msg, *args, **kwargs)


def info(msg: str, *args: object, **kwargs: object) -> None:
    log(INFO, msg, *args, **kwargs)


def warning(msg: str, *args: object, **kwargs: object) -> None:
    log(WARNING, msg, *args, **kwargs)


def error(msg: str, *args: object, **kwargs: object) -> None:
    log(ERROR, msg, *args, **kwargs)


def critical(msg: str, *args: object, **kwargs: object) -> None:
    log(CRITICAL, msg, *args, **kwargs)
