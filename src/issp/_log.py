from __future__ import annotations

import functools
import logging
import sys
from logging import CRITICAL, DEBUG, ERROR, INFO, WARNING
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


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
