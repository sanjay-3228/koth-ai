"""Structured and timestamped logging configuration for koth-agent."""
import logging
import os
import sys
import time
from typing import Optional


class Formatter(logging.Formatter):
    """Custom formatter providing clean, millisecond-precision timestamps."""

    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        if datefmt:
            s = time.strftime(datefmt, ct)
        else:
            t = time.strftime("%Y-%m-%d %H:%M:%S", ct)
            s = f"{t}.{int(record.msecs):03d}"
        return s


_DEFAULT_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
_initialized = False


def setup_logging(level: Optional[str] = None) -> None:
    """Initialize root logger configuration."""
    global _initialized
    log_level = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    numeric_level = getattr(logging, log_level, logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Avoid duplicate handlers if called multiple times
    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(numeric_level)
        formatter = Formatter(_DEFAULT_FORMAT)
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)
    else:
        for handler in root_logger.handlers:
            handler.setLevel(numeric_level)
            handler.setFormatter(Formatter(_DEFAULT_FORMAT))

    _initialized = True


def get_logger(name: str) -> logging.Logger:
    """Return a logger instance configured with the koth-agent format."""
    if not _initialized:
        setup_logging()
    return logging.getLogger(name)
