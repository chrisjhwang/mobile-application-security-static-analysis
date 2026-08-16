"""Structured-ish logging setup shared by every subcommand.

The old scripts used bare ``print`` for both progress and errors, which meant
batch runs produced output that could not be filtered, timestamped, or
redirected to a file separately from report content. Everything now goes
through the ``mobsec`` logger hierarchy.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(level: str = "INFO", log_file: Path | None = None) -> logging.Logger:
    """Configure and return the root ``mobsec`` logger.

    Console output goes to stderr so that report text written to stdout stays
    pipeable. If ``log_file`` is given, a full-detail copy is also written there.
    """
    logger = logging.getLogger("mobsec")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    console.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    logger.addHandler(console)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Child logger, e.g. ``get_logger("pipeline")`` -> ``mobsec.pipeline``."""
    return logging.getLogger(f"mobsec.{name}")
