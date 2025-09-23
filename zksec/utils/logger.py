import logging
import sys
from datetime import datetime
from pathlib import Path

VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def setup_logging(
    log_level: str, output_dir: Path, file_logging: bool
) -> None:
    """Initialize root logger with console and optional file handlers.

    Args:
        log_level: One of DEBUG, INFO, WARNING, ERROR, CRITICAL (case-insensitive).
        output_dir: Directory where log files are written when file logging is enabled.
        file_logging: Whether to enable file logging in addition to console output.
    """
    # Normalize and validate log level
    log_level = str(log_level).upper()
    if log_level not in VALID_LOG_LEVELS:
        raise ValueError(
            f"Config error: Invalid log_level '{log_level}'. "
            f"Must be one of {', '.join(VALID_LOG_LEVELS)}."
        )


    # Create formatter (shared by both handlers)
    formatter = logging.Formatter(
        "%(asctime)s: [%(filename)s:%(lineno)d]: \t[%(levelname)s]: \t%(message)s",
        datefmt="%H:%M:%S",
    )

    # Get root logger and reset handlers
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers = []  # Clear existing handlers

    # Create console logging
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    if file_logging:
        # Create file logging
        file_path = output_dir / f"zksec.log"
        file_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            file_handler = logging.FileHandler(file_path, encoding="utf-8")
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except Exception as e:
            # Fall back to console-only if file cannot be created
            logging.getLogger(__name__).warning(
                f"Failed to set up file logging at '{file_path}': {e}"
            )
