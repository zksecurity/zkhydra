import logging
import sys
from pathlib import Path
from datetime import datetime

VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def setup_logging(log_level: str, output_dir: Path, file_logging: bool) -> None:
    # Validate log level
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
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    if file_logging:
        # Create file logging
        current_day = datetime.now().strftime("%Y-%m-%d")
        file_path = output_dir / f"zksec_{current_day}.log"
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(file_path)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
