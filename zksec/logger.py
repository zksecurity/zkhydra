import logging

VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def setup_logging(log_level: str) -> None:
    # Validate log level

    if log_level not in VALID_LOG_LEVELS:
        raise ValueError(
            f"Config error: Invalid log_level '{log_level}'. "
            f"Must be one of {', '.join(VALID_LOG_LEVELS)}."
        )

    # Setup logging
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s: [%(filename)s:%(lineno)d]: \t[%(levelname)s]: \t%(message)s",
        datefmt="%H:%M:%S",
    )
