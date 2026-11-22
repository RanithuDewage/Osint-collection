import logging
from pathlib import Path

from config.settings import APP_NAME

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / f"{APP_NAME.lower()}.log"


class ConsoleFilter(logging.Filter):
    def filter(self, record):
        return record.levelno >= logging.WARNING


def get_logger(name):
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    LOG_DIR.mkdir(exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Console: show only WARNING and ERROR to the user.
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.addFilter(ConsoleFilter())
    console_handler.setFormatter(formatter)

    # File: keep all logs for debugging.
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    logger.setLevel(logging.INFO)
    logger.propagate = False

    return logger
