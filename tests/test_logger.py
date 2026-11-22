import logging

from utils.logger import get_logger


def test_get_logger():
    logger = get_logger("test")

    assert isinstance(logger, logging.Logger)
    assert logger.name == "test"
    assert logger.level == logging.INFO
    assert len(logger.handlers) == 2

    handler_types = {
        type(handler)
        for handler in logger.handlers
    }

    assert logging.StreamHandler in handler_types
    assert logging.FileHandler in handler_types
