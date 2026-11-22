import pytest

from utils.errors import (
    BlackBoxError,
    TargetValidationError,
)


def test_target_validation_error_is_blackbox_error():
    error = TargetValidationError("Invalid target")

    assert isinstance(error, BlackBoxError)


def test_target_validation_error_can_be_raised():
    with pytest.raises(TargetValidationError):
        raise TargetValidationError("Invalid target")
