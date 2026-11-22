class BlackBoxError(Exception):
    """Base exception for BlackBox."""


class TargetValidationError(BlackBoxError):
    """Raised when a target is invalid."""
