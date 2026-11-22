from abc import ABC, abstractmethod


class ReconModule(ABC):
    """Base interface for reconnaissance modules."""

    @abstractmethod
    def run(self, target):
        """Run the module against a target."""
        raise NotImplementedError
