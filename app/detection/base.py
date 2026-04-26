from abc import ABC, abstractmethod
from detection.models import DetectionSignal, EmailData

class BaseDetector(ABC):
    """
    Every detector implements this interface.
    To add a new detector: subclass, implement 'analyze', register in scanner.
    """

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def analyze(self, email: EmailData, pre_signals: list | None = None) -> DetectionSignal: ...