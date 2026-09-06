"""
Abstract Base Class for all Rantanplan Scanner Adapters.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from rantanplan.models import (
    DoctorResult,
    NormalizedResult,
    RawExecution,
    RunProfile,
    ScannerIdentity,
    TestCase,
)


class ScannerAdapter(ABC):
    """Stable interface for security scanner adapters."""

    @abstractmethod
    def identity(self) -> ScannerIdentity:
        """Returns the scanner identity (name, version, binary path)."""
        pass

    @abstractmethod
    def doctor(self) -> DoctorResult:
        """Checks scanner installation and version compatibility."""
        pass

    @abstractmethod
    def capabilities(self) -> List[str]:
        """Returns supported canonical capabilities (e.g. prompt.injection, secret.exfiltration)."""
        pass

    @abstractmethod
    def supports(self, case: TestCase) -> bool:
        """Determines if the scanner supports a specific test case based on applicability matrix."""
        pass

    @abstractmethod
    def build_command(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> List[str]:
        """Constructs the command-line arguments slice."""
        pass

    @abstractmethod
    def run(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        """Executes the scanner against the target fixture."""
        pass

    @abstractmethod
    def parse(self, case: TestCase, execution: RawExecution) -> NormalizedResult:
        """Parses raw execution output into a NormalizedResult."""
        pass
