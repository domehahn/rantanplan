"""
Abstract Base Class for all Rantanplan Scanner Adapters.
"""

from abc import ABC, abstractmethod

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

    @abstractmethod
    def doctor(self) -> DoctorResult:
        """Checks scanner installation and version compatibility."""

    @abstractmethod
    def capabilities(self) -> list[str]:
        """Returns supported canonical capabilities (e.g. prompt.injection, secret.exfiltration)."""

    @abstractmethod
    def supports(self, case: TestCase) -> bool:
        """Determines if the scanner supports a specific test case based on applicability matrix."""

    @abstractmethod
    def build_command(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> list[str]:
        """Constructs the command-line arguments slice."""

    @abstractmethod
    def run(self, case: TestCase, profile: RunProfile, fixture_dir: str) -> RawExecution:
        """Executes the scanner against the target fixture."""

    @abstractmethod
    def parse(self, case: TestCase, execution: RawExecution) -> NormalizedResult:
        """Parses raw execution output into a NormalizedResult."""

