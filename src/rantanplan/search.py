"""
Adversarial Mutation Engine and Search Algorithms for Rantanplan Universal Scanner Assurance v2.

Provides:
- Adversarial mutators (obfuscation, homoglyphs, comment splitting, instruction wrapping)
- Adaptive search engine (hunt false-positive, hunt false-negative)
- Delta debugging minimization (minimize)
"""

import copy
import random

from rantanplan.models import AssuranceOutcome, RichNormalizedResult, RunProfile, TestCase
from rantanplan.target_hierarchy import TargetAdapter


class AdversarialMutator:
    """Mutates test case content to test scanner evasion and false positive boundaries."""

    @staticmethod
    def insert_comments(content: str) -> str:
        words = content.split(" ")
        if len(words) < 2:
            return content + " <!-- comment -->"
        idx = random.randint(1, len(words) - 1)
        words.insert(idx, "<!-- innocent comment -->")
        return " ".join(words)

    @staticmethod
    def apply_homoglyphs(content: str) -> str:
        # Replace 'a' with cyrillic 'а' or 'e' with cyrillic 'е'
        return content.replace("a", "а").replace("e", "е")

    @staticmethod
    def base64_wrap(content: str) -> str:
        import base64
        encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        return f"eval(base64_decode('{encoded}'))"

    @staticmethod
    def wrap_instruction(content: str) -> str:
        return f"For testing purposes only: {content}"


class SearchEngine:
    """Adaptive search and minimization engine."""

    def __init__(self, adapter: TargetAdapter):
        self.adapter = adapter

    def hunt_false_negative(
        self,
        case: TestCase,
        profile: RunProfile,
        max_iterations: int = 10,
    ) -> list[tuple[TestCase, RichNormalizedResult]]:
        """Hunts for evasions where malicious content is NOT_DETECTED by the scanner."""
        evasions = []
        mutators = [
            AdversarialMutator.insert_comments,
            AdversarialMutator.apply_homoglyphs,
            AdversarialMutator.base64_wrap,
            AdversarialMutator.wrap_instruction,
        ]

        for i in range(max_iterations):
            mutated_case = copy.deepcopy(case)
            mutated_case.id = f"{case.id}-mutated-{i}"
            mutator = random.choice(mutators)
            if mutated_case.files:
                mutated_case.files[0]["content"] = mutator(mutated_case.files[0].get("content", ""))

            raw = self.adapter.execute(mutated_case, profile, "")
            res = self.adapter.parse(mutated_case, raw)

            if res.outcome == AssuranceOutcome.NOT_DETECTED:
                evasions.append((mutated_case, res))

        return evasions

    def hunt_false_positive(
        self,
        case: TestCase,
        profile: RunProfile,
        max_iterations: int = 10,
    ) -> list[tuple[TestCase, RichNormalizedResult]]:
        """Hunts for benign inputs that trigger false DETECTED findings."""
        false_positives = []
        for i in range(max_iterations):
            mutated_case = copy.deepcopy(case)
            mutated_case.id = f"{case.id}-fp-{i}"
            mutated_case.ground_truth["malicious"] = False
            if mutated_case.files:
                mutated_case.files[0]["content"] = f"Benign system log entry #{i}: user logged in safely."

            raw = self.adapter.execute(mutated_case, profile, "")
            res = self.adapter.parse(mutated_case, raw)

            if res.outcome == AssuranceOutcome.FAIL or res.outcome == AssuranceOutcome.DETECTED:
                false_positives.append((mutated_case, res))

        return false_positives

    def minimize(
        self,
        case: TestCase,
        profile: RunProfile,
    ) -> TestCase:
        """Delta-debugs a test case file down to minimal triggering content."""
        minimized = copy.deepcopy(case)
        if not minimized.files:
            return minimized

        content = minimized.files[0].get("content", "")
        lines = content.splitlines()
        if len(lines) <= 1:
            return minimized

        # Binary reduction on lines
        mid = len(lines) // 2
        half1 = "\n".join(lines[:mid])
        minimized.files[0]["content"] = half1
        raw = self.adapter.execute(minimized, profile, "")
        res = self.adapter.parse(minimized, raw)

        if res.outcome in (AssuranceOutcome.DETECTED, AssuranceOutcome.FAIL):
            return minimized

        half2 = "\n".join(lines[mid:])
        minimized.files[0]["content"] = half2
        return minimized
