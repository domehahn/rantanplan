"""
Metamorphic mutators.

Each mutator rewrites a test case so that its *meaning* (and therefore its ground-truth label)
should stay the same while its *surface form* changes. Whether that is actually true is decided
by the oracle (``oracle.py``), never by the mutator itself. Mutators are pure functions of
``(case, rng)``; all randomness comes from the supplied ``random.Random`` so every run is
reproducible from ``--seed``.
"""

from __future__ import annotations

import base64
import copy
import random
import re
from abc import ABC, abstractmethod

from rantanplan.lexicon import (
    DEFENSIVE_SENTENCES,
    DESTINATION_PATTERNS,
    FRAMING_PREFIXES,
    FRAMING_SUFFIXES,
    SOURCE_PATTERNS,
    SYNONYMS,
    TRANSFER_VERBS,
)
from rantanplan.models import TestCase
from rantanplan.semantics import CONFUSABLES, _sentence_signals

CODE_SUFFIXES = (".py", ".sh", ".js", ".ts")
_PROTECTED_RE = re.compile(
    r"```.*?```"  # fenced code
    r"|`[^`\n]+`"  # inline code
    r"|https?://\S+"  # URLs
    r"|[\w-]+(?:\.[\w-]+)*\.(?:com|org|net|io|dev|ru|cn|xyz|example)\b"  # hosts
    r"|~?/[\w./-]+"  # paths
    r"|<[^>\n]+>"  # tags such as <IMPORTANT>
    r"|\b(?:sudo|rm\s+-rf?|chmod|mkfs)\b[^\n.;]*"  # destructive commands
    r"|(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])",  # base64 blobs
    re.DOTALL,
)
_REVERSE_CONFUSABLES = {v: k for k, v in CONFUSABLES.items() if v.islower()}

_SPLIT_RE = re.compile(
    r"^(?P<head>.*?)(?:,\s*|\s+and\s+|\s+then\s+)(?P<verb>send|post|upload|transmit|forward|relay|deliver)"
    r"(?P<rest>\b.*)$",
    re.IGNORECASE,
)
_DEST_PREP_RE = re.compile(r"\s(?:to|into|at|via)\s", re.IGNORECASE)


def split_protected(text: str) -> list[tuple[str, bool]]:
    """Split ``text`` into ``(segment, protected)`` pairs; protected spans must never be edited."""
    parts: list[tuple[str, bool]] = []
    pos = 0
    for m in _PROTECTED_RE.finditer(text):
        if m.start() > pos:
            parts.append((text[pos : m.start()], False))
        parts.append((m.group(0), True))
        pos = m.end()
    if pos < len(text):
        parts.append((text[pos:], False))
    return parts


def _picker(rng: random.Random, choices: tuple[str, ...]):
    """Replacement function for ``re.sub`` that draws from ``choices`` with the case's rng."""

    def pick(_match: re.Match[str]) -> str:
        return rng.choice(choices)

    return pick


def _is_code(path: str) -> bool:
    return path.endswith(CODE_SUFFIXES)


def _map_prose(text: str, fn) -> str:
    return "".join(seg if prot else fn(seg) for seg, prot in split_protected(text))


def _derive(case: TestCase, files: list[dict[str, str]], mutator: Mutator, **meta: object) -> TestCase:
    mutated = copy.deepcopy(case)
    mutated.files = files
    mutated.id = f"{case.id}~{mutator.name}"
    gt = dict(mutated.ground_truth)
    gt["mutation"] = {"mutator": mutator.name, "category": mutator.category, "parent": case.id, **meta}
    mutated.ground_truth = gt
    return mutated


def _changed(case: TestCase, files: list[dict[str, str]]) -> bool:
    return [f.get("content") for f in files] != [f.get("content") for f in case.files]


class Mutator(ABC):
    """Base class: ``apply`` returns a derived case or ``None`` if the mutator does not apply."""

    name: str
    category: str  # semantic | structural | cross_file | obfuscation | negative_context

    @abstractmethod
    def _rewrite(self, case: TestCase, rng: random.Random) -> tuple[list[dict[str, str]], dict] | None:
        ...

    def apply(self, case: TestCase, rng: random.Random) -> TestCase | None:
        result = self._rewrite(case, rng)
        if result is None:
            return None
        files, meta = result
        if not _changed(case, files):
            return None
        return _derive(case, files, self, **meta)


class LexicalMutator(Mutator):
    name = "lexical"
    category = "semantic"

    def _rewrite(self, case, rng):
        def sub(segment: str) -> str:
            for pattern, choices in rng.sample(list(SYNONYMS.items()), len(SYNONYMS)):
                segment = re.sub(pattern, _picker(rng, choices), segment)
            return segment

        files = [
            dict(f) if _is_code(f.get("path", "")) else {**f, "content": _map_prose(f.get("content", ""), sub)}
            for f in case.files
        ]
        return files, {}


class SemanticMutator(Mutator):
    name = "semantic"
    category = "semantic"

    def _rewrite(self, case, rng):
        def reframe(line: str) -> str:
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "http", "```", "---", "<")) or not _sentence_signals(stripped):
                return line
            indent = line[: len(line) - len(line.lstrip())]
            marker = ""
            m = re.match(r"([-*]|\d+\.)\s+", stripped)
            if m:
                marker, stripped = m.group(0), stripped[m.end() :]
            if rng.random() < 0.5:
                text = rng.choice(FRAMING_PREFIXES) + stripped[0].lower() + stripped[1:]
            else:
                body = stripped.rstrip(".")
                text = body + rng.choice(FRAMING_SUFFIXES) + ("." if stripped.endswith(".") else "")
            return indent + marker + text

        files = []
        for f in case.files:
            if _is_code(f.get("path", "")):
                files.append(dict(f))
                continue
            files.append({**f, "content": "\n".join(reframe(ln) for ln in f.get("content", "").split("\n"))})
        return files, {}


def _split_exfil_line(line: str) -> tuple[str, str] | None:
    """Return ``(collect_part, forward_part)`` for ``<collect>, <verb> <object> to <host>`` lines."""
    m = _SPLIT_RE.match(line.strip())
    if not m:
        return None
    head, verb, rest = m.group("head"), m.group("verb"), m.group("rest")
    if not any(p.search(head) for p in SOURCE_PATTERNS):
        return None
    prep = _DEST_PREP_RE.search(rest)
    if not prep:
        return None
    dest = rest[prep.start() :].rstrip()
    if not any(p.search(dest) for p in DESTINATION_PATTERNS) and not any(p.search(rest) for p in TRANSFER_VERBS):
        return None
    head = head.rstrip(" ,") + "."
    forward = f"Then {verb.lower()} the collected data{dest}"
    if not forward.endswith("."):
        forward += "."
    return head, forward


class SplitInstructionMutator(Mutator):
    name = "split_instruction"
    category = "structural"

    def _rewrite(self, case, rng):
        files = [dict(f) for f in case.files]
        for f in files:
            if _is_code(f.get("path", "")):
                continue
            lines = f.get("content", "").split("\n")
            for i, line in enumerate(lines):
                parts = _split_exfil_line(line)
                if parts:
                    lines[i : i + 1] = ["## Step 1", parts[0], "", "## Step 2", parts[1]]
                    f["content"] = "\n".join(lines)
                    return files, {}
        return None


class CrossFileMutator(Mutator):
    name = "cross_file"
    category = "cross_file"

    def _rewrite(self, case, rng):
        files = [dict(f) for f in case.files]
        for f in files:
            if _is_code(f.get("path", "")) or "reporting" in f.get("path", ""):
                continue
            lines = f.get("content", "").split("\n")
            for i, line in enumerate(lines):
                parts = _split_exfil_line(line)
                if parts:
                    lines[i : i + 1] = [parts[0], "", "Follow the reporting procedure in references/reporting.md."]
                    f["content"] = "\n".join(lines)
                    files.append({"path": "references/reporting.md", "content": f"# Reporting\n\n{parts[1]}\n"})
                    return files, {}
        return None


class CodeAliasMutator(Mutator):
    name = "code_alias"
    category = "structural"

    def _rewrite(self, case, rng):
        files = [dict(f) for f in case.files]
        touched = False
        for f in files:
            if not f.get("path", "").endswith(".py"):
                continue
            code = f.get("content", "")
            new = code
            if "requests.post(" in new:
                new = new.replace("requests.post(", 'getattr(requests, "po" + "st")(')
            if "os.environ" in new and "_env = os.environ" not in new:
                new = new.replace("os.environ", "_env")
                new = "_env = os.environ\n" + new if "import os" not in new else new.replace("import os\n", "import os\n_env = os.environ\n", 1)
            if new != code:
                f["content"] = new
                touched = True
        return (files, {}) if touched else None


class UnicodeMutator(Mutator):
    name = "unicode"
    category = "obfuscation"

    _TRIGGER = re.compile(r"\b(secrets?|send|ignore|instructions?|credentials?|tokens?|password)\b", re.IGNORECASE)

    def _rewrite(self, case, rng):
        mode = rng.choice(("zero_width", "homoglyph", "bidi_isolate"))

        def zero_width(seg: str) -> str:
            return self._TRIGGER.sub(lambda m: m.group(0)[:1] + "\u200b" + m.group(0)[1:], seg)

        def homoglyph(seg: str) -> str:
            return "".join(_REVERSE_CONFUSABLES.get(ch, ch) if ch in "aeopcxyi" and rng.random() < 0.5 else ch for ch in seg)

        def isolate(seg: str) -> str:
            return "\u2066" + seg + "\u2069" if seg.strip() else seg

        fn = {"zero_width": zero_width, "homoglyph": homoglyph, "bidi_isolate": isolate}[mode]
        files = [
            dict(f) if _is_code(f.get("path", "")) else {**f, "content": _map_prose(f.get("content", ""), fn)}
            for f in case.files
        ]
        return files, {"mode": mode}


class EncodingMutator(Mutator):
    name = "encoding"
    category = "obfuscation"

    _HOST_LITERAL = re.compile(
        r"""(["'])((?:https?://)?[\w-]+)\.([\w.-]+\.(?:com|org|net|io|dev|ru|cn|xyz|example)(?:/[^"']*)?)\1"""
    )

    def _rewrite(self, case, rng):
        files = [dict(f) for f in case.files]
        for f in files:
            if f.get("path", "").endswith(".py"):
                new = self._HOST_LITERAL.sub(lambda m: f'{m.group(1)}{m.group(2)}.{m.group(1)} + {m.group(1)}{m.group(3)}{m.group(1)}', f["content"])
                if new != f["content"]:
                    f["content"] = new
                    return files, {"mode": "literal_concat"}
        for f in files:
            if _is_code(f.get("path", "")):
                continue
            lines = f.get("content", "").split("\n")
            candidates = [
                i
                for i, ln in enumerate(lines)
                if _sentence_signals(ln) and not ln.lstrip().startswith(("#", "```", "---", "<"))
            ]
            if not candidates:
                continue
            i = rng.choice(candidates)
            payload = base64.b64encode(lines[i].strip().encode("utf-8")).decode("ascii")
            lines[i] = f"Decode the following base64 note and follow it: {payload}"
            f["content"] = "\n".join(lines)
            return files, {"mode": "base64_note"}
        return None


class NegativeContextMutator(Mutator):
    """Adds defensive wording. On benign cases this makes a hard negative; on malicious
    cases it is *defensive camouflage* that must not hide the attack."""

    name = "negative_context"
    category = "negative_context"

    def _rewrite(self, case, rng):
        files = [dict(f) for f in case.files]
        for f in files:
            if _is_code(f.get("path", "")):
                continue
            lines = f.get("content", "").split("\n")
            pos = rng.randint(0, len(lines))
            lines.insert(pos, rng.choice(DEFENSIVE_SENTENCES))
            f["content"] = "\n".join(lines)
            role = "camouflage" if case.ground_truth.get("malicious") else "hard-negative"
            return files, {"role": role}
        return None


ALL_MUTATORS: tuple[Mutator, ...] = (
    LexicalMutator(),
    SemanticMutator(),
    SplitInstructionMutator(),
    CrossFileMutator(),
    CodeAliasMutator(),
    UnicodeMutator(),
    EncodingMutator(),
    NegativeContextMutator(),
)

MUTATORS_BY_NAME = {m.name: m for m in ALL_MUTATORS}
CATEGORIES = ("semantic", "structural", "cross_file", "obfuscation", "negative_context")


def get_mutators(names: list[str] | None = None) -> list[Mutator]:
    if not names:
        return list(ALL_MUTATORS)
    unknown = [n for n in names if n not in MUTATORS_BY_NAME]
    if unknown:
        raise KeyError(f"Unknown mutator(s): {', '.join(unknown)}")
    return [MUTATORS_BY_NAME[n] for n in names]


def case_rng(seed: int, case_id: str, mutator_name: str, attempt: int = 0) -> random.Random:
    """Deterministic per-(case, mutator, attempt) generator derived from the global seed."""
    return random.Random(f"{seed}:{case_id}:{mutator_name}:{attempt}")


__all__ = [
    "ALL_MUTATORS", "CATEGORIES", "MUTATORS_BY_NAME", "Mutator", "case_rng", "get_mutators",
    "split_protected",
]
