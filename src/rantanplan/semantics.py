"""
Reference semantics for Rantanplan.

This module is the *independent definition of meaning* that the metamorphic oracle,
the corpus consistency check and the ``mock-strict`` calibration target are built on.
It is deliberately a transparent, rule-based analyzer rather than another scanner:

1. ``deobfuscate`` removes presentation tricks (zero-width characters, BIDI controls,
   homoglyphs, base64 blobs, string-literal concatenation) without changing meaning.
2. ``analyze`` extracts capability signals (``secrets.read``, ``network.external``, ...)
   sentence by sentence, honouring defensive negation ("Never send API keys ...").
3. ``indicators`` extracts literal artefacts (hosts, destructive commands) that must
   survive any meaning-preserving mutation unchanged.

Known limits (documented, not hidden): English-only lexicon, no data-flow analysis for
code beyond pattern matching, no handling of encodings other than base64.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

from rantanplan.lexicon import (
    DEFENSIVE_CUES,
    DESTINATION_PATTERNS,
    EXEC_PATTERNS,
    HIDDEN_INSTRUCTION_PATTERNS,
    INJECTION_PATTERNS,
    PRONOUN_REFERENCES,
    SOURCE_PATTERNS,
    TRANSFER_VERBS,
)

ZERO_WIDTH = "\u200b\u200c\u200d\u2060\ufeff\u00ad"
BIDI_CONTROLS = "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"

# Cyrillic / Greek look-alikes of Latin letters (reference confusables table).
CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u0501": "d",
    "\u0261": "g", "\u03bf": "o", "\u0391": "A", "\u0415": "E", "\u041e": "O",
    "\u0420": "P", "\u0421": "C", "\u0425": "X", "\u0406": "I",
}

_STRIP_TABLE = {ord(c): None for c in ZERO_WIDTH + BIDI_CONTROLS}
_CONFUSABLE_TABLE = {ord(k): v for k, v in CONFUSABLES.items()}

_ALIAS_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(os\.environ(?:\.copy\(\))?|os\.getenv\([^)]*\))\s*$", re.MULTILINE)
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_CONCAT_RE = re.compile(r"""(["'])\s*\+\s*\1""")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+|;")
_HOST_RE = re.compile(r"[\w-]+(?:\.[\w-]+)*\.(?:com|org|net|io|dev|ru|cn|xyz|example)\b", re.UNICODE)


@dataclass(frozen=True)
class Analysis:
    """Result of analysing the full text of a case."""

    signals: frozenset[str] = field(default_factory=frozenset)
    malicious: bool = False
    indicators: frozenset[str] = field(default_factory=frozenset)
    obfuscated: bool = False
    negated_signals: frozenset[str] = field(default_factory=frozenset)


def has_hidden_characters(text: str) -> bool:
    return any(c in text for c in ZERO_WIDTH + BIDI_CONTROLS) or any(c in text for c in CONFUSABLES)


def _decode_b64_blobs(text: str) -> list[str]:
    decoded: list[str] = []
    for match in _B64_RE.finditer(text):
        blob = match.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            candidate = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if candidate and sum(unicodedata.category(ch) != "Cc" or ch in "\n\t" for ch in candidate) / len(candidate) > 0.95:
            decoded.append(candidate)
    return decoded


def _resolve_aliases(text: str) -> str:
    """Replace variables assigned from a secret source by the source expression itself."""
    for name, source in _ALIAS_RE.findall(text):
        text = re.sub(rf"\b{re.escape(name)}\b(?!\s*=\s*os\.)", source, text)
    return text


def deobfuscate(text: str, map_confusables: bool = True) -> str:
    """Return ``text`` plus decoded payloads, with presentation tricks removed."""
    text = unicodedata.normalize("NFKC", text).translate(_STRIP_TABLE)
    if map_confusables:
        text = text.translate(_CONFUSABLE_TABLE)
    text = _CONCAT_RE.sub("", text)
    text = _resolve_aliases(text)
    extra = _decode_b64_blobs(text)
    if extra:
        text = text + "\n" + "\n".join(deobfuscate(e, map_confusables) for e in extra)
    return text


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENTENCE_SPLIT_RE.split(text) if s and s.strip()]


def _any(patterns: tuple[re.Pattern[str], ...], text: str) -> bool:
    return any(p.search(text) for p in patterns)


def _is_defensive(sentence: str) -> bool:
    scrubbed = sentence
    for pat in HIDDEN_INSTRUCTION_PATTERNS:
        scrubbed = pat.sub(" ", scrubbed)
    return _any(DEFENSIVE_CUES, scrubbed)


def _sentence_signals(sentence: str) -> set[str]:
    sig: set[str] = set()
    if _any(SOURCE_PATTERNS, sentence):
        sig.add("secrets.read")
    if _any(TRANSFER_VERBS, sentence) and _any(DESTINATION_PATTERNS, sentence):
        sig.add("network.external")
    if _any(INJECTION_PATTERNS, sentence):
        sig.add("prompt.override")
    if _any(EXEC_PATTERNS, sentence):
        sig.add("code.exec.destructive")
    if _any(HIDDEN_INSTRUCTION_PATTERNS, sentence):
        sig.add("tool.hidden-instruction")
    return sig


def analyze_text(text: str) -> Analysis:
    """Analyse already-concatenated text (all files of a case)."""
    obfuscated = has_hidden_characters(text) or bool(_decode_b64_blobs(text))
    sentences = _sentences(deobfuscate(text))

    active: set[str] = set()
    negated: set[str] = set()
    source_at: list[int] = []
    pronoun_sinks: list[int] = []
    exfil = False

    for i, sentence in enumerate(sentences):
        sig = _sentence_signals(sentence)
        if _is_defensive(sentence):
            negated |= sig
            continue
        active |= sig
        if "secrets.read" in sig:
            source_at.append(i)
            if "network.external" in sig:
                exfil = True
        if "network.external" in sig and _any(PRONOUN_REFERENCES, sentence):
            pronoun_sinks.append(i)

    if not exfil:
        # split-instruction / cross-file chain: a secret is collected, then "it" is forwarded
        exfil = any(0 < sink - src <= 4 for sink in pronoun_sinks for src in source_at)

    if not exfil:
        active -= {"secrets.read", "network.external"}

    actionable = any(_any(TRANSFER_VERBS, s) or _any(SOURCE_PATTERNS, s) for s in sentences if not _is_defensive(s))
    if "tool.hidden-instruction" in active and not (exfil or "secrets.read" in active or actionable):
        active.discard("tool.hidden-instruction")

    malicious = exfil or bool(active & {"prompt.override", "code.exec.destructive", "tool.hidden-instruction"})
    return Analysis(
        signals=frozenset(active),
        malicious=malicious,
        indicators=indicators(text),
        obfuscated=obfuscated,
        negated_signals=frozenset(negated),
    )


def indicators(text: str) -> frozenset[str]:
    """Literal artefacts (hosts, destructive commands) that a faithful mutation must preserve.

    Computed *without* confusable mapping so that a homoglyph inside a host name is a
    different indicator (a different domain is a different meaning).
    """
    raw = deobfuscate(text, map_confusables=False)
    found: set[str] = {h.lower() for h in _HOST_RE.findall(raw)}
    for pat in EXEC_PATTERNS:
        for m in pat.finditer(raw):
            found.add(re.sub(r"\s+", " ", m.group(0).lower()))
    return frozenset(found)


def analyze_files(files: list[dict[str, str]]) -> Analysis:
    """Analyse every file of a case as one document (cross-file chains are visible)."""
    ordered = sorted(files, key=lambda f: (0 if f.get("path", "").upper().endswith("SKILL.MD") else 1, f.get("path", "")))
    return analyze_text("\n".join(f.get("content", "") for f in ordered))
