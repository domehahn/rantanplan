"""
Programmatic archive generators for testing scanner archive processing safety.
"""

import io
import os
import zipfile
from typing import Tuple


def generate_zip_traversal_archive() -> bytes:
    """Generates an in-memory ZIP archive containing parent directory traversal paths (e.g. ../../etc/passwd)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # Dangerous parent directory traversal path
        zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        zf.writestr("SKILL.md", "# Skill with ZIP Traversal\n")
    return buffer.getvalue()


def generate_zip_case_collision_archive() -> bytes:
    """Generates an archive with case-colliding filenames (e.g. skill.md vs SKILL.md)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("SKILL.md", "# Upper Case Skill\n")
        zf.writestr("skill.md", "# Lower Case Skill\n")
    return buffer.getvalue()


def generate_high_compression_ratio_archive() -> bytes:
    """Generates a small in-memory zip bomb candidate (high compression ratio of repetitive zeroes)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1MB of zeroes compresses to a few bytes
        zf.writestr("zeroes.dat", b"0" * 1024 * 1024)
        zf.writestr("SKILL.md", "# High Compression Test Skill\n")
    return buffer.getvalue()

