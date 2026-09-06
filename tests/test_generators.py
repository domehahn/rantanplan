"""
Unit tests for programmatic archive and bytecode generators.
"""

from rantanplan.generators.archive import (
    generate_zip_traversal_archive,
    generate_zip_case_collision_archive,
    generate_high_compression_ratio_archive,
)
from rantanplan.generators.pyc import generate_dangerous_bytecode_fixture


def test_zip_traversal_generator():
    data = generate_zip_traversal_archive()
    assert len(data) > 0
    assert b"../../etc/passwd" in data


def test_zip_case_collision_generator():
    data = generate_zip_case_collision_archive()
    assert len(data) > 0
    assert b"SKILL.md" in data
    assert b"skill.md" in data


def test_high_compression_ratio_generator():
    data = generate_high_compression_ratio_archive()
    assert len(data) > 0
    # High compression zip should be much smaller than uncompressed 1MB
    assert len(data) < 50000


def test_dangerous_bytecode_generator():
    data = generate_dangerous_bytecode_fixture()
    assert len(data) > 0
    assert b"os" in data or len(data) > 100
