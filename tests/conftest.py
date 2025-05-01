from __future__ import annotations

import gzip
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def open_file_gz(name: str) -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(name), "rb") as fh:
        yield fh


@pytest.fixture
def system_hive() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/SYSTEM.gz")
