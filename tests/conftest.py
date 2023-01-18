import gzip
import os

import pytest


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


def open_file_gz(name):
    with gzip.GzipFile(absolute_path(name), "rb") as f:
        yield f


@pytest.fixture
def system_hive():
    yield from open_file_gz("data/SYSTEM.gz")
