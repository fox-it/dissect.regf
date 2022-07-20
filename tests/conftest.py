import os
import io
import zlib
import pytest


def open_data(name):
    with open(os.path.join(os.path.dirname(__file__), name), "rb") as fh:
        buf = fh.read()

    return io.BytesIO(zlib.decompress(buf))


@pytest.fixture
def system_hive():
    return open_data("data/SYSTEM.bin")
