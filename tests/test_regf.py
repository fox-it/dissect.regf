from __future__ import annotations

from typing import BinaryIO

import pytest

from dissect.regf import regf


def test_regf(system_hive: BinaryIO) -> None:
    hive = regf.RegistryHive(system_hive)

    root = hive.root()

    assert len(list(root.subkeys())) == 17
    assert root.name == "ROOT"
    assert root.path == ""
    assert hive.open("Software") is root.subkey("Software") is root.subkey("software")

    key_path = "ControlSet001\\Control\\Lsa"
    lsa = hive.open(key_path)

    assert lsa.name == "Lsa"
    assert lsa.path == key_path
    assert lsa.subkey("JD").class_name == "cdebfed5"
    assert lsa.subkey("Skew1").class_name == "7db4e11c"
    assert lsa.subkey("GBG").class_name == "b185f3f2"
    assert lsa.subkey("Data").class_name == "a282942c"

    assert hive.open("ControlSet001\\Services\\Tcpip\\Parameters\\DNSRegisteredAdapters").class_name == "DynDRootClass"

    assert list(hive.walk())


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (
            b"",
            "",
        ),
        (
            b"The Quick Brown Fox\x00Jumped Over The Lazy Dog",
            "The Quick Brown Fox",
        ),
        (
            b"The Quick Brown Fox\x00Jumped Over The Lazy Dog\x00",
            "The Quick Brown Fox",
        ),
        (
            b"The Quick Brown Fox",
            "The Quick Brown Fox",
        ),
        (
            "The Quick Brown Fox\x00Jumped Over The Lazy Dog".encode("utf-16-le"),
            "The Quick Brown Fox",
        ),
        (
            "The Quick Brown Fox\x00Jumped Over The Lazy Dog\x00".encode("utf-16-le"),
            "The Quick Brown Fox",
        ),
        (
            "The Quick Brown Fox\x00Jumped Over The Lazy Dog".encode("utf-16-le") + b"\x00",
            "The Quick Brown Fox",
        ),
        (
            "The Quick Brown Fox".encode("utf-16-le"),
            "The Quick Brown Fox",
        ),
        (
            b"\xe4bcd\x00",  # interpreted as latin1
            "äbcd",
        ),
        (
            b"\xe4bcd",  # interpreted as utf-16-le
            "拤摣",
        ),
        (
            b"\x41\x00\x00\x01\x42\x00",
            "AĀB",
        ),
    ],
)
def test_try_decode_sz(data: bytes, expected: str) -> None:
    assert regf.try_decode_sz(data) == expected
