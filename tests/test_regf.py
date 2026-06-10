from __future__ import annotations

import logging
from typing import BinaryIO

import pytest

from dissect.regf import regf
from dissect.regf.exceptions import RegistryKeyNotFoundError


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


def test_bad_keyvalue_cell_entry(bad_key_value_cell_hive: BinaryIO, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, regf.log.name):
        hive = regf.RegistryHive(bad_key_value_cell_hive)
        root = hive.root()

        assert len(list(root.subkeys())) == 1
        svc = root.subkey("Service")

        values = list(svc.values())

        assert len(values) == 2
        value_dict = {v.name: v for v in values}

        assert "Type" in value_dict
        assert value_dict["Type"].type == 4  # REG_DWORD
        assert value_dict["Type"].value == 224

        assert "Start" in value_dict
        assert value_dict["Start"].type == 4  # REG_DWORD
        assert value_dict["Start"].value == 3

    assert "Invalid cell signature b'6\\x00' at offset 0x130" in caplog.text


def test_fastleaf_non_ascii_subkey(fastleaf_hive: BinaryIO) -> None:
    hive = regf.RegistryHive(fastleaf_hive)
    root = hive.root()

    assert isinstance(root._subkey_list, regf.FastLeaf)

    key = root.subkey("Администратор")
    assert key.name == "Администратор"

    key = root.subkey("Гость")
    assert key.name == "Гость"

    with pytest.raises(RegistryKeyNotFoundError):
        root.subkey("Missing")
