from __future__ import annotations

import logging
import os
import struct
from functools import cached_property, lru_cache
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.ts import wintimestamp

from dissect.regf.c_regf import (
    REG_BINARY,
    REG_DWORD,
    REG_DWORD_BIG_ENDIAN,
    REG_EXPAND_SZ,
    REG_FULL_RESOURCE_DESCRIPTOR,
    REG_MULTI_SZ,
    REG_NONE,
    REG_QWORD,
    REG_RESOURCE_REQUIREMENTS_LIST,
    REG_SZ,
    c_regf,
)
from dissect.regf.exceptions import (
    Error,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_REGF", "CRITICAL"))


class RegistryHive:
    def __init__(self, fh: BinaryIO):
        self.fh = fh

        data = fh.read(4096)
        self.header = c_regf.REGF_HEADER(data)
        self.filename = self.header.filename.decode("utf-16-le").rstrip("\x00")

        dirty = xor32_crc(data[:508]) == self.header.checksum
        if dirty:
            log.warning(
                "Checksum failed, the %r hive is dirty, recovery needed, "
                "may not be able to read keys and values properly",
                self.filename,
            )
        else:
            log.debug("Hive %r checksum OK", self.filename)

        in_transaction = self.header.primary_sequence != self.header.secondary_sequence
        if in_transaction:
            log.warning(
                "The hive %r is undergoing a transaction, may not be able to read keys and values properly",
                self.filename,
            )
        else:
            log.debug("Hive %r is not undergoing any transactions", self.filename)

        self.hbin_offset = 4096
        self._root = self.cell(self.header.root_key_offset)

        self.cell = lru_cache(4096)(self.cell)

    def root(self) -> IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue:
        return self._root

    def read_cell_data(self, offset: int) -> bytes:
        self.fh.seek(self.hbin_offset + offset)
        size = c_regf.int32(self.fh)
        if size < 0:  # allocated
            size = -size

        return self.fh.read(size - 4)

    def read_cell(self, offset: int) -> IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue:
        data = self.read_cell_data(offset)
        return self.parse_cell_data(data)

    def parse_cell_data(self, data: bytes) -> IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue:
        sig = data[:2]
        if sig == b"li":
            return IndexLeaf(self, data)

        if sig == b"lf":
            return FastLeaf(self, data)

        if sig == b"lh":
            return HashLeaf(self, data)

        if sig == b"ri":
            return IndexRoot(self, data)

        if sig == b"nk":
            return NamedKey(self, data)

        if sig == b"vk":
            return KeyValue(self, data)

        if sig == b"sk":
            raise NotImplementedError(repr(sig))

        if sig == b"db":
            raise NotImplementedError(repr(sig))

        raise NotImplementedError(repr(sig))

    def cell(self, offset: int) -> IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue:
        return self.read_cell(offset)

    def open(self, path: str) -> IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue:
        path = path.strip("\\")
        parts = path.split("\\") if path else []

        realpath = []
        node = self.root()
        for part in parts:
            subkey = node.subkey(part)
            realpath.append(subkey.name)

            node = subkey

        return node

    def walk(self) -> Iterator[tuple[int, bool, NamedKey | bytes]]:
        next_hbin = self.hbin_offset

        while True:
            self.fh.seek(next_hbin)
            header = c_regf.HBIN_HEADER(self.fh)
            if header.signature != 0x6E696268:
                break

            next_hbin += header.size

            while self.fh.tell() < next_hbin:
                offset = self.fh.tell()
                size = c_regf.int32(self.fh)

                allocated = False
                if size < 0:  # allocated
                    size = -size
                    allocated = True

                data = self.read_cell_data(offset)
                try:
                    reg_entry = self.parse_cell_data(data)
                except NotImplementedError:
                    reg_entry = data

                yield offset, allocated, reg_entry


class NamedKey:
    def __init__(self, hive: RegistryHive, data: bytes):
        self.hive = hive
        self._cache = {}

        self.nk = c_regf.NAMED_KEY(data)

        self.class_name = None
        if self.nk.class_name_offset != 0xFFFFFFFF:
            self.class_name = self.hive.read_cell_data(self.nk.class_name_offset)[: self.nk.class_name_size].decode(
                "utf-16-le"
            )

        name_blob = data[len(c_regf.NAMED_KEY) :][: self.nk.key_name_size]

        self.name = decode_name(name_blob, self.nk.key_name_size, self.nk.flags.CompName)

    def __repr__(self) -> str:
        return f"<NamedKey {self.name}>"

    @property
    def path(self) -> str:
        parts = []

        current = self
        # As long as we are not the ROOT key, we add our name to the stack.
        #
        # The path is relative to the hive of this key. Adding a name for the
        # ROOT key will lead to issues when this hive is mapped on a subkey of
        # another hive. The full path to this key is constructed using both the
        # path of the subkey in the other hive and this key's path.
        #
        # If ROOT would be part of that path, that part (and thus the whole
        # path) would not be accesible, nor is the presence of the ROOT part in
        # the path expected by the user (it is never visible in e.g. regedit).
        parent = self.hive.cell(current.nk.parent_key_offset) if current.nk.flags.HiveEntry != 1 else None

        while parent is not None:
            parts.append(current.name)
            current = parent
            parent = self.hive.cell(current.nk.parent_key_offset) if current.nk.flags.HiveEntry != 1 else None

        return "\\".join(list(reversed(parts)))

    @property
    def timestamp(self) -> datetime:
        return wintimestamp(self.nk.last_written)

    @cached_property
    def subkey_list(self) -> IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue | None:
        if not self.nk.num_subkeys:
            return None

        subkey_list = self.hive.cell(self.nk.subkey_list_offset)
        if self.nk.num_subkeys != subkey_list.num_elements:
            log.debug(
                "NamedKey %s has %d subkeys, while the %s has %d elements",
                self.name,
                self.nk.num_subkeys,
                subkey_list.__class__.__name__,
                subkey_list.num_elements,
            )

        return subkey_list

    def subkeys(self) -> Iterator[IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue]:
        if self.subkey_list:
            yield from self.subkey_list

    def subkey(self, name: str) -> IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue:
        lname = name.lower()

        try:
            return self._cache[lname]
        except KeyError:
            pass

        if self.subkey_list:
            sk = self.subkey_list.subkey(name)

            if sk:
                self._cache[lname] = sk
                return sk

        raise RegistryKeyNotFoundError(name)

    def values(self) -> Iterator[KeyValue]:
        if self.nk.num_values:
            data = self.hive.read_cell_data(self.nk.value_list_offset)

            # Possible slack values
            if len(data) // 4 < self.nk.num_values:
                num_values = len(data) // 4
                bytes_short = self.nk.num_values * 4 - len(data)
                if bytes_short:
                    log.debug(
                        "Value list of key %r is %d bytes short reading %d values instead of %d, "
                        "the difference could be due to slack values",
                        self.name,
                        bytes_short,
                        num_values,
                        self.nk.num_values,
                    )
            else:
                num_values = self.nk.num_values

            yield from ValueList(self.hive, data, num_values)

    def value(self, name: str) -> KeyValue:
        for value in self.values():
            if value.name.lower() == name.lower():
                return value

        raise RegistryValueNotFoundError(name)


class KeyValue:
    def __init__(self, hive: RegistryHive, data: bytes):
        self.hive = hive
        self.kv = c_regf.KEY_VALUE(data)

        if data[:2] != b"vk":
            raise Error(f"Invalid KeyValue signature {data[:2]!r}")

        name_blob = data[len(c_regf.KEY_VALUE) :][: self.kv.name_length]
        if self.kv.name_length == 0:
            self.name = "(Default)"
        else:
            self.name = decode_name(name_blob, self.kv.name_length, self.kv.flags.CompName)

    def __repr__(self) -> str:
        return f"<KeyValue {self.name}={self.value!r}>"

    @property
    def type(self) -> int:
        return self.kv.data_type

    @cached_property
    def data(self) -> bytes:
        data_size = self.kv.data_size & ~0x80000000
        if self.kv.data_size & 0x80000000:
            data = struct.pack("I", self.kv.data_offset)[:data_size]
        else:
            data = self.hive.read_cell_data(self.kv.data_offset)[:data_size]
            if data_size != 12 and len(data) == 12:
                bd = c_regf.BIG_DATA(data)
                if bd.signature == 0x6264:
                    segment_list = self.hive.read_cell_data(bd.segment_list_offset)
                    parts = []
                    for segment in c_regf.int32[bd.num_segments](segment_list):
                        part = self.hive.read_cell_data(segment)
                        parts.append(part[:16344])

                    data = b"".join(parts)[:data_size]

        return data

    @cached_property
    def value(self) -> int | str | list[str] | bytes:
        return parse_value(self.kv.data_type, self.data)


class ValueList:
    def __init__(self, hive: RegistryHive, data: bytes, count: int):
        self.hive = hive
        self._values = c_regf.int32[count](data)

    def __iter__(self) -> Iterator[KeyValue]:
        for entry in self._values:
            if entry <= 2:
                continue

            yield KeyValue(self.hive, self.hive.read_cell_data(entry))


class IndexRoot:
    def __init__(self, hive: RegistryHive, data: bytes):
        self.hive = hive
        self.ir = c_regf.INDEX_ROOT(data)

    def __iter__(self) -> Iterator[IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue]:
        for entry in self.ir.entries:
            yield from self.hive.cell(entry)

    @property
    def num_elements(self) -> int:
        return self.ir.num_elements

    def subkey(self, name: str) -> IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue | None:
        for entry in self.ir.entries:
            if sk := self.hive.cell(entry).subkey(name):
                return sk
        return None


class IndexLeaf:
    def __init__(self, hive: RegistryHive, data: bytes):
        self.hive = hive
        self.il = c_regf.INDEX_LEAF(data)

    def __iter__(self) -> Iterator[IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue]:
        for entry in self.il.entries:
            yield self.hive.cell(entry)

    @property
    def num_elements(self) -> int:
        return self.il.num_elements

    def subkey(self, name: str) -> IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue | None:
        for entry in self.il.entries:
            if (sk := self.hive.cell(entry)).name == name:
                return sk
        return None


class HashLeaf:
    def __init__(self, hive: RegistryHive, data: bytes):
        self.hive = hive
        self.hl = c_regf.HASH_LEAF(data)

    def __iter__(self) -> Iterator[IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue]:
        for entry in self.hl.entries:
            yield self.hive.cell(entry.key_node_offset)

    @property
    def num_elements(self) -> int:
        return self.hl.num_elements

    def subkey(self, name: str) -> IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue | None:
        name_hash = hashname(name)
        name = name.lower()

        for entry in self.hl.entries:
            if name_hash == entry.name_hash and (sk := self.hive.cell(entry.key_node_offset)).name.lower() == name:
                return sk

        return None


class FastLeaf:
    def __init__(self, hive: RegistryHive, data: bytes):
        self.hive = hive
        self.fl = c_regf.FAST_LEAF(data)

    def __iter__(self) -> Iterator[IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue]:
        for entry in self.fl.entries:
            yield self.hive.cell(entry.key_node_offset)

    @property
    def num_elements(self) -> int:
        return self.fl.num_elements

    def subkey(self, name: str) -> IndexLeaf | FastLeaf | HashLeaf | IndexRoot | NamedKey | KeyValue | None:
        name = name.lower()
        name_hint = name[:4]

        for entry in self.fl.entries:
            # If names are < 4 characters, the name hint is padded with
            # 0-bytes, the characters are stored from the lowest byte number
            # up.
            # Note that names of keys are only supposed to contain "printable
            # characters except the `\' character", which probably is the
            # printable subset of ascii (MS documentation is inconclusive on
            # this).
            if (
                name_hint == entry.name_hint.rstrip(b"\x00").decode("ascii").lower()
                and (sk := self.hive.cell(entry.key_node_offset)).name.lower() == name
            ):
                return sk

        return None


def decode_name(blob: bytes, size: int, is_comp_name: bool) -> str:
    if is_comp_name:
        try:
            return blob.decode()
        except UnicodeDecodeError:
            pass

        try:
            return blob.decode("latin1")
        except UnicodeDecodeError:
            pass
    else:
        try:
            return c_regf.wchar[size // 2](blob)
        except UnicodeDecodeError:
            pass

    return repr(blob)


def try_decode_sz(data: bytes) -> str:
    if not len(data):
        return ""

    try:
        if (data.isascii() or data.endswith(b"\x00")) and data[1:2] != b"\x00":
            # This will return the string latin1 decoded up until the first
            # NULL byte.
            return data.split(b"\x00")[0].decode("latin1")

        if len(data) % 2 != 0:
            data = data.ljust(len(data) + 1, b"\x00")

        # This will return the string utf-16-le decoded up until the first
        # double NULL byte.
        # A naive split on two NULL bytes will not work as the possibility
        # exists that the first NULL byte is the high byte of the first
        # character and the second NULL byte the low byte of the second
        # character. So the first NULL byte should start at an even index in
        # the data.
        idx = -1
        while (idx := data.find(b"\x00\x00", idx + 1)) & 1:
            if idx == -1:
                idx = len(data)
                break
        return data[:idx].decode("utf-16-le")

    except UnicodeDecodeError:
        # Last ditch effort, decode the whole bytestring as if it were utf-16,
        # any decoding errors, which incase of utf-16 will be invalid utf-16
        # surrogates, will be ignored.
        return data.decode("utf-16-le", "ignore").strip("\x00")


def parse_value(data_type: int, data: bytes) -> int | str | list[str] | bytes:
    if data_type in (REG_DWORD, REG_DWORD_BIG_ENDIAN):
        if len(data) == 0:
            return 0

        if data_type == REG_DWORD:
            return c_regf.uint32(data[:4])

        if data_type == REG_DWORD_BIG_ENDIAN:
            return struct.unpack(">I", data[:4])[0]

    if data_type == REG_QWORD:
        return c_regf.uint64(data) if len(data) else 0

    if data_type in (REG_SZ, REG_EXPAND_SZ):
        return try_decode_sz(data)

    if data_type in (REG_BINARY, REG_NONE):
        return data

    if data_type == REG_MULTI_SZ:
        data_len = len(data)
        data = BytesIO(data)

        multi_string = []
        while data.tell() < data_len:
            string = read_null_terminated_wstring(data)
            if string == "":
                break

            multi_string.append(string)

        return multi_string

    if data_type == REG_FULL_RESOURCE_DESCRIPTOR:
        log.warning("Unimplemented REG_FULL_RESOURCE_DESCRIPTOR")
        return data

    if data_type == REG_RESOURCE_REQUIREMENTS_LIST:
        log.warning("Unimplemented REG_RESOURCE_REQUIREMENTS_LIST")
        return data

    log.warning("Data type 0x%x not supported", data_type)
    return data


def read_null_terminated_wstring(stream: BinaryIO, encoding: str = "utf-16-le") -> str:
    """Adapted function to read null terminated wide strings.

    The cstruct way raises EOFError when the end of the stream is reached.
    This is fine, but not what we want for this particular implementation.
    """
    wide_string = b""
    while True:
        wide_char = stream.read(2)

        if len(wide_char) != 2 or wide_char == b"\x00\x00":
            break

        wide_string += wide_char

    return wide_string.decode(encoding)


def hashname(name: str) -> int:
    # Note that `name' is a python str(), which means the ord() used to
    # calculate name_hash works (it wouldn't for byte()).
    # Also note that names of keys are only supposed to contain "printable
    # characters except the `\' character", which probably is the printable
    # subset of ascii (MS documentation is inconclusive on this).
    name_hash = 0
    for char in name.upper():
        name_hash = (name_hash * 37 + ord(char)) & 0xFFFFFFFF

    return name_hash


def xor32_crc(data: bytes) -> int:
    crc = 0
    for ii in c_regf.uint32[len(data) // 4](data):
        crc ^= ii

    return crc
