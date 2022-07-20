import os
import sys
import struct
import logging
from functools import lru_cache

from io import BytesIO

from dissect.util.ts import wintimestamp

from dissect.regf.c_regf import (
    c_regf,
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
)
from dissect.regf.exceptions import Error, RegistryKeyNotFoundError, RegistryValueNotFoundError


log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_REGF", "CRITICAL"))


PY37 = sys.version_info[0] == 3 and sys.version_info[1] >= 7


class RegistryHive:
    def __init__(self, fh):
        self.fh = fh

        data = fh.read(4096)
        self.header = c_regf.REGF_HEADER(data)
        self.filename = self.header.filename.decode("utf-16-le").rstrip("\x00")

        dirty = xor32_crc(data[:508]) == self.header.checksum
        if dirty:
            log.warning(
                f"Checksum failed, the {self.filename!r} hive is dirty, recovery needed, "
                "may not be able to read keys and values properly."
            )
        else:
            log.debug(f"Hive {self.filename!r} checksum OK.")
        in_transaction = self.header.primary_sequence != self.header.secondary_sequence
        if in_transaction:
            log.warning(
                f"The hive {self.filename!r} is undergoing a transaction, "
                "may not be able to read keys and values properly."
            )
        else:
            log.debug(f"Hive {self.filename!r} is not undergoing any transactions.")

        self.hbin_offset = 4096
        self._root = self.cell(self.header.root_key_offset)

    def root(self):
        return self._root

    def read_cell_data(self, offset):
        self.fh.seek(self.hbin_offset + offset)
        size = c_regf.int32(self.fh)
        if size < 0:  # allocated
            size = -size

        return self.fh.read(size - 4)

    def read_cell(self, offset):
        data = self.read_cell_data(offset)
        return self.parse_cell_data(data)

    def parse_cell_data(self, data):
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

    @lru_cache(4096)
    def cell(self, offset):
        return self.read_cell(offset)

    def open(self, path):
        path = path.strip("\\")
        if path:
            parts = path.split("\\")
        else:
            parts = []

        realpath = []
        node = self._root
        for part in parts:
            subkey = node.subkey(part)
            realpath.append(subkey.name)

            node = subkey

        return node

    def walk(self):
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
    def __init__(self, hive, data):
        self.hive = hive
        self._cache = {}
        self._subkey_list = None

        self.nk = c_regf.NAMED_KEY(data)

        name_blob = data[len(c_regf.NAMED_KEY) :][: self.nk.key_name_size]
        self.name = decode_name(name_blob, self.nk.key_name_size, self.nk.flags.CompName)

    @property
    def subkey_list(self):
        if not self.nk.num_subkeys:
            return None

        if not self._subkey_list:
            self._subkey_list = self.hive.cell(self.nk.subkey_list_offset)

            if self.nk.num_subkeys != self._subkey_list.num_elements:
                log.debug(
                    f"NamedKey {self.name} has {self.nk.num_subkeys} subkeys, while the "
                    f"{self._subkey_list.__class__.__name__} has "
                    f"{self._subkey_list.num_elements} elements"
                )

        return self._subkey_list

    def subkeys(self):
        if self.subkey_list:
            for subkey in self.subkey_list:
                yield subkey

    def subkey(self, name):
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

    def values(self):
        if self.nk.num_values:
            data = self.hive.read_cell_data(self.nk.value_list_offset)

            # Possible slack values
            if len(data) // 4 < self.nk.num_values:
                num_values = len(data) // 4
                bytes_short = self.nk.num_values * 4 - len(data)
                if bytes_short:
                    log.debug(
                        f"Value list of key {self.name!r} is {bytes_short} bytes short "
                        f"reading {num_values} values instead of {self.nk.num_values}, "
                        "the difference could be due to slack values."
                    )
            else:
                num_values = self.nk.num_values

            values_list = ValueList(self.hive, data, num_values)

            for i in values_list:
                yield i

    def value(self, name):
        for value in self.values():
            if value.name.lower() == name.lower():
                return value

        raise RegistryValueNotFoundError(name)

    @property
    def path(self):
        parts = [self.name]
        data = self.hive.cell(self.nk.parent_key_offset)
        parts.append(data.name)

        while data.nk.flags.HiveEntry != 1:
            data = self.hive.cell(data.nk.parent_key_offset)
            parts.append(data.name)

        return "\\".join(list(reversed(parts)))

    @property
    def timestamp(self):
        return wintimestamp(self.nk.last_written)

    def __repr__(self):
        return f"<NamedKey {self.name}>"


class KeyValue:
    def __init__(self, hive, data):
        self.hive = hive
        self.kv = c_regf.KEY_VALUE(data)
        self._data = None
        self._value = None

        if data[:2] != b"vk":
            raise Error(f"Invalid KeyValue signature {repr(data[:2])}")

        name_blob = data[len(c_regf.KEY_VALUE) :][: self.kv.name_length]
        if self.kv.name_length == 0:
            self.name = "(Default)"
        else:
            self.name = decode_name(name_blob, self.kv.name_length, self.kv.flags.CompName)

    @property
    def type(self):
        return self.kv.data_type

    @property
    def data(self):
        if self._data is None:
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

                        data = b"".join(parts)

                        # assert(len(data) == data_size)
                        data = data[:data_size]
            self._data = data
        return self._data

    def parse_value(self):
        data = self.data

        if self.kv.data_type in (REG_DWORD, REG_DWORD_BIG_ENDIAN):
            if len(data) == 0:
                return 0

            if self.kv.data_type == REG_DWORD:
                return c_regf.uint32(data[:4])
            elif self.kv.data_type == REG_DWORD_BIG_ENDIAN:
                return struct.unpack(">I", data[:4])[0]

        if self.kv.data_type in (REG_SZ, REG_EXPAND_SZ):
            return try_decode_sz(data)

        if self.kv.data_type in (REG_BINARY, REG_NONE):
            return data

        if self.kv.data_type == REG_MULTI_SZ:
            data_len = len(data)
            data = BytesIO(data)

            multi_string = []
            while data.tell() < data_len:
                string = read_null_terminated_wstring(data)
                if string == "":
                    break

                multi_string.append(string)

            return multi_string

        if self.kv.data_type == REG_QWORD:
            return c_regf.uint64(data) if len(data) else 0

        if self.kv.data_type == REG_FULL_RESOURCE_DESCRIPTOR:
            log.warning("Unimplemented REG_FULL_RESOURCE_DESCRIPTOR")
            return data

        if self.kv.data_type == REG_RESOURCE_REQUIREMENTS_LIST:
            log.warning("Unimplemented REG_RESOURCE_REQUIREMENTS_LIST")
            return data

        log.warning("Data type 0x%x not supported", self.kv.data_type)
        return data

    @property
    def value(self):
        if self._value is None:
            self._value = self.parse_value()
        return self._value

    def __repr__(self):
        return f"<KeyValue {self.name}={self.value!r}>"


class ValueList:
    def __init__(self, hive, data, count):
        self.hive = hive
        self._values = c_regf.int32[count](data)

    def __iter__(self):
        for entry in self._values:
            if entry <= 2:
                continue

            yield KeyValue(self.hive, self.hive.read_cell_data(entry))


class IndexRoot:
    def __init__(self, hive, data):
        self.hive = hive
        self.ir = c_regf.INDEX_ROOT(data)

    def __iter__(self):
        for entry in self.ir.entries:
            for e in self.hive.cell(entry):
                yield e

    @property
    def num_elements(self):
        return self.ir.num_elements

    def subkey(self, name):
        for entry in self.ir.entries:
            sk = self.hive.cell(entry).subkey(name)
            if sk:
                return sk


class IndexLeaf:
    def __init__(self, hive, data):
        self.hive = hive
        self.il = c_regf.INDEX_LEAF(data)

    def __iter__(self):
        for entry in self.il.entries:
            yield self.hive.cell(entry)

    @property
    def num_elements(self):
        return self.il.num_elements

    def subkey(self, name):
        for entry in self.il.entries:
            sk = self.hive.cell(entry)
            if name == sk.name:
                return sk


class HashLeaf:
    def __init__(self, hive, data):
        self.hive = hive
        self.hl = c_regf.HASH_LEAF(data)

    def __iter__(self):
        for entry in self.hl.entries:
            yield self.hive.cell(entry.key_node_offset)

    @property
    def num_elements(self):
        return self.hl.num_elements

    def subkey(self, name):
        name_hash = hashname(name)
        for entry in self.hl.entries:
            if name_hash == entry.name_hash:
                sk = self.hive.cell(entry.key_node_offset)
                if sk.name.lower() == name.lower():
                    return sk

        return None


class FastLeaf:
    def __init__(self, hive, d):
        self.hive = hive
        self.fl = c_regf.FAST_LEAF(d)

    def __iter__(self):
        for entry in self.fl.entries:
            yield self.hive.cell(entry.key_node_offset)

    @property
    def num_elements(self):
        return self.fl.num_elements

    def subkey(self, name):
        name_hint = name[:4].lower()

        for entry in self.fl.entries:
            # If names are < 4 characters, the name hint is padded with
            # 0-bytes, the characters are stored from the lowest byte number
            # up.
            # Note that names of keys are only supposed to contain "printable
            # characters except the `\' character", which probably is the
            # printable subset of ascii (MS documentation is inconclusive on
            # this).
            if name_hint == entry.name_hint.rstrip(b"\x00").decode("ascii").lower():
                sk = self.hive.cell(entry.key_node_offset)
                if sk.name.lower() == name.lower():
                    return sk

        return None


def decode_name(blob, size, is_comp_name):
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


def try_decode_sz(data):
    if not len(data):
        return ""

    try:
        if (isascii(data) or data.endswith(b"\x00")) and data[1:2] != b"\x00":
            # This will return the string latin1 decoded up until the first
            # NULL byte.
            return data.split(b"\x00")[0].decode("latin1")

        if len(data) % 2 != 0:
            data = data.ljust(len(data) + 1, b"\x00")

        # This will return the string utf-16-le decoded up until the first
        # double NULL byte.
        return data.split(b"\x00\x00")[0].decode("utf-16-le")

    except UnicodeDecodeError:
        # Last ditch effort, decode the whole bytestring as if it were utf-16,
        # any decoding errors, which incase of utf-16 will be invalid utf-16
        # surrogates, will be ignored.
        return data.decode("utf-16-le", "ignore").strip("\x00")


def read_null_terminated_wstring(stream, encoding="utf-16-le"):
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


def isascii(byte_string):
    if PY37:
        return byte_string.isascii()
    else:
        return all(byte <= 127 for byte in byte_string)


def hashname(name):
    # Note that `name' is a python str(), which means the ord() used to
    # calculate name_hash works (it wouldn't for byte()).
    # Also note that names of keys are only supposed to contain "printable
    # characters except the `\' character", which probably is the printable
    # subset of ascii (MS documentation is inconclusive on this).
    name_hash = 0
    for char in name.upper():
        name_hash = (name_hash * 37 + ord(char)) & 0xFFFFFFFF

    return name_hash


def xor32_crc(data):
    crc = 0
    for ii in c_regf.uint32[len(data) // 4](data):
        crc ^= ii

    return crc
