from __future__ import annotations


class Error(Exception):
    pass


class RegistryKeyNotFoundError(Error):
    pass


class RegistryValueNotFoundError(Error):
    pass
