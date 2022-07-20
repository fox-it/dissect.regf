class Error(Exception):
    pass


class RegistryKeyNotFoundError(Error):
    pass


class RegistryValueNotFoundError(Error):
    pass
