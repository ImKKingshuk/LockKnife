class LockKnifeError(Exception):
    pass


class ConfigError(LockKnifeError):
    pass


class ExternalToolError(LockKnifeError):
    pass


class DeviceError(LockKnifeError):
    pass

