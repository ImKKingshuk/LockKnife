class LockKnifeError(Exception):
    """Base exception for all LockKnife errors."""

    def __init__(self, message: str, error_code: str | None = None) -> None:
        super().__init__(message)
        self.error_code = error_code


class ConfigError(LockKnifeError):
    """Configuration-related errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="LK-0001")


class ExternalToolError(LockKnifeError):
    """External tool dependency errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="LK-0002")


class DeviceError(LockKnifeError):
    """Device communication and ADB errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="LK-1001")


class ForensicsError(LockKnifeError):
    """Forensic analysis errors (snapshot, timeline, correlation)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="LK-3001")


class ExtractionError(LockKnifeError):
    """Data extraction errors (SMS, contacts, browser, location)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="LK-2001")


class ExploitError(LockKnifeError):
    """Exploitation framework errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="LK-4001")


class RuntimeInstrumentationError(LockKnifeError):
    """Frida/runtime instrumentation errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="LK-5001")


class IntelligenceError(LockKnifeError):
    """CVE intel, OSV.dev, intelligence gathering errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="LK-6001")


class ReportingError(LockKnifeError):
    """Report generation errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="LK-7001")
