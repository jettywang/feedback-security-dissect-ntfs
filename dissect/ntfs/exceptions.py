from __future__ import annotations


class Error(Exception):
    pass


class BrokenIndexError(Error):
    pass


class BrokenMftError(Error):
    pass


class FilenameNotAvailableError(Error):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class MftNotAvailableError(Error):
    pass


class SecurityDescriptorError(Error):
    """Base class for security descriptor evidence errors.

    Args:
        message: The error message.
        evidence: Optional :class:`~dissect.ntfs.secure.SecurityDescriptorEvidence` describing the copies
            that were inspected.
    """

    def __init__(self, message: str, evidence: object = None):
        super().__init__(message)
        self.evidence = evidence


class SecurityDescriptorConflictError(SecurityDescriptorError, KeyError):
    """Raised when multiple distinct descriptor contents exist for the same security ID."""


class SecurityDescriptorCorruptionError(SecurityDescriptorError, KeyError):
    """Raised when no complete, verified descriptor copy can be selected."""


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotAReparsePointError(Error):
    pass


class VolumeNotAvailableError(Error):
    pass
