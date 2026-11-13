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


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotAReparsePointError(Error):
    pass


class StreamVerificationError(BrokenMftError):
    """Raised when a non-resident stream cannot be assembled into a verified, complete stream.

    This is raised in strict mode (``strict=True``) when verification of the
    ``$ATTRIBUTE_LIST`` references and VCN chain of a multi-record stream fails, for example
    because a fragment is missing (an evidence gap), fragments overlap, an extension record has
    been reused (sequence number mismatch) or a fragment does not belong to the base record.
    """


class VolumeNotAvailableError(Error):
    pass
