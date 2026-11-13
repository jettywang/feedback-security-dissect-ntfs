from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.util.stream import RunlistStream
from dissect.util.ts import wintimestamp

from dissect.ntfs.c_ntfs import USN_PAGE_SIZE, c_ntfs
from dissect.ntfs.exceptions import Error
from dissect.ntfs.util import segment_reference, ts_to_ns

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from dissect.ntfs.mft import MftRecord
    from dissect.ntfs.ntfs import NTFS

# A FILE_ID_128 stores the 6 byte MFT segment number and 2 byte sequence number
# in its low 8 bytes; the upper 8 bytes are a volume/non-MFT identifier and
# must be preserved instead of being truncated away.
MFT_SEGMENT_MASK = 0x0000FFFFFFFFFFFF
FILE_ID_SEQUENCE_SHIFT = 48
# Records are 8 byte aligned within a USN page.
USN_RECORD_ALIGNMENT = 8


class UsnJrnl:
    """Parse the USN journal from a file-like object of the ``$UsnJrnl:$J`` stream.

    Args:
        fh: A file-like object of the $UsnJrnl:$J stream.
        ntfs: An optional :class:`~dissect.ntfs.ntfs.NTFS` class instance, used for resolving file paths.
    """

    def __init__(self, fh: BinaryIO, ntfs: NTFS | None = None):
        self.fh = fh
        self.ntfs = ntfs

    def records(self) -> Iterator[UsnRecord]:
        """Yield all parsable USN records (major versions 2, 3 and 4).

        Version specific fields are kept on the yielded :class:`UsnRecord` instead of being
        normalized into a single filename event: version 3/4 records carry 128 bit file
        references and version 4 records carry extents and no filename.

        Iteration advances by each record's ``RecordLength``. Zero filled pages, unknown
        record versions and records with a corrupt or truncated length never cause an
        infinite loop or consume a following valid record: the remainder of the current
        USN page is skipped and parsing resumes at the next page boundary. A truncated
        final record (including a truncated version 4 extent) is not yielded.
        """
        fh = self.fh
        offset = self._initial_offset()
        page_end = USN_PAGE_SIZE

        while True:
            if offset >= page_end:
                page_end = offset + USN_PAGE_SIZE - (offset % USN_PAGE_SIZE)

            fh.seek(offset)
            if fh.read(4) == b"\x00" * 4:
                # The remainder of the page is zero filled, continue at the next page.
                offset = page_end
                continue

            try:
                record = UsnRecord(self, fh, offset)
            except EOFError:
                # No complete record (or extent) remains in the stream.
                break
            except ValueError:
                # Unknown version, bad filename encoding or another malformed record.
                # Only the common header is trusted: a usable RecordLength lets us skip
                # just this entry, otherwise the remainder of the page is skipped so a
                # later page can still produce valid events.
                record_length = self._recover_record_length(fh, offset, page_end)
                if record_length is None:
                    offset = page_end
                    continue
                offset += record_length
                if offset % USN_RECORD_ALIGNMENT:
                    offset += -(offset) & (USN_RECORD_ALIGNMENT - 1)
                continue

            record_length = record.record.RecordLength
            if not self._valid_record_length(offset, record_length, page_end, record.header.MajorVersion, record):
                offset = page_end
                continue

            yield record
            offset += record_length
            if offset % USN_RECORD_ALIGNMENT:
                offset += -(offset) & (USN_RECORD_ALIGNMENT - 1)

    def _initial_offset(self) -> int:
        """Return the offset of the first potentially allocated run in a sparse journal."""
        fh = self.fh
        offset = 0

        if isinstance(fh, RunlistStream):
            for run_offset, run_size in fh.runlist:
                if run_offset is not None:
                    break

                offset += run_size * fh.block_size

        return offset

    @staticmethod
    def _recover_record_length(fh: BinaryIO, offset: int, page_end: int) -> int | None:
        """Read a bare ``RecordLength`` from a record that failed to parse.

        Returns the length when it is aligned, covers the common header and stays within
        the current USN page, otherwise ``None``. This keeps unknown versions skippable
        without ever looping or walking past the page boundary.
        """
        fh.seek(offset)
        record_length = int.from_bytes(fh.read(4), "little")

        if record_length < c_ntfs.USN_RECORD_COMMON_HEADER.size:
            return None
        if record_length % USN_RECORD_ALIGNMENT:
            return None
        if offset + record_length > page_end:
            return None
        return record_length

    @staticmethod
    def _valid_record_length(
        offset: int,
        record_length: int,
        page_end: int,
        major_version: int,
        record: UsnRecord,
    ) -> bool:
        """Validate ``RecordLength`` so iteration always makes forward progress.

        A length of zero would loop forever, a non-aligned length is not produced by NTFS,
        records cannot cross a USN page boundary and the length must cover the full
        version specific body (including every declared version 4 extent).
        """
        if record_length < c_ntfs.USN_RECORD_COMMON_HEADER.size:
            return False
        if record_length % USN_RECORD_ALIGNMENT:
            return False
        if offset + record_length > page_end:
            return False

        if major_version == 2:
            minimum_length = c_ntfs.USN_RECORD_V2.size
        elif major_version == 3:
            minimum_length = c_ntfs.USN_RECORD_V3.size
        elif major_version == 4:
            minimum_length = c_ntfs.USN_RECORD_V4.size + (
                record.record.NumberOfExtents * c_ntfs.USN_RECORD_EXTENT.size
            )
        else:
            # Unknown versions cannot be length validated beyond the common header.
            return True

        return record_length >= minimum_length


class UsnRecord:
    """Parse a USN record from a file-like object and offset.

    Version 2, 3 and 4 records are supported. The version specific cstruct remains
    available as :attr:`record` and common fields are proxied through this class.
    Version 4 records expose their extents through :attr:`extents`.

    Args:
        usnjrnl: The :class:`UsnJrnl` class this record is parsed from.
        fh: The file-like object to parse a USN record from.
        offset: The offset to parse a USN record at.

    Raises:
        EOFError: If the record (or a version 4 extent) is truncated by the end of the stream.
        ValueError: If the record version is unknown.
    """

    def __init__(self, usnjrnl: UsnJrnl, fh: BinaryIO, offset: int):
        self.usnjrnl = usnjrnl
        self.offset = offset
        self.extents = []

        fh.seek(offset)
        self.header = c_ntfs.USN_RECORD_COMMON_HEADER(fh)
        self.major_version = self.header.MajorVersion
        self.minor_version = self.header.MinorVersion

        fh.seek(offset)
        if self.major_version == 2:
            self.record = c_ntfs.USN_RECORD_V2(fh)
        elif self.major_version == 3:
            self.record = c_ntfs.USN_RECORD_V3(fh)
        elif self.major_version == 4:
            self.record = c_ntfs.USN_RECORD_V4(fh)
            # A short read here raises EOFError so a truncated record is never presented
            # as a complete, fully evidenced, event.
            for _ in range(self.record.NumberOfExtents):
                self.extents.append(c_ntfs.USN_RECORD_EXTENT(fh))
        else:
            raise ValueError(f"Unsupported USN_RECORD version: {self.major_version}")

        if self.major_version in (2, 3):
            fh.seek(offset + self.record.FileNameOffset)
            self.filename = fh.read(self.record.FileNameLength).decode("utf-16-le")
        else:
            # Version 4 records describe range changes and have no filename.
            self.filename = None

    def __repr__(self) -> str:
        return f"<UsnRecord v{self.major_version} {self.record.Usn}>"

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.record, attr)

    @property
    def file_reference(self) -> int:
        """Return the full file reference without truncating 128 bit references.

        Version 2 references are returned as the full 64 bit packed value
        (48 bit segment number + 16 bit sequence number). Version 3/4 references
        are returned as the full 128 bit ``FILE_ID_128`` value.
        """
        return self._reference(self.record.FileReferenceNumber)

    @property
    def parent_reference(self) -> int:
        """Return the full parent file reference, see :attr:`file_reference`."""
        return self._reference(self.record.ParentFileReferenceNumber)

    def _reference(self, reference: Any) -> int:
        if self.major_version == 2:
            return segment_reference(reference) | (reference.SequenceNumber << FILE_ID_SEQUENCE_SHIFT)
        return int.from_bytes(reference.Identifier, "little")

    @property
    def segment_number(self) -> int:
        """Return the 48 bit MFT segment number of :attr:`file_reference`."""
        return self.file_reference & MFT_SEGMENT_MASK

    @property
    def parent_segment_number(self) -> int:
        """Return the 48 bit MFT segment number of :attr:`parent_reference`."""
        return self.parent_reference & MFT_SEGMENT_MASK

    @property
    def sequence_number(self) -> int:
        """Return the 16 bit sequence number embedded in :attr:`file_reference`."""
        if self.major_version == 2:
            return self.record.FileReferenceNumber.SequenceNumber
        return (self.file_reference >> FILE_ID_SEQUENCE_SHIFT) & 0xFFFF

    @property
    def parent_sequence_number(self) -> int:
        """Return the 16 bit sequence number embedded in :attr:`parent_reference`."""
        if self.major_version == 2:
            return self.record.ParentFileReferenceNumber.SequenceNumber
        return (self.parent_reference >> FILE_ID_SEQUENCE_SHIFT) & 0xFFFF

    @property
    def remaining_extents(self) -> int | None:
        """Return the number of extents carried in following version 4 records.

        Returns ``None`` for non version 4 records. A non-zero value means this is a
        partial event: additional extents for the same file reference and USN follow
        in subsequent records.
        """
        if self.major_version != 4:
            return None
        return self.record.RemainingExtents

    @property
    def has_remaining_extents(self) -> bool:
        """Return whether this version 4 record is continued by later extent records."""
        return self.major_version == 4 and self.record.RemainingExtents > 0

    @cached_property
    def file(self) -> MftRecord | None:
        if self.usnjrnl.ntfs and self.usnjrnl.ntfs.mft:
            return self.usnjrnl.ntfs.mft(self.segment_number)
        return None

    @cached_property
    def parent(self) -> MftRecord | None:
        if self.usnjrnl.ntfs and self.usnjrnl.ntfs.mft:
            return self.usnjrnl.ntfs.mft(self.parent_segment_number)
        return None

    @property
    def timestamp(self) -> datetime | None:
        if self.major_version == 4:
            # Version 4 range records do not carry a timestamp.
            return None
        return wintimestamp(self.record.TimeStamp)

    @property
    def timestamp_ns(self) -> int | None:
        if self.major_version == 4:
            return None
        return ts_to_ns(self.record.TimeStamp)

    @cached_property
    def full_path(self) -> str:
        if self.major_version == 4:
            return f"<unavailable_filename_reference_0x{self.file_reference:x}>"

        try:
            parent = self.parent
        except Error:
            parent = None

        ref = self.parent_segment_number
        sequence = self.parent_sequence_number
        if parent is None:
            parent_path = f"<unavailable_reference_0x{ref:x}#{sequence}>"
        elif parent.header.SequenceNumber == sequence:
            parent_path = parent.full_path()
        else:
            parent_path = f"<broken_reference_0x{ref:x}#{sequence}>"

        return f"{parent_path}\\{self.filename}"
