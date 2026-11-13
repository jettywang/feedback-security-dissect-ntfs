from __future__ import annotations

from dataclasses import dataclass
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
    from dissect.ntfs.rename import RenameTrace


@dataclass(frozen=True, slots=True)
class UsnJournalGap:
    """A span of missing journal pages between two parsed USN records.

    Args:
        start_offset: The journal offset where the missing span starts.
        end_offset: The journal offset of the next parsed record.
    """

    start_offset: int
    end_offset: int

    @property
    def size(self) -> int:
        """Return the size of the missing span in bytes."""
        return self.end_offset - self.start_offset

    def __str__(self) -> str:
        return f"<UsnJournalGap {self.start_offset:#x}-{self.end_offset:#x}>"


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
        """Yield all parsed USN records.

        Only yields version 2 USN records, other record versions are ignored.

        This iterator does not expose missing journal pages. Use :meth:`events` when the offsets of missing pages
        are relevant, for example when correlating rename events across the journal.
        """
        for event in self.events():
            if isinstance(event, UsnRecord):
                yield event

    def rename_traces(self, *, max_pending: int = 256) -> Iterator[RenameTrace]:
        """Yield correlated rename traces from this journal.

        This is a convenience wrapper around :func:`~dissect.ntfs.rename.track_renames` and
        :meth:`events`. The returned traces retain the original :class:`UsnRecord` objects.

        Args:
            max_pending: The maximum number of pending ``RENAME_OLD_NAME`` records to retain.
        """
        from dissect.ntfs.rename import track_renames

        return track_renames(self.events(), max_pending=max_pending)

    def events(self) -> Iterator[UsnRecord | UsnJournalGap]:
        """Yield USN records and the missing journal spans between them.

        Only yields version 2 USN records, other record versions are ignored. A :class:`UsnJournalGap` is yielded
        for each run of empty (all zero) journal pages that lies between parsed records. Empty pages before the first
        record (pre-allocated space) and after the last record are not gaps.

        A gap means that records may be missing from the journal. Consumers that correlate events across records
        must not treat an event before a gap as conclusive with respect to an event after the gap.
        """
        fh = self.fh
        offset = 0

        if isinstance(fh, RunlistStream):
            for run_offset, run_size in fh.runlist:
                if run_offset is not None:
                    break

                offset += run_size * fh.block_size

        gap_start = None
        seen_record = False

        while True:
            fh.seek(offset)
            header = fh.read(4)

            if not header:
                # End of the journal. Empty pages at the tail are unused pre-allocated space, not a gap.
                break

            if header == b"\x00" * 4:
                if offset % USN_PAGE_SIZE:
                    # Zero padding at the end of a page, not a missing page.
                    offset += USN_PAGE_SIZE - (offset % USN_PAGE_SIZE)
                    continue

                # An empty page at a page boundary between records means journal records are missing.
                if seen_record and gap_start is None:
                    gap_start = offset
                offset += USN_PAGE_SIZE
                continue

            if gap_start is not None:
                yield UsnJournalGap(gap_start, offset)
                gap_start = None

            try:
                record = UsnRecord(self, fh, offset)
            except EOFError:
                break

            seen_record = True
            if record.header.MajorVersion == 2:
                yield record

            offset += record.record.RecordLength
            if offset % 8:
                offset += -(offset) & (8 - 1)


class UsnRecord:
    """Parse a USN record from a file-like object and offset.

    Args:
        usnjrnl: The :class:`UsnJrnl` class this record is parsed from.
        fh: The file-like object to parse a USN record from.
        offset: The offset to parse a USN record at.
    """

    def __init__(self, usnjrnl: UsnJrnl, fh: BinaryIO, offset: int):
        self.usnjrnl = usnjrnl
        self.offset = offset
        self.extents = []

        fh.seek(offset)
        self.header = c_ntfs.USN_RECORD_COMMON_HEADER(fh)

        fh.seek(offset)
        if self.header.MajorVersion == 2:
            self.record = c_ntfs.USN_RECORD_V2(fh)
        elif self.header.MajorVersion == 3:
            self.record = c_ntfs.USN_RECORD_V3(fh)
        elif self.header.MajorVersion == 4:
            self.record = c_ntfs.USN_RECORD_V4(fh)
            for _ in range(self.record.NumberOfExtents):
                self.extents.append(c_ntfs.USN_RECORD_EXTENT(fh))
        else:
            raise ValueError(f"Unsupported USN_RECORD version: {self.header.MajorVersion}")

        if self.header.MajorVersion in (2, 3):
            fh.seek(offset + self.record.FileNameOffset)
            self.filename = fh.read(self.record.FileNameLength).decode("utf-16-le")
        else:
            self.filename = None

    def __repr__(self) -> str:
        return f"<UsnRecord {self.record.Usn}>"

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.record, attr)

    @cached_property
    def file(self) -> MftRecord | None:
        if self.usnjrnl.ntfs and self.usnjrnl.ntfs.mft:
            return self.usnjrnl.ntfs.mft(self.record.FileReferenceNumber)
        return None

    @cached_property
    def parent(self) -> MftRecord | None:
        if self.usnjrnl.ntfs and self.usnjrnl.ntfs.mft:
            return self.usnjrnl.ntfs.mft(self.record.ParentFileReferenceNumber)
        return None

    @property
    def timestamp(self) -> datetime:
        return wintimestamp(self.record.TimeStamp)

    @property
    def timestamp_ns(self) -> int:
        return ts_to_ns(self.record.TimeStamp)

    @cached_property
    def full_path(self) -> str:
        try:
            parent = self.parent
        except Error:
            parent = None

        ref = segment_reference(self.record.ParentFileReferenceNumber)
        if parent is None:
            parent_path = f"<unavailable_reference_0x{ref:x}#{self.record.ParentFileReferenceNumber.SequenceNumber}>"
        elif parent.header.SequenceNumber == self.record.ParentFileReferenceNumber.SequenceNumber:
            parent_path = parent.full_path()
        else:
            parent_path = f"<broken_reference_0x{ref:x}#{self.record.ParentFileReferenceNumber.SequenceNumber}>"

        return f"{parent_path}\\{self.filename}"
