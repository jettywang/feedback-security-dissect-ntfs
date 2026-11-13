"""Low-level builders for synthetic but on-disk-accurate NTFS structures.

Everything here is serialized with the same ``dissect.ntfs.c_ntfs`` cstruct
definitions that the library uses for parsing real evidence, so the produced
bytes are read back through the genuine dissect.ntfs parser rather than a
parallel hand-written decoder.

All timestamps are carried as raw Windows FILETIME ticks: the number of
100-nanosecond intervals since 1601-01-01 00:00:00 UTC. They are *never*
rounded to seconds/microseconds inside this module.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_TYPE_CODE,
    FILE_NAME_NTFS,
    FILE_RECORD_SEGMENT_IN_USE,
    c_ntfs,
)

RECORD_SIZE = 1024
SECTOR_SIZE = 512
# A deliberately fixed, non-zero update sequence number so fixup handling is
# exercised instead of silently passing on all-zero slack space.
FIXUP_SIGNATURE = 0xBEEF
EPOCH_1601_TO_1970_NS = 11644473600000000000


def filetime(year: int, month: int, day: int, hour: int = 0, minute: int = 0,
             second: int = 0, ticks100: int = 0) -> int:
    """Build a raw FILETIME tick value from UTC wall-clock components.

    ``ticks100`` adds sub-second 100ns units (0..9_999_999). The value is
    computed through the dissect helper's inverse so the two stay consistent.
    """
    import datetime as _dt

    epoch_ns = int(_dt.datetime(year, month, day, hour, minute, second,
                                tzinfo=_dt.timezone.utc).timestamp() * 1_000_000_000)
    ns = epoch_ns + ticks100 * 100
    # ts_to_ns(ticks) = ticks * 100 - EPOCH_NS  => invert it.
    return (ns + EPOCH_1601_TO_1970_NS) // 100


def add_ticks(ticks: int, *, seconds: int = 0, ms: int = 0, us: int = 0,
              hundred_ns: int = 0) -> int:
    """Return a new FILETIME offset by a precise 100ns-granular delta."""
    return ticks + seconds * 10_000_000 + ms * 10_000 + us * 10 + hundred_ns


def ticks_to_iso(ticks: int) -> str:
    """Render a tick value without dropping the 100ns tail.

    The trailing seven digits are the 100ns fraction. This formatting is for
    human display only; comparisons always use the integer tick value.
    """
    import datetime as _dt

    from dissect.ntfs.util import ts_to_ns

    ns = ts_to_ns(ticks)
    base, frac = divmod(ns, 1_000_000_000)
    dt = _dt.datetime.fromtimestamp(base, tz=_dt.timezone.utc)
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{frac:09d}Z"


def make_file_ref(segment: int, sequence: int) -> c_ntfs._MFT_SEGMENT_REFERENCE:
    ref = c_ntfs.MFT_SEGMENT_REFERENCE()
    ref.SegmentNumberLowPart = segment & 0xFFFFFFFF
    ref.SegmentNumberHighPart = (segment >> 32) & 0xFFFF
    ref.SequenceNumber = sequence
    return ref


def _resident_attribute(type_code: ATTRIBUTE_TYPE_CODE, instance: int,
                        value: bytes) -> bytes:
    header = c_ntfs._ATTRIBUTE_RECORD_HEADER()
    header.TypeCode = type_code
    header.FormCode = 0
    header.NameLength = 0
    header.NameOffset = 0
    header.Flags = 0
    header.Instance = instance
    # Resident form: 16 bytes common header + 8 bytes resident union, value
    # begins at offset 24. Record length is 8-byte aligned.
    header.Form.Resident.ValueLength = len(value)
    header.Form.Resident.ValueOffset = 24
    header.Form.Resident.Flags = 0
    header.Form.Resident.Reserved = 0
    total = (24 + len(value) + 7) & ~7
    header.RecordLength = total
    head = header.dumps()[:24]
    return head + value + b"\x00" * (total - 24 - len(value))


def standard_information(creation: int, modification: int, change: int,
                         access: int, file_attributes: int = 0x20,
                         usn: int = 0) -> bytes:
    si = c_ntfs._STANDARD_INFORMATION()
    si.CreationTime = creation
    si.LastModificationTime = modification
    si.LastChangeTime = change
    si.LastAccessTime = access
    si.FileAttributes = file_attributes
    si.MaximumVersions = 0
    si.VersionNumber = 0
    si.ClassId = 0
    si.OwnerId = 0
    si.SecurityId = 0
    si.QuotaCharged = 0
    si.Usn = usn
    return _resident_attribute(ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION, 0, si.dumps())


def file_name(parent_segment: int, parent_sequence: int, name: str,
              creation: int, modification: int, change: int, access: int,
              *, allocated_length: int = 4096, file_size: int = 16,
              file_attributes: int = 0x20, flags: int = FILE_NAME_NTFS,
              is_directory: bool = False) -> bytes:
    fn = c_ntfs._FILE_NAME()
    fn.ParentDirectory = make_file_ref(parent_segment, parent_sequence)
    fn.CreationTime = creation
    fn.LastModificationTime = modification
    fn.LastChangeTime = change
    fn.LastAccessTime = access
    fn.AllocatedLength = allocated_length
    fn.FileSize = file_size
    attrs = file_attributes
    if is_directory:
        attrs |= c_ntfs.FILE_NAME_INDEX_PRESENT
    fn.FileAttributes = attrs
    fn.ReparsePointTag = 0
    encoded = name.encode("utf-16-le")
    fn.FileNameLength = len(encoded) // 2
    fn.Flags = flags
    fn.FileName = name
    return _resident_attribute(ATTRIBUTE_TYPE_CODE.FILE_NAME, 1, fn.dumps())


def build_file_record(segment: int, sequence: int, reference_count: int,
                      is_directory: bool, attributes: list[bytes]) -> bytes:
    """Assemble one 1024-byte FILE record with a valid multi-sector fixup."""
    usa_offset = 0x30
    first_attribute_offset = 0x38
    end_marker = struct.pack("<I", 0xFFFFFFFF)
    body = b"".join(attributes) + end_marker

    header = c_ntfs._FILE_RECORD_SEGMENT_HEADER()
    header.MultiSectorHeader.Signature = b"FILE"
    header.MultiSectorHeader.UpdateSequenceArrayOffset = usa_offset
    # One common USN + one saved word per 512-byte sector (2 sectors here).
    header.MultiSectorHeader.UpdateSequenceArraySize = 4
    header.Lsn = 0
    header.SequenceNumber = sequence
    header.ReferenceCount = reference_count
    header.FirstAttributeOffset = first_attribute_offset
    header.Flags = FILE_RECORD_SEGMENT_IN_USE | (0x2 if is_directory else 0)
    header.BytesInUse = first_attribute_offset + len(body)
    header.BytesAllocated = RECORD_SIZE
    header.BaseFileRecordSegment = c_ntfs.FILE_REFERENCE()
    header.NextAttributeInstance = len(attributes) + 1

    record = bytearray(RECORD_SIZE)
    head = header.dumps()
    record[0:len(head)] = head
    record[first_attribute_offset:first_attribute_offset + len(body)] = body

    sector_count = RECORD_SIZE // SECTOR_SIZE
    for index in range(sector_count):
        end = SECTOR_SIZE * (index + 1) - 2
        saved = bytes(record[end:end + 2])
        record[usa_offset + 2 + 2 * index:usa_offset + 4 + 2 * index] = saved
        record[end:end + 2] = struct.pack("<H", FIXUP_SIGNATURE)
    record[usa_offset:usa_offset + 2] = struct.pack("<H", FIXUP_SIGNATURE)
    return bytes(record)


@dataclass
class UsnEvent:
    usn: int
    timestamp: int
    reason: int
    segment: int
    sequence: int
    parent_segment: int
    parent_sequence: int
    name: str
    file_attributes: int = 0x20


def usn_record_v2(event: UsnEvent) -> bytes:
    name_bytes = event.name.encode("utf-16-le")
    base_length = 60
    record_length = (base_length + len(name_bytes) + 7) & ~7

    record = c_ntfs.USN_RECORD_V2()
    record.RecordLength = record_length
    record.MajorVersion = 2
    record.MinorVersion = 0
    record.FileReferenceNumber = make_file_ref(event.segment, event.sequence)
    record.ParentFileReferenceNumber = make_file_ref(
        event.parent_segment, event.parent_sequence)
    record.Usn = event.usn
    record.TimeStamp = event.timestamp
    record.Reason = c_ntfs.USN_REASON(event.reason)
    record.SourceInfo = c_ntfs.USN_SOURCE(0)
    record.SecurityId = 0
    record.FileAttributes = c_ntfs.FILE_ATTRIBUTE(event.file_attributes)
    record.FileNameLength = len(name_bytes)
    record.FileNameOffset = base_length
    padding = record_length - base_length - len(name_bytes)
    return record.dumps()[:base_length] + name_bytes + b"\x00" * padding
