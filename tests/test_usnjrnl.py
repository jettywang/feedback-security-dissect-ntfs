from __future__ import annotations

from io import BytesIO

import pytest

from dissect.ntfs.c_ntfs import USN_PAGE_SIZE, c_ntfs
from dissect.ntfs.usnjrnl import UsnJrnl, UsnRecord


def test_usnjrnl_record_v4() -> None:
    data = bytes.fromhex(
        "5000000004000000c1000000000001000000000000000000bf00000000000100"
        "0000000000000000d00201000000000003810080000000000000000001001000"
        "00000000000000000040280000000000"
    )
    record = UsnRecord(None, BytesIO(data), 0)
    assert record.major_version == 4
    assert record.filename is None
    assert record.timestamp is None
    assert record.timestamp_ns is None
    assert len(record.extents) == 1
    assert record.extents[0].Offset == 0
    assert record.extents[0].Length == 0x284000
    assert record.remaining_extents == 0
    assert record.has_remaining_extents is False


def test_usnjrnl_record_v2() -> None:
    data = bytes.fromhex(
        "5800000002000000c100000000000100bf000000000001002003010000000000"
        "6252641a86a4d7010381008000000000000000002000000018003c0069007300"
        "2d00310035005000320036002e0074006d00700000000000"
    )
    record = UsnRecord(None, BytesIO(data), 0)
    assert record.major_version == 2
    assert record.filename == "is-15P26.tmp"
    assert str(record.timestamp) == "2021-09-08 07:49:50.607420+00:00"
    # The full 64 bit reference (segment + sequence) is preserved.
    assert record.file_reference == 0x00010000000000C1
    assert record.segment_number == 0xC1
    assert record.sequence_number == 1
    assert record.remaining_extents is None


def aligned_length(length: int) -> int:
    return length + (-length % 8)


def v2_record(usn: int, segment: int, sequence: int, parent_segment: int, filename: str) -> bytes:
    name = filename.encode("utf-16-le")
    record_length = aligned_length(c_ntfs.USN_RECORD_V2.size + len(name))
    record = c_ntfs.USN_RECORD_V2(
        RecordLength=record_length,
        MajorVersion=2,
        MinorVersion=0,
        FileReferenceNumber=c_ntfs.MFT_SEGMENT_REFERENCE(
            SegmentNumberLowPart=segment & 0xFFFFFFFF,
            SegmentNumberHighPart=(segment >> 32) & 0xFFFF,
            SequenceNumber=sequence,
        ),
        ParentFileReferenceNumber=c_ntfs.MFT_SEGMENT_REFERENCE(
            SegmentNumberLowPart=parent_segment & 0xFFFFFFFF,
            SegmentNumberHighPart=(parent_segment >> 32) & 0xFFFF,
            SequenceNumber=sequence,
        ),
        Usn=usn,
        TimeStamp=132754656000000000,
        Reason=c_ntfs.USN_REASON.FILE_CREATE,
        SourceInfo=c_ntfs.USN_SOURCE.NORMAL,
        SecurityId=0,
        FileAttributes=c_ntfs.FILE_ATTRIBUTE(0x20),
        FileNameLength=len(name),
        FileNameOffset=c_ntfs.USN_RECORD_V2.size,
    )
    return record.dumps() + name + b"\x00" * (record_length - c_ntfs.USN_RECORD_V2.size - len(name))


def file_id_128(value: int) -> c_ntfs.FILE_ID_128:
    return c_ntfs.FILE_ID_128(Identifier=value.to_bytes(16, "little"))


def v3_record(usn: int, file_ref: int, parent_ref: int, filename: str) -> bytes:
    name = filename.encode("utf-16-le")
    record_length = aligned_length(c_ntfs.USN_RECORD_V3.size + len(name))
    record = c_ntfs.USN_RECORD_V3(
        RecordLength=record_length,
        MajorVersion=3,
        MinorVersion=0,
        FileReferenceNumber=file_id_128(file_ref),
        ParentFileReferenceNumber=file_id_128(parent_ref),
        Usn=usn,
        TimeStamp=132754656000000000,
        Reason=c_ntfs.USN_REASON.FILE_CREATE,
        SourceInfo=c_ntfs.USN_SOURCE.NORMAL,
        SecurityId=0,
        FileAttributes=c_ntfs.FILE_ATTRIBUTE(0x20),
        FileNameLength=len(name),
        FileNameOffset=c_ntfs.USN_RECORD_V3.size,
    )
    return record.dumps() + name + b"\x00" * (record_length - c_ntfs.USN_RECORD_V3.size - len(name))


def v4_record(usn: int, file_ref: int, parent_ref: int, extents: list[tuple[int, int]], remaining: int) -> bytes:
    record_length = aligned_length(
        c_ntfs.USN_RECORD_V4.size + len(extents) * c_ntfs.USN_RECORD_EXTENT.size
    )
    record = c_ntfs.USN_RECORD_V4(
        RecordLength=record_length,
        MajorVersion=4,
        MinorVersion=0,
        FileReferenceNumber=file_id_128(file_ref),
        ParentFileReferenceNumber=file_id_128(parent_ref),
        Usn=usn,
        Reason=c_ntfs.USN_REASON.DATA_EXTEND,
        SourceInfo=c_ntfs.USN_SOURCE.NORMAL,
        RemainingExtents=remaining,
        NumberOfExtents=len(extents),
        ExtentSize=c_ntfs.USN_RECORD_EXTENT.size,
    )
    blobs = [record.dumps()]
    blobs.extend(c_ntfs.USN_RECORD_EXTENT(Offset=offset, Length=length).dumps() for offset, length in extents)
    blobs.append(b"\x00" * (record_length - c_ntfs.USN_RECORD_V4.size - len(extents) * c_ntfs.USN_RECORD_EXTENT.size))
    return b"".join(blobs)


def test_usnjrnl_iterates_v2_v3_v4_in_order() -> None:
    v2_ref = (5 << 48) | 0x100
    v2_parent = (5 << 48) | 0x05
    v3_ref = 0x112233445566778899AABBCCDDEEFF00
    v3_parent = 0x0123456789ABCDEF0000000000000005
    v4_ref = 0xAABBCCDDEEFF00112233445566778899
    v4_parent = 0x00000000000000000000000000000005

    page = bytearray(USN_PAGE_SIZE)
    first = v2_record(0x1000, 0x100, 5, 0x05, "alpha.txt")
    second = v3_record(0x2000, v3_ref, v3_parent, "beta.txt")
    third = v4_record(0x3000, v4_ref, v4_parent, [(0x1000, 0x2000), (0x4000, 0x800)], 1)

    cursor = 0
    for blob in (first, second, third):
        page[cursor : cursor + len(blob)] = blob
        cursor += len(blob)

    journal = UsnJrnl(BytesIO(bytes(page)))
    records = list(journal.records())

    assert [record.major_version for record in records] == [2, 3, 4]
    assert [record.offset for record in records] == [0, len(first), len(first) + len(second)]
    assert [record.Usn for record in records] == [0x1000, 0x2000, 0x3000]

    v2, v3, v4 = records

    assert v2.filename == "alpha.txt"
    assert v2.file_reference == v2_ref
    assert v2.parent_reference == v2_parent
    assert v2.segment_number == 0x100
    assert v2.sequence_number == 5
    assert v2.remaining_extents is None

    # The 128 bit references must survive intact instead of being cut to 64 bits.
    assert v3.filename == "beta.txt"
    assert v3.file_reference == v3_ref
    assert v3.parent_reference == v3_parent
    assert v3.segment_number == 0xBBCCDDEEFF00
    assert v3.sequence_number == 0x99AA
    assert v3.remaining_extents is None
    assert v3.timestamp_ns is not None

    # Version 4 keeps extents and continuation state explicit instead of a filename event.
    assert v4.filename is None
    assert v4.file_reference == v4_ref
    assert v4.parent_reference == v4_parent
    assert [(extent.Offset, extent.Length) for extent in v4.extents] == [(0x1000, 0x2000), (0x4000, 0x800)]
    assert v4.remaining_extents == 1
    assert v4.has_remaining_extents is True
    assert v4.timestamp is None
    assert "unavailable_filename" in v4.full_path


def test_usnjrnl_skips_zero_filled_pages_and_continues() -> None:
    first_page = bytearray(USN_PAGE_SIZE)
    first = v2_record(0x1000, 0x100, 5, 0x05, "alpha.txt")
    first_page[: len(first)] = first

    second_page = bytearray(USN_PAGE_SIZE)
    second = v2_record(0x2000, 0x200, 6, 0x05, "beta.txt")
    second_page[: len(second)] = second

    journal = UsnJrnl(BytesIO(bytes(first_page) + b"\x00" * USN_PAGE_SIZE + bytes(second_page)))
    records = list(journal.records())

    assert [record.Usn for record in records] == [0x1000, 0x2000]
    assert [record.offset for record in records] == [0, USN_PAGE_SIZE * 2]


def test_usnjrnl_recovers_from_corrupt_record_length_on_next_page() -> None:
    corrupt = bytearray(USN_PAGE_SIZE)
    broken = v2_record(0x1000, 0x100, 5, 0x05, "broken.txt")
    # Claim a non-aligned length that cannot be used to walk the journal.
    broken = bytearray(broken)
    broken[0:4] = (7).to_bytes(4, "little")
    corrupt[: len(broken)] = broken

    healthy = bytearray(USN_PAGE_SIZE)
    good = v2_record(0x2000, 0x200, 6, 0x05, "good.txt")
    healthy[: len(good)] = good

    journal = UsnJrnl(BytesIO(bytes(corrupt) + bytes(healthy)))
    records = list(journal.records())

    assert len(records) == 1
    assert records[0].Usn == 0x2000
    assert records[0].offset == USN_PAGE_SIZE


def test_usnjrnl_zero_length_record_does_not_loop() -> None:
    page = bytearray(USN_PAGE_SIZE)
    blob = v2_record(0x1000, 0x100, 5, 0x05, "alpha.txt")
    page[: len(blob)] = blob
    page[0:4] = (0).to_bytes(4, "little")

    records = list(UsnJrnl(BytesIO(bytes(page))).records())

    assert records == []


def test_usnjrnl_unknown_version_advances_by_record_length() -> None:
    page = bytearray(USN_PAGE_SIZE)
    unknown = bytearray(32)
    unknown[0:4] = (32).to_bytes(4, "little")
    unknown[4:6] = (9).to_bytes(2, "little")
    known = v2_record(0x2000, 0x200, 6, 0x05, "known.txt")

    page[:32] = unknown
    page[32 : 32 + len(known)] = known

    records = list(UsnJrnl(BytesIO(bytes(page))).records())

    assert len(records) == 1
    assert records[0].major_version == 2
    assert records[0].offset == 32
    assert records[0].Usn == 0x2000


def test_usnjrnl_record_crossing_page_boundary_is_skipped() -> None:
    page = bytearray(USN_PAGE_SIZE)
    blob = v2_record(0x1000, 0x100, 5, 0x05, "alpha.txt")
    # Place the record so its declared length extends into the next page.
    start = USN_PAGE_SIZE - 16
    page[start : start + len(blob)] = blob[: USN_PAGE_SIZE - start]
    page[start : start + 4] = (len(blob)).to_bytes(4, "little")

    next_page = bytearray(USN_PAGE_SIZE)
    good = v2_record(0x2000, 0x200, 6, 0x05, "good.txt")
    next_page[: len(good)] = good

    records = list(UsnJrnl(BytesIO(bytes(page) + bytes(next_page))).records())

    assert len(records) == 1
    assert records[0].Usn == 0x2000
    assert records[0].offset == USN_PAGE_SIZE


def test_usnjrnl_truncated_v4_extent_is_not_evidence() -> None:
    file_ref = 0xAABBCCDDEEFF00112233445566778899
    parent_ref = 0x00000000000000000000000000000005
    complete = v4_record(0x1000, file_ref, parent_ref, [(0x0, 0x1000)], 0)
    truncated = bytearray(v4_record(0x2000, file_ref, parent_ref, [(0x2000, 0x3000)], 0))
    # Cut the final extent in half; its RecordLength still promises a full extent.
    truncated = bytes(truncated[: c_ntfs.USN_RECORD_V4.size + 8])

    journal = UsnJrnl(BytesIO(complete + truncated))
    records = list(journal.records())

    assert len(records) == 1
    record = records[0]
    assert record.Usn == 0x1000
    assert record.offset == 0
    assert len(record.extents) == 1


def test_usnjrnl_short_trailing_bytes_terminate_cleanly() -> None:
    blob = v2_record(0x1000, 0x100, 5, 0x05, "alpha.txt")

    records = list(UsnJrnl(BytesIO(blob[: c_ntfs.USN_RECORD_COMMON_HEADER.size])).records())

    assert records == []


def test_usnrecord_unknown_version_raises_value_error() -> None:
    data = bytearray(32)
    data[0:4] = (32).to_bytes(4, "little")
    data[4:6] = (9).to_bytes(2, "little")

    with pytest.raises(ValueError):
        UsnRecord(None, BytesIO(bytes(data)), 0)
