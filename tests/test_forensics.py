from __future__ import annotations

import struct
from typing import BinaryIO

import pytest

from dissect.ntfs import (
    ATTRIBUTE_TYPE_CODE,
    NTFS,
    AllocationCrossChecker,
    AllocationIssue,
    AllocationRange,
)
from dissect.ntfs.attr import Attribute
from dissect.ntfs.c_ntfs import FILE_RECORD_SEGMENT_IN_USE
from dissect.ntfs.mft import MftRecord

RECORD_SIZE = 1024


def _encode_varint(value: int, length: int) -> bytes:
    return value.to_bytes(length, "little", signed=True)


def _encode_run(run: tuple[int | None, int], previous_lcn: int) -> tuple[bytes, int]:
    lcn, count = run
    count_len = max(1, (count.bit_length() + 7) // 8)
    if lcn is None:
        header = count_len
        return bytes([header]) + _encode_varint(count, count_len), previous_lcn

    delta = lcn - previous_lcn
    offset_len = max(1, (delta.bit_length() + 7) // 8)
    header = count_len | (offset_len << 4)
    return (
        bytes([header]) + _encode_varint(count, count_len) + _encode_varint(delta, offset_len),
        lcn,
    )


def make_nonresident_attribute(
    runlist: list[tuple[int | None, int]],
    *,
    clusters: int,
    stream_name: str = "",
    flags: int = 0,
) -> Attribute:
    """Build a synthetic non-resident ``$DATA`` attribute from a runlist."""
    mapping = b""
    previous_lcn = 0
    for run in runlist:
        encoded, previous_lcn = _encode_run(run, previous_lcn)
        mapping += encoded
    mapping += b"\x00"

    name_bytes = stream_name.encode("utf-16-le")
    name_offset = 0x40 if name_bytes else 0

    # Fixed non-resident attribute layout: 16-byte generic header, 24-byte
    # non-resident head and 32-byte size fields. The mapping pairs follow any
    # optional name and are 8-byte aligned.
    fixed_header_length = 16 + 24 + 32
    mapping_offset = max(fixed_header_length, name_offset + len(name_bytes))
    mapping_offset = (mapping_offset + 7) & ~7

    header = struct.pack(
        "<IIBBHHH",
        ATTRIBUTE_TYPE_CODE.DATA,
        0,  # placeholder, patched once the full length is known
        1,  # non-resident
        len(name_bytes) // 2,
        name_offset,
        flags,
        0,  # instance
    )
    nonresident_head = struct.pack(
        "<QQHB5s",
        0,  # LowestVcn
        max(clusters - 1, 0),  # HighestVcn
        mapping_offset,  # MappingPairsOffset (USHORT)
        0,  # CompressionUnit
        b"\x00" * 5,  # Reserved[5]
    )
    nonresident_sizes = struct.pack(
        "<QQQQ",
        clusters * 4096,  # AllocatedLength
        clusters * 4096,  # FileSize
        clusters * 4096,  # ValidDataLength
        clusters * 4096,  # TotalAllocated
    )
    body = header + nonresident_head + nonresident_sizes
    body += b"\x00" * (mapping_offset - len(body))
    if name_bytes:
        body = body[:name_offset] + name_bytes + body[name_offset + len(name_bytes) :]
    body += mapping
    record_length = (len(body) + 7) & ~7
    body += b"\x00" * (record_length - len(body))
    body = bytearray(body)
    body[:8] = struct.pack("<II", ATTRIBUTE_TYPE_CODE.DATA, record_length)
    body = bytes(body)

    attribute = Attribute.from_bytes(body)
    assert attribute.dataruns() == runlist
    return attribute


def make_record(
    segment: int,
    attributes: list[Attribute],
    *,
    in_use: bool = True,
    reference_count: int = 1,
) -> MftRecord:
    """Build a synthetic MFT record (with a valid fixup array) holding attributes."""
    buffer = bytearray(RECORD_SIZE)
    first_attribute_offset = 0x38
    fixup_offset = 0x30

    struct.pack_into("<4sHH", buffer, 0, b"FILE", fixup_offset, 3)
    struct.pack_into(
        "<QHHHHIIQH",
        buffer,
        8,
        0,  # Lsn
        1,  # SequenceNumber
        reference_count,
        first_attribute_offset,
        FILE_RECORD_SEGMENT_IN_USE if in_use else 0,
        RECORD_SIZE,
        RECORD_SIZE,
        0,  # BaseFileRecordSegment (as ULONG64)
        0,  # NextAttributeInstance
    )
    # Fixup array: signature word plus one replacement per sector.
    struct.pack_into("<HHH", buffer, fixup_offset, 0x0000, buffer[510], buffer[1022])
    struct.pack_into("<H", buffer, 510, 0x0000)
    struct.pack_into("<H", buffer, 1022, 0x0000)

    offset = first_attribute_offset
    for attribute in attributes:
        raw = attribute.header.fh.getvalue()
        buffer[offset : offset + len(raw)] = raw
        offset += len(raw)
    struct.pack_into("<I", buffer, offset, ATTRIBUTE_TYPE_CODE.END)

    record = MftRecord.from_bytes(bytes(buffer))
    record.segment = segment
    return record


def make_bitmap(bit_count: int, set_clusters: set[int]) -> bytes:
    """Build an NTFS bitmap (LSB first) of exactly ``bit_count`` covered bits."""
    data = bytearray((bit_count + 7) // 8)
    for index in set_clusters:
        data[index >> 3] |= 1 << (index & 7)
    return bytes(data)


def test_consistent_allocation_has_no_conflicts() -> None:
    # One active file claiming clusters 0..3, all marked allocated.
    attribute = make_nonresident_attribute([(10, 2), (20, 2)], clusters=4)
    record = make_record(100, [attribute])
    bitmap = make_bitmap(32, {10, 11, 20, 21})

    checker = AllocationCrossChecker(
        volume_bitmap=bitmap,
        mft_bitmap=make_bitmap(256, {100}),
        total_clusters=32,
        mft_record_count=256,
    )
    checker.add_record(record)
    report = checker.check()

    assert not report.has_conflicts()
    assert report.issues() == frozenset()
    for lcn in (10, 11, 20, 21):
        audit = report.audit(lcn)
        assert audit.allocated
        assert audit.referenced
        assert audit.recoverable
        assert audit.issues == ()
    assert report.audit(0).references == frozenset()
    assert report.record(100).in_use


def test_hard_links_share_record_without_duplicate_occupation() -> None:
    # Two directory entries (hard links) point at one segment; claims must not double up.
    attribute = make_nonresident_attribute([(40, 3)], clusters=3)
    record = make_record(100, [attribute], reference_count=2)
    bitmap = make_bitmap(64, {40, 41, 42})

    checker = AllocationCrossChecker(
        volume_bitmap=bitmap,
        mft_bitmap=make_bitmap(256, {100}),
        total_clusters=64,
        mft_record_count=256,
    )
    checker.add_record(record)
    # Registering the same record again represents the second hard link.
    checker.add_record(record)
    report = checker.check()

    assert not report.has_conflicts()
    audit = report.audit(41)
    assert len(audit.claims) == 1
    assert {claim.segment for claim in audit.claims} == {100}
    assert audit.recoverable


def test_sparse_runs_occupy_no_clusters() -> None:
    # VCN layout: 2 sparse, 2 real at LCN 8..9, 1 sparse.
    attribute = make_nonresident_attribute([(None, 2), (8, 2), (None, 1)], clusters=5)
    record = make_record(100, [attribute])
    bitmap = make_bitmap(16, {8, 9})

    checker = AllocationCrossChecker(
        volume_bitmap=bitmap,
        mft_bitmap=make_bitmap(256, {100}),
        total_clusters=16,
        mft_record_count=256,
    )
    checker.add_record(record)
    report = checker.check()

    assert checker.sparse_clusters == 3
    assert not report.has_conflicts()
    assert report.audit(8).recoverable
    assert report.audit(9).recoverable
    # Sparse VCNs never create a claim against a physical cluster.
    assert report.audit(0).claims == ()
    assert all(not audit.referenced for audit in report.cluster_audits if audit.lcn not in {8, 9})


def test_cross_linked_active_records_claim_same_cluster() -> None:
    first = make_nonresident_attribute([(50, 4)], clusters=4)
    second = make_nonresident_attribute([(52, 2)], clusters=2)
    record_a = make_record(100, [first])
    record_b = make_record(101, [second])
    bitmap = make_bitmap(64, {50, 51, 52, 53})

    checker = AllocationCrossChecker(
        volume_bitmap=bitmap,
        mft_bitmap=make_bitmap(256, {100, 101}),
        total_clusters=64,
        mft_record_count=256,
    )
    checker.add_record(record_a)
    checker.add_record(record_b)
    report = checker.check()

    assert report.has_conflicts()
    conflict = report.ranges_for(AllocationIssue.CROSS_LINKED)
    assert len(conflict) == 1
    assert conflict[0].start == 52
    assert conflict[0].end == 53
    assert conflict[0].references == frozenset({"<segment 100>", "<segment 101>"})
    for lcn in (52, 53):
        audit = report.audit(lcn)
        assert audit.cross_linked
        assert not audit.recoverable
        assert {claim.segment for claim in audit.claims} == {100, 101}
    # Non-overlapping clusters of the same files remain recoverable.
    assert report.audit(50).recoverable
    assert report.audit(51).recoverable


def test_freed_cluster_still_referenced_by_active_record() -> None:
    attribute = make_nonresident_attribute([(70, 2)], clusters=2)
    record = make_record(100, [attribute])
    # The bitmap claims both clusters are free even though the record is active.
    bitmap = make_bitmap(80, set())

    checker = AllocationCrossChecker(
        volume_bitmap=bitmap,
        mft_bitmap=make_bitmap(256, {100}),
        total_clusters=80,
        mft_record_count=256,
    )
    checker.add_record(record)
    report = checker.check()

    stale = report.ranges_for(AllocationIssue.FREED_BUT_REFERENCED)
    assert len(stale) == 1
    assert stale[0].start == 70
    assert stale[0].end == 71
    assert stale[0].references == frozenset({"<segment 100>"})
    for lcn in (70, 71):
        audit = report.audit(lcn)
        assert audit.bitmap_allocated is False
        assert audit.referenced
        assert not audit.allocated
        assert not audit.recoverable


def test_deleted_record_claims_are_stale_not_duplicate_occupation() -> None:
    attribute = make_nonresident_attribute([(90, 2)], clusters=2)
    deleted = make_record(200, [attribute], in_use=False)
    bitmap = make_bitmap(96, set())

    checker = AllocationCrossChecker(volume_bitmap=bitmap, mft_bitmap=make_bitmap(256, set()), total_clusters=96)
    checker.add_record(deleted)
    report = checker.check()

    assert AllocationIssue.FREED_BUT_REFERENCED in report.issues()
    audit = report.audit(90)
    assert audit.claims == ()
    assert {claim.segment for claim in audit.deleted_claims} == {200}
    # A stale reference is a carving candidate, not a recoverable allocated file.
    assert not audit.recoverable
    assert report.record(200).in_use is False


def test_volume_bitmap_truncation_leaves_unknown_range() -> None:
    attribute = make_nonresident_attribute([(30, 2)], clusters=2)
    record = make_record(100, [attribute])
    # Volume claims 40 clusters but the bitmap only describes the first 16.
    bitmap = make_bitmap(16, set())

    checker = AllocationCrossChecker(
        volume_bitmap=bitmap,
        mft_bitmap=make_bitmap(256, {100}),
        total_clusters=40,
        mft_record_count=256,
    )
    checker.add_record(record)
    report = checker.check()

    assert report.volume_bitmap_issue == AllocationRange(16, 39, AllocationIssue.VOLUME_BITMAP_TRUNCATED)
    assert report.audit(30).bitmap_allocated is None
    assert AllocationIssue.BITMAP_UNKNOWN in report.audit(30).issues
    # Indeterminate bitmap evidence must not be promoted to a recovery claim.
    assert not report.audit(30).recoverable


def test_mft_bitmap_disagrees_with_record_flags() -> None:
    attribute = make_nonresident_attribute([(5, 1)], clusters=1)
    active = make_record(100, [attribute], in_use=True)
    # MFT bitmap says segment 100 is free although the header flag says in use.
    mft_bitmap = make_bitmap(128, set())
    volume_bitmap = make_bitmap(16, {5})

    checker = AllocationCrossChecker(
        volume_bitmap=volume_bitmap,
        mft_bitmap=mft_bitmap,
        total_clusters=16,
        mft_record_count=128,
    )
    checker.add_record(active)
    report = checker.check()

    status = report.record(100)
    assert status.flag_in_use is True
    assert status.bitmap_in_use is False
    assert status.issues == (AllocationIssue.RECORD_FLAGS_CONFLICT,)
    assert report.has_conflicts()


def test_mft_bitmap_truncation_is_reported() -> None:
    checker = AllocationCrossChecker(
        mft_bitmap=make_bitmap(8, set()),
        mft_record_count=32,
    )
    checker.add_runlist([(1, 1)], segment=100, reference="<segment 100>")
    report = checker.check()

    assert report.mft_bitmap_issue == AllocationRange(8, 31, AllocationIssue.MFT_BITMAP_TRUNCATED)
    # Segment 100 is beyond the truncated bitmap: its in-use bit is unknowable.
    assert report.record(100).issues == (AllocationIssue.RECORD_BITMAP_UNKNOWN,)


def test_synthetic_runlist_roundtrip_and_raw_runlist_entry() -> None:
    # The synthetic attribute must decode through dissect.ntfs's own parser.
    sparse_attribute = make_nonresident_attribute([(None, 1), (12, 2)], clusters=3)
    assert sparse_attribute.dataruns() == [(None, 1), (12, 2)]

    checker = AllocationCrossChecker(
        volume_bitmap=make_bitmap(20, {12, 13}),
        mft_bitmap=make_bitmap(256, {101}),
        total_clusters=20,
        mft_record_count=256,
    )
    checker.add_runlist(
        [(None, 1), (12, 2)],
        segment=101,
        stream_name="ads",
        reference="evidence.txt:ads",
    )
    report = checker.check()

    assert checker.sparse_clusters == 1
    assert not report.has_conflicts()
    audit = report.audit(13)
    assert audit.recoverable
    assert audit.claims[0].stream_name == "ads"
    assert audit.references == frozenset({"evidence.txt:ads"})


def test_report_only_observes_and_never_mutates_inputs() -> None:
    attribute = make_nonresident_attribute([(5, 2)], clusters=2)
    record = make_record(100, [attribute])
    bitmap = make_bitmap(16, {5, 6})
    snapshot = bytes(bitmap)

    checker = AllocationCrossChecker(
        volume_bitmap=bitmap,
        mft_bitmap=make_bitmap(256, {100}),
        total_clusters=16,
        mft_record_count=256,
    )
    checker.add_record(record)
    checker.check()

    # The checker holds no write path; the source bitmap bytes are unchanged.
    assert bytes(bitmap) == snapshot


def test_from_ntfs_on_real_image_is_consistent(ntfs_bin: BinaryIO) -> None:
    fs = NTFS(ntfs_bin)
    large = fs.mft.get("Large.txt")
    checker = AllocationCrossChecker.from_ntfs(fs, segments=range(48))
    report = checker.check()

    # A freshly formatted reference image must not show cross-links or stale clusters.
    assert AllocationIssue.CROSS_LINKED not in report.issues()
    assert AllocationIssue.FREED_BUT_REFERENCED not in report.issues()
    assert report.volume_bitmap_issue is None
    assert report.mft_bitmap_issue is None

    # Every non-resident cluster claimed by Large.txt must be bitmap-allocated and recoverable.
    for lcn, count in large.dataruns():
        if lcn is None:
            continue
        for offset in range(count):
            audit = report.audit(lcn + offset)
            assert audit is not None
            assert audit.allocated
            assert audit.recoverable


def test_mft_only_parsing_reports_indeterminate_volume_bitmap(mft_bin: BinaryIO) -> None:
    fs = NTFS(mft=mft_bin)
    checker = AllocationCrossChecker.from_ntfs(fs)
    report = checker.check()

    # Without a volume file the bitmap cannot be consulted; this is indeterminate, not a conflict.
    assert not report.has_conflicts()
    assert all(not audit.allocated for audit in report.cluster_audits)
    assert report.volume_bitmap_issue is None


@pytest.mark.parametrize(
    ("runlist", "expected"),
    [
        ([(0, 1)], [(0, 1)]),
        ([(None, 4), (16, 2), (None, 1)], [(None, 4), (16, 2), (None, 1)]),
        ([(100, 1), (90, 2)], [(100, 1), (90, 2)]),  # backward delta must encode signed
    ],
)
def test_runlist_encoding_roundtrip(runlist: list[tuple[int | None, int]], expected: list) -> None:
    clusters = sum(count for _, count in runlist)
    attribute = make_nonresident_attribute(runlist, clusters=clusters)
    assert attribute.dataruns() == expected
