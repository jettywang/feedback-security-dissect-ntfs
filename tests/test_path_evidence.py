from __future__ import annotations

import io
import json
import struct
from typing import Any

from dissect.ntfs.c_ntfs import FILE_NUMBER_ROOT, c_ntfs
from dissect.ntfs.mft import Mft, MftRecord
from dissect.ntfs.path import (
    FilenameNamespace,
    PathReference,
    PathStatus,
)

RECORD_SIZE = 1024
FIRST_ATTRIBUTE_OFFSET = 56

# Name tuples are (name, namespace, parent segment, parent sequence).
#
# Segment 12 is a file with two hard links to Alpha and Beta and a DOS alias for the Alpha link.
# It also has one reference to a reused parent slot, one parent chain that loops back to itself and
# one reference to a segment outside the supplied MFT.
SAMPLE = {
    FILE_NUMBER_ROOT: (5, [(".", FilenameNamespace.WIN32_AND_DOS, FILE_NUMBER_ROOT, 5)], 2),
    10: (1, [("Alpha", FilenameNamespace.WIN32, FILE_NUMBER_ROOT, 5)], 2),
    11: (1, [("Beta", FilenameNamespace.WIN32, FILE_NUMBER_ROOT, 5)], 2),
    12: (
        7,
        [
            ("shared.txt", FilenameNamespace.WIN32, 10, 1),
            ("link2.txt", FilenameNamespace.WIN32, 11, 1),
            ("SHARED~1.TXT", FilenameNamespace.DOS, 10, 1),
            ("stale.txt", FilenameNamespace.WIN32, 20, 1),
            ("loop.txt", FilenameNamespace.WIN32, 13, 1),
            ("missing.txt", FilenameNamespace.WIN32, 30, 1),
        ],
        0,
    ),
    13: (1, [("Cyclic", FilenameNamespace.WIN32, 12, 7)], 2),
    20: (2, [("Reused", FilenameNamespace.WIN32, FILE_NUMBER_ROOT, 5)], 2),
}


def _build_record(
    sequence: int,
    names: list[tuple[str, int, int, int]],
    flags: int = 0,
    record_size: int = RECORD_SIZE,
) -> bytes:
    # Raw MFT record including the update sequence array; MftRecord.from_bytes applies the fixup.
    data = bytearray(record_size)
    sector_count = record_size // 512
    fixup_offset = 48

    data[:4] = b"FILE"
    struct.pack_into("<HH", data, 4, fixup_offset, sector_count + 1)
    data[fixup_offset : fixup_offset + 2] = b"\xaa\xaa"
    for index in range(sector_count):
        struct.pack_into("<H", data, fixup_offset + 2 + index * 2, index + 1)
        struct.pack_into("<H", data, (index + 1) * 512 - 2, 0xAAAA)

    struct.pack_into("<Q", data, 8, 0)  # Lsn
    struct.pack_into("<H", data, 16, sequence)
    struct.pack_into("<H", data, 18, 1)  # ReferenceCount
    struct.pack_into("<H", data, 20, FIRST_ATTRIBUTE_OFFSET)
    struct.pack_into("<H", data, 22, flags)  # FILE_FILE_NAME_INDEX_PRESENT for directories
    struct.pack_into("<I", data, 24, record_size)
    struct.pack_into("<I", data, 28, record_size)

    offset = FIRST_ATTRIBUTE_OFFSET
    for name, namespace, parent_segment, parent_sequence in names:
        file_name = c_ntfs._FILE_NAME()
        file_name.ParentDirectory.SegmentNumberLowPart = parent_segment
        file_name.ParentDirectory.SegmentNumberHighPart = 0
        file_name.ParentDirectory.SequenceNumber = parent_sequence
        file_name.FileNameLength = len(name)
        file_name.Flags = int(namespace)
        file_name.FileName = name
        value = file_name.dumps()

        record_length = (24 + len(value) + 7) & ~7
        struct.pack_into("<I", data, offset, 0x30)  # ATTRIBUTE_TYPE_CODE.FILE_NAME
        struct.pack_into("<I", data, offset + 4, record_length)
        struct.pack_into("<I", data, offset + 16, len(value))  # Resident.ValueLength
        struct.pack_into("<H", data, offset + 20, 24)  # Resident.ValueOffset
        data[offset + 24 : offset + 24 + len(value)] = value
        offset += record_length

    struct.pack_into("<I", data, offset, 0xFFFFFFFF)
    struct.pack_into("<I", data, offset + 4, 0)
    struct.pack_into("<I", data, 24, offset + 8)
    return bytes(data)


def _build_mft(records: dict[int, tuple[int, list[tuple[str, int, int, int]], int]]) -> tuple[Mft, Any]:
    class FakeNtfs:
        _record_size = RECORD_SIZE
        _record_size_shift = 10
        fh = None
        mft = None
        cluster_size = 4096

    stream = bytearray((max(records) + 1) * RECORD_SIZE)
    for segment, (sequence, names, flags) in records.items():
        stream[segment * RECORD_SIZE : (segment + 1) * RECORD_SIZE] = _build_record(sequence, names, flags)
        # Mark the unused slot after the last record as invalid, so reader-like bounds are visible.
    for segment in range(max(records) + 1):
        if segment in records:
            continue
        struct.pack_into("<I", stream, segment * RECORD_SIZE, 0)

    ntfs = FakeNtfs()
    mft = Mft(io.BytesIO(bytes(stream)), ntfs=ntfs)
    ntfs.mft = mft
    return mft, ntfs


def test_path_evidence_two_hard_links_and_dos_alias() -> None:
    mft, _ = _build_mft(SAMPLE)
    record = mft.get(12)

    candidates = record.path_candidates()
    by_name = {candidate.name: candidate for candidate in candidates}

    assert set(by_name) == {"shared.txt", "link2.txt", "SHARED~1.TXT", "stale.txt", "loop.txt", "missing.txt"}
    assert all(candidate.reference == PathReference(12, 7) for candidate in candidates)

    # Hard links are separate candidates with their own parent reference.
    assert by_name["shared.txt"].status == PathStatus.RESOLVED
    assert by_name["shared.txt"].path == "Alpha\\shared.txt"
    assert by_name["shared.txt"].parent_reference == PathReference(10, 1)
    assert by_name["link2.txt"].status == PathStatus.RESOLVED
    assert by_name["link2.txt"].path == "Beta\\link2.txt"
    assert by_name["link2.txt"].parent_reference == PathReference(11, 1)

    # The DOS name is preserved with its namespace and never overwrites the Win32 name.
    assert by_name["SHARED~1.TXT"].namespace == FilenameNamespace.DOS
    assert by_name["SHARED~1.TXT"].path == "Alpha\\SHARED~1.TXT"
    assert by_name["shared.txt"].namespace == FilenameNamespace.WIN32

    # Resolved candidates come first, then the unresolved evidence-only candidates.
    assert [candidate.resolved for candidate in candidates] == [True, True, True, False, False, False]


def test_path_evidence_keeps_raw_references_for_unresolvable_chains() -> None:
    mft, _ = _build_mft(SAMPLE)
    record = mft.get(12)
    by_name = {candidate.name: candidate for candidate in record.path_candidates()}

    reused = by_name["stale.txt"]
    assert reused.status == PathStatus.BROKEN_REFERENCE
    assert reused.parent_reference == PathReference(20, 1)
    assert reused.path is None
    assert reused.elements[-1].reference == PathReference(20, 1)
    assert reused.elements[-1].name is None
    assert "generation 2" in reused.reason
    assert reused.legacy_path == "<broken_reference_0x14#1>\\stale.txt"

    cycle = by_name["loop.txt"]
    assert cycle.status == PathStatus.CYCLE
    assert cycle.path is None
    assert cycle.elements[-1].reference == PathReference(12, 7)
    assert cycle.legacy_path == "<cycle_0xc#7>\\Cyclic\\loop.txt"

    partial = by_name["missing.txt"]
    assert partial.status == PathStatus.MISSING_RECORD
    assert partial.parent_reference == PathReference(30, 1)
    assert partial.path is None
    assert partial.legacy_path == "<missing_record_0x1e#1>\\missing.txt"

    # No unresolved candidate may present itself as a single authoritative path.
    for candidate in (reused, cycle, partial):
        assert candidate.path is None
        assert candidate.resolved is False
        assert candidate.as_dict()["path"] is None
        assert candidate.as_dict()["parent_segment"] == candidate.parent_segment
        assert candidate.as_dict()["parent_sequence"] == candidate.parent_sequence


def test_path_evidence_parents_with_multiple_names_branch() -> None:
    records = dict(SAMPLE)
    # Alpha itself has a DOS and a Win32 name, plus a second parent branch to root. Every ancestor
    # name must produce its own candidate instead of picking one silently.
    records[10] = (
        1,
        [
            ("Alpha", FilenameNamespace.WIN32, FILE_NUMBER_ROOT, 5),
            ("ALPHA~1", FilenameNamespace.DOS, FILE_NUMBER_ROOT, 5),
            ("AlphaLink", FilenameNamespace.WIN32, 21, 1),
        ],
        2,
    )
    records[21] = (1, [("Elsewhere", FilenameNamespace.WIN32, FILE_NUMBER_ROOT, 5)], 2)

    mft, _ = _build_mft(records)
    record = mft.get(12)
    candidates = [candidate for candidate in record.path_candidates() if candidate.name == "shared.txt"]

    paths = {candidate.path for candidate in candidates if candidate.resolved}
    assert paths == {"Alpha\\shared.txt", "ALPHA~1\\shared.txt", "Elsewhere\\AlphaLink\\shared.txt"}
    assert {candidate.status for candidate in candidates} == {PathStatus.RESOLVED}

    # Ignoring DOS removes both the target DOS alias and the ancestor DOS name.
    non_dos = [
        candidate for candidate in mft.get(12).path_candidates(ignore_dos=True) if candidate.name == "shared.txt"
    ]
    assert {candidate.path for candidate in non_dos} == {"Alpha\\shared.txt", "Elsewhere\\AlphaLink\\shared.txt"}


def test_path_evidence_cache_key_includes_generation() -> None:
    mft, ntfs = _build_mft(SAMPLE)

    older = mft.get(12)
    assert older.header.SequenceNumber == 7

    # A different record generation in the same slot must not inherit the cached evidence.
    newer_bytes = _build_record(8, [("newgen.txt", FilenameNamespace.WIN32, 10, 1)], 0)
    newer = MftRecord.from_bytes(newer_bytes, ntfs)
    newer.segment = 12

    assert newer.header.SequenceNumber == 8
    newer_paths = newer.path_candidates()
    assert [candidate.path for candidate in newer_paths] == ["Alpha\\newgen.txt"]
    older_paths = older.path_candidates()
    assert [candidate.path for candidate in older_paths] == [
        "Alpha\\shared.txt",
        "Beta\\link2.txt",
        "Alpha\\SHARED~1.TXT",
        None,
        None,
        None,
    ]
    assert "newgen.txt" not in {candidate.name for candidate in older_paths}

    # Both generations are cached separately: the newer record object has its own entry even though
    # the MFT slot still holds generation 7, so its paths can never be served to generation 7.
    keys = {(key[0], key[1]) for key in mft._path_cache}
    assert (12, 7) in keys
    assert (12, 8) in keys
    assert mft.get_generation(12, 7) is older
    assert mft.get_generation(12, 8) is None  # the slot still contains generation 7
    assert mft.get_generation(12, 9) is None

    # Repeated enumeration uses the per-generation cache entry and returns an independent list.
    first = mft.path_candidates(older)
    second = mft.path_candidates(older)
    assert first == second
    first.clear()
    assert second


def test_path_evidence_root_reference_generation_is_validated() -> None:
    records = dict(SAMPLE)
    records[10] = (1, [("Alpha", FilenameNamespace.WIN32, FILE_NUMBER_ROOT, 9)], 2)

    mft, _ = _build_mft(records)
    record = mft.get(12)
    candidate = next(candidate for candidate in record.path_candidates() if candidate.name == "shared.txt")

    assert candidate.status == PathStatus.BROKEN_REFERENCE
    assert candidate.parent_reference == PathReference(10, 1)
    assert candidate.path is None
    assert candidate.elements[1].parent_reference == PathReference(FILE_NUMBER_ROOT, 9)


def test_legacy_full_paths_still_expose_valid_paths() -> None:
    mft, _ = _build_mft(SAMPLE)
    record = mft.get(12)

    assert record.full_path() == "Alpha\\shared.txt"
    paths = record.full_paths()
    assert paths[0:3] == ["Alpha\\shared.txt", "Beta\\link2.txt", "Alpha\\SHARED~1.TXT"]
    assert paths[3:] == [
        "<broken_reference_0x14#1>\\stale.txt",
        "<cycle_0xc#7>\\Cyclic\\loop.txt",
        "<missing_record_0x1e#1>\\missing.txt",
    ]

    filtered = record.full_paths(ignore_dos=True)
    assert "Alpha\\SHARED~1.TXT" not in filtered
    assert filtered[0:2] == ["Alpha\\shared.txt", "Beta\\link2.txt"]


def test_path_evidence_is_json_serialisable() -> None:
    mft, _ = _build_mft(SAMPLE)

    evidence = mft.get(12).path_evidence()
    assert len(evidence) == 6
    assert {item["status"] for item in evidence} == {
        "resolved",
        "broken_reference",
        "cycle",
        "missing_record",
    }

    payload = json.dumps(evidence, ensure_ascii=False)
    assert "SHARED~1.TXT" in payload
    assert "stale.txt" in payload

    candidate = next(candidate for candidate in mft.get(12).path_candidates() if candidate.name == "stale.txt")
    data = candidate.as_dict()
    assert data["parent_segment"] == 20
    assert data["parent_sequence"] == 1
    assert data["elements"][-1]["name"] is None
    assert data["elements"][-1]["status"] == "broken_reference"
    assert data["elements"][-1]["reference"] == [20, 1]
    assert data["elements"][-1]["parent_reference"] is None


def test_path_evidence_limits_are_enforced() -> None:
    mft, _ = _build_mft(SAMPLE)

    truncated = mft.get(12).path_candidates(max_candidates=2)
    assert [candidate.name for candidate in truncated] == ["shared.txt", "link2.txt", None]
    assert truncated[-1].status == PathStatus.LIMIT_EXCEEDED
    assert truncated[-1].path is None
    assert "limit" in truncated[-1].reason

    shallow = mft.get(12).path_candidates(max_depth=1)
    assert {candidate.status for candidate in shallow} == {PathStatus.LIMIT_EXCEEDED}
    for candidate in shallow:
        assert candidate.path is None
        assert candidate.elements[-1].reference == candidate.parent_reference
