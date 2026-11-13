from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.ntfs.c_ntfs import USN_PAGE_SIZE, c_ntfs
from dissect.ntfs.rename import (
    RenameIdentity,
    RenameStatus,
    RenameTrace,
    RenameTracker,
    UnpairedReason,
    track_renames,
)
from dissect.ntfs.usnjrnl import UsnJournalGap, UsnJrnl, UsnRecord

if TYPE_CHECKING:
    from collections.abc import Iterable

OLD = c_ntfs.USN_REASON.RENAME_OLD_NAME
NEW = c_ntfs.USN_REASON.RENAME_NEW_NAME


def usn_record(
    segment: int,
    sequence: int,
    parent: tuple[int, int],
    usn: int,
    name: str,
    reason: int = 0,
) -> bytes:
    """Build a raw version 2 USN record.

    Args:
        segment: MFT segment number of the file.
        sequence: Sequence number of the file reference.
        parent: ``(segment, sequence)`` of the parent directory reference.
        usn: The USN of the record.
        name: The file name in the record.
        reason: The USN reason flags.
    """
    rec = c_ntfs.USN_RECORD_V2()
    rec.RecordLength = 0
    rec.MajorVersion = 2
    rec.MinorVersion = 0
    rec.FileReferenceNumber.SegmentNumberLowPart = segment & 0xFFFFFFFF
    rec.FileReferenceNumber.SegmentNumberHighPart = segment >> 32
    rec.FileReferenceNumber.SequenceNumber = sequence
    rec.ParentFileReferenceNumber.SegmentNumberLowPart = parent[0] & 0xFFFFFFFF
    rec.ParentFileReferenceNumber.SegmentNumberHighPart = parent[0] >> 32
    rec.ParentFileReferenceNumber.SequenceNumber = parent[1]
    rec.Usn = usn
    rec.TimeStamp = 0
    rec.Reason = c_ntfs.USN_REASON(reason)
    rec.SourceInfo = c_ntfs.USN_SOURCE(0)
    rec.SecurityId = 0
    rec.FileAttributes = c_ntfs.FILE_ATTRIBUTE.ARCHIVE
    data = name.encode("utf-16-le")
    rec.FileNameLength = len(data)
    rec.FileNameOffset = 60
    rec.RecordLength = (60 + len(data) + 7) & ~7

    return bytes(rec) + data + b"\x00" * (rec.RecordLength - 60 - len(data))


def journal(*pages: Iterable[bytes] | None) -> bytes:
    """Build page-aligned journal data from an explicit page layout.

    Each positional argument is an iterable of records for one journal page, or ``None`` for a missing page
    written as all zeroes.

    Args:
        pages: The page layout of the journal.
    """
    result = []
    for page in pages:
        if page is None:
            result.append(b"\x00" * USN_PAGE_SIZE)
            continue

        data = b"".join(page)
        if len(data) > USN_PAGE_SIZE:
            raise ValueError(f"page contains {len(data)} bytes, exceeds {USN_PAGE_SIZE}")
        result.append(data + b"\x00" * (USN_PAGE_SIZE - len(data)))

    return b"".join(result)


def parse(data: bytes) -> list[UsnRecord | UsnJournalGap]:
    return list(UsnJrnl(BytesIO(data)).events())


def traces(events: Iterable[UsnRecord | UsnJournalGap], *, max_pending: int = 256) -> list[RenameTrace]:
    return list(track_renames(events, max_pending=max_pending))


def summary(trace: RenameTrace) -> tuple[str | None, str, UnpairedReason | None, str | None, str | None]:
    identity = trace.identity.label if trace.identity is not None else None
    return (identity, trace.status.value, trace.reason, trace.old_name, trace.new_name)


def test_rename_pair() -> None:
    data = journal(
        [usn_record(42, 7, (5, 5), 100, "a.txt", OLD)],
        [usn_record(42, 7, (5, 5), 110, "b.txt", NEW)],
    )
    events = parse(data)

    assert [type(event) for event in events] == [UsnRecord, UsnRecord]

    result = traces(events)
    assert len(result) == 1
    trace = result[0]
    assert trace.status is RenameStatus.PAIRED
    assert trace.reason is None
    assert trace.identity == RenameIdentity(42, 7)
    assert trace.old is events[0]
    assert trace.new is events[1]
    assert trace.old_name == "a.txt"
    assert trace.new_name == "b.txt"
    assert trace.evidence == (
        "file reference 0x2a#7: segment 42, sequence 7",
        "RENAME_OLD_NAME usn 100 precedes RENAME_NEW_NAME usn 110",
        "journal offsets 0x0 -> 0x1000 have no missing-page gap between them",
        "rename 'a.txt' -> 'b.txt'",
        "parent reference 0x5#5 -> 0x5#5",
    )


def test_rename_requires_sequence_not_just_slot() -> None:
    """A reused MFT slot with a different sequence number is a different file."""
    data = journal(
        [
            usn_record(42, 1, (5, 5), 100, "old.txt", OLD),
            usn_record(42, 2, (5, 5), 110, "new.txt", NEW),
        ]
    )

    result = traces(parse(data))
    assert [summary(trace) for trace in result] == [
        ("0x2a#2", "incomplete", UnpairedReason.NEW_WITHOUT_OLD, None, "new.txt"),
        ("0x2a#1", "incomplete", UnpairedReason.OLD_WITHOUT_NEW, "old.txt", None),
    ]
    assert result[0].gap is None
    assert all("segment 42" in trace.evidence[0] for trace in result)
    assert not any(trace.paired for trace in result)


def test_rename_not_by_filename() -> None:
    """Files that swap names must pair by reference identity, not by name."""
    data = journal(
        [
            usn_record(42, 1, (5, 5), 100, "a.txt", OLD),
            usn_record(77, 3, (5, 5), 110, "b.txt", OLD),
            usn_record(42, 1, (5, 5), 120, "b.txt", NEW),
        ],
        [usn_record(77, 3, (5, 5), 130, "a.txt", NEW)],
    )

    result = traces(parse(data))
    assert len(result) == 2
    assert {trace.identity: (trace.old_name, trace.new_name) for trace in result} == {
        RenameIdentity(42, 1): ("a.txt", "b.txt"),
        RenameIdentity(77, 3): ("b.txt", "a.txt"),
    }
    assert all(trace.status is RenameStatus.PAIRED for trace in result)


def test_rename_interleaved_files() -> None:
    data = journal(
        [
            usn_record(42, 1, (5, 5), 100, "a-1.txt", OLD),
            usn_record(77, 3, (5, 5), 110, "b-1.txt", OLD),
            usn_record(42, 1, (5, 5), 120, "a-2.txt", NEW),
            usn_record(77, 3, (5, 5), 130, "b-2.txt", NEW),
        ]
    )

    result = traces(parse(data))
    assert len(result) == 2
    assert {trace.identity: (trace.old_name, trace.new_name, trace.status) for trace in result} == {
        RenameIdentity(42, 1): ("a-1.txt", "a-2.txt", RenameStatus.PAIRED),
        RenameIdentity(77, 3): ("b-1.txt", "b-2.txt", RenameStatus.PAIRED),
    }


def test_rename_consecutive() -> None:
    data = journal(
        [
            usn_record(42, 1, (5, 5), 100, "a.txt", OLD),
            usn_record(42, 1, (5, 5), 110, "b.txt", NEW),
            usn_record(42, 1, (5, 5), 120, "b.txt", OLD),
            usn_record(42, 1, (5, 5), 130, "c.txt", NEW),
        ]
    )

    result = traces(parse(data))
    assert [(trace.old_name, trace.new_name, trace.status) for trace in result] == [
        ("a.txt", "b.txt", RenameStatus.PAIRED),
        ("b.txt", "c.txt", RenameStatus.PAIRED),
    ]


def test_rename_slot_reuse_pending_isolated() -> None:
    """Pending renames for two generations of the same slot are tracked independently."""
    data = journal(
        [
            usn_record(42, 1, (5, 5), 100, "a.txt", OLD),
            usn_record(42, 2, (5, 5), 110, "c.txt", OLD),
        ],
        [
            usn_record(42, 1, (5, 5), 120, "b.txt", NEW),
            usn_record(42, 2, (5, 5), 130, "d.txt", NEW),
        ],
    )

    result = traces(parse(data))
    assert [(trace.identity.label, trace.old_name, trace.new_name) for trace in result] == [
        ("0x2a#1", "a.txt", "b.txt"),
        ("0x2a#2", "c.txt", "d.txt"),
    ]
    assert any(
        "segment 42 is also pending for 0x2a#1" in line for line in result[1].evidence
    )


def test_rename_journal_gap_prevents_pairing() -> None:
    """A missing page between OLD and NEW must not produce a guessed complete rename."""
    data = journal(
        [usn_record(42, 1, (5, 5), 100, "a.txt", OLD)],
        None,
        [usn_record(42, 1, (5, 5), 120, "b.txt", NEW)],
    )

    events = parse(data)
    assert isinstance(events[1], UsnJournalGap)
    assert events[1].start_offset == USN_PAGE_SIZE
    assert events[1].end_offset == 2 * USN_PAGE_SIZE

    result = traces(events)
    assert len(result) == 2
    first, second = result
    assert first.status is RenameStatus.INCOMPLETE
    assert first.reason is UnpairedReason.JOURNAL_GAP
    assert first.old_name == "a.txt"
    assert first.new is None
    assert first.gap is events[1]
    assert first.evidence[-1] == (
        "journal gap 0x1000-0x2000 follows before a matching RENAME_NEW_NAME record"
    )

    assert second.status is RenameStatus.INCOMPLETE
    assert second.reason is UnpairedReason.NEW_WITHOUT_OLD
    assert second.old is None
    assert second.new_name == "b.txt"
    assert second.gap is events[1]
    assert second.evidence[-1].startswith("the preceding journal gap 0x1000-0x2000")
    assert not any(trace.paired for trace in result)


def test_records_skips_gaps_and_rename_traces_convenience() -> None:
    """``records()`` keeps its historical record-only behaviour while the convenience entry point correlates."""
    data = journal(
        [usn_record(42, 1, (5, 5), 100, "a.txt", OLD)],
        None,
        [usn_record(42, 1, (5, 5), 120, "b.txt", NEW)],
    )

    records = list(UsnJrnl(BytesIO(data)).records())
    assert [record.filename for record in records] == ["a.txt", "b.txt"]

    result = list(UsnJrnl(BytesIO(data)).rename_traces())
    assert [trace.status for trace in result] == [RenameStatus.INCOMPLETE, RenameStatus.INCOMPLETE]
    assert [trace.reason for trace in result] == [UnpairedReason.JOURNAL_GAP, UnpairedReason.NEW_WITHOUT_OLD]


def test_rename_new_without_old() -> None:
    events = parse(journal([usn_record(42, 1, (5, 5), 100, "b.txt", NEW)]))

    result = traces(events)
    assert len(result) == 1
    trace = result[0]
    assert trace.status is RenameStatus.INCOMPLETE
    assert trace.reason is UnpairedReason.NEW_WITHOUT_OLD
    assert trace.old is None
    assert trace.new is events[0]
    assert trace.evidence[-1] == "no pending RENAME_OLD_NAME for usn 100 on this file reference"


def test_rename_old_without_new() -> None:
    events = parse(journal([usn_record(42, 1, (5, 5), 100, "a.txt", OLD)]))

    result = traces(events)
    assert len(result) == 1
    trace = result[0]
    assert trace.status is RenameStatus.INCOMPLETE
    assert trace.reason is UnpairedReason.OLD_WITHOUT_NEW
    assert trace.old is events[0]
    assert trace.new is None
    assert trace.evidence[-1] == "the journal ended without a matching RENAME_NEW_NAME record"


def test_rename_old_superseded() -> None:
    data = journal(
        [
            usn_record(42, 1, (5, 5), 100, "a.txt", OLD),
            usn_record(42, 1, (5, 5), 110, "b.txt", OLD),
            usn_record(42, 1, (5, 5), 120, "c.txt", NEW),
        ]
    )

    result = traces(parse(data))
    assert [(trace.status, trace.reason, trace.old_name, trace.new_name) for trace in result] == [
        (RenameStatus.INCOMPLETE, UnpairedReason.OLD_SUPERSEDED, "a.txt", None),
        (RenameStatus.PAIRED, None, "b.txt", "c.txt"),
    ]


def test_rename_invalid_order() -> None:
    data = journal(
        [
            usn_record(42, 1, (5, 5), 200, "a.txt", OLD),
            usn_record(42, 1, (5, 5), 190, "b.txt", NEW),
        ]
    )

    result = traces(parse(data))
    assert len(result) == 1
    trace = result[0]
    assert trace.status is RenameStatus.INCOMPLETE
    assert trace.reason is UnpairedReason.INVALID_ORDER
    assert "does not follow" in trace.evidence[-1]


def test_rename_ambiguous_reason() -> None:
    events = parse(journal([usn_record(42, 1, (5, 5), 100, "a.txt", OLD | NEW)]))

    result = traces(events)
    assert len(result) == 1
    trace = result[0]
    assert trace.status is RenameStatus.INCOMPLETE
    assert trace.reason is UnpairedReason.AMBIGUOUS_REASON
    assert trace.old is events[0]
    assert trace.new is None


def test_rename_pending_limit() -> None:
    data = journal(
        [
            usn_record(42, 1, (5, 5), 100, "a.txt", OLD),
            usn_record(77, 3, (5, 5), 110, "b.txt", OLD),
        ],
        [usn_record(77, 3, (5, 5), 120, "c.txt", NEW)],
    )

    result = traces(parse(data), max_pending=1)
    assert [(trace.status, trace.reason, trace.old_name, trace.new_name) for trace in result] == [
        (RenameStatus.INCOMPLETE, UnpairedReason.PENDING_LIMIT, "a.txt", None),
        (RenameStatus.PAIRED, None, "b.txt", "c.txt"),
    ]


def test_rename_pending_limit_zero() -> None:
    events = parse(journal([usn_record(42, 1, (5, 5), 100, "a.txt", OLD)]))

    tracker = RenameTracker(max_pending=0)
    result = list(tracker.feed(events[0]))
    assert tracker.pending_count == 0
    assert result[0].reason is UnpairedReason.PENDING_LIMIT


def test_rename_pending_count_bounded() -> None:
    records = [usn_record(100 + index, 1, (5, 5), 100 + index, f"f{index}.txt", OLD) for index in range(10)]
    pages = [records[index * 2 : index * 2 + 2] for index in range(5)]
    data = journal(*pages)

    tracker = RenameTracker(max_pending=3)
    max_pending = 0
    for event in parse(data):
        list(tracker.feed(event))
        max_pending = max(max_pending, tracker.pending_count)
    list(tracker.finish())

    assert max_pending <= 3


def test_rename_trailing_padding_is_not_gap() -> None:
    events = parse(journal([usn_record(42, 1, (5, 5), 100, "a.txt", 0)]))

    assert len(events) == 1
    assert isinstance(events[0], UsnRecord)
    assert not any(isinstance(event, UsnJournalGap) for event in events)


@pytest.mark.parametrize(
    "order",
    [
        (0, 1, 2, 3),
        (0, 2, 1, 3),
        (1, 0, 3, 2),
        (1, 3, 0, 2),
    ],
)
def test_rename_reordering_independent_files(order: tuple[int, ...]) -> None:
    """Reordering interleaved events of independent files must not change their conclusions."""
    records = [
        usn_record(42, 1, (5, 5), 100, "a-1.txt", OLD),
        usn_record(77, 3, (5, 5), 110, "b-1.txt", OLD),
        usn_record(42, 1, (5, 5), 120, "a-2.txt", NEW),
        usn_record(77, 3, (5, 5), 130, "b-2.txt", NEW),
    ]
    data = journal([records[index] for index in order])

    result = traces(parse(data))
    assert {trace.identity: summary(trace) for trace in result} == {
        RenameIdentity(42, 1): ("0x2a#1", "paired", None, "a-1.txt", "a-2.txt"),
        RenameIdentity(77, 3): ("0x4d#3", "paired", None, "b-1.txt", "b-2.txt"),
    }


def test_small_journal_slot_reuse_and_gap() -> None:
    """Small journal with slot reuse, a missing page and half events.

    Page 0: file 0x2a#1 renames ``a.txt`` -> ``b.txt``, then renames ``b.txt`` again but only the OLD record
    survived. File 0x2a#2 is created (no rename).
    Page 1: missing (all zeroes); the matching NEW record of 0x2a#1 could have been here.
    Page 2: file 0x2a#2 renames ``created.txt``, but only the NEW record survived. Same MFT slot, different sequence.
    Page 3: file 0x33#3 renames ``x.txt`` -> ``y.txt``.
    Page 4: only the NEW record for file 0x44#4 survived.
    """
    data = journal(
        [
            usn_record(0x2A, 1, (5, 5), 100, "a.txt", OLD),
            usn_record(0x2A, 1, (5, 5), 110, "b.txt", NEW),
            usn_record(0x2A, 1, (5, 5), 120, "b.txt", OLD),
            usn_record(0x2A, 2, (5, 5), 125, "created.txt", 0),
        ],
        None,
        [usn_record(0x2A, 2, (5, 5), 200, "renamed.txt", NEW)],
        [
            usn_record(0x33, 3, (5, 5), 210, "x.txt", OLD),
            usn_record(0x33, 3, (5, 5), 220, "y.txt", NEW),
        ],
        [usn_record(0x44, 4, (5, 5), 230, "z.txt", NEW)],
    )

    result = traces(parse(data))

    assert [summary(trace) for trace in result] == [
        ("0x2a#1", "paired", None, "a.txt", "b.txt"),
        ("0x2a#1", "incomplete", UnpairedReason.JOURNAL_GAP, "b.txt", None),
        ("0x2a#2", "incomplete", UnpairedReason.NEW_WITHOUT_OLD, None, "renamed.txt"),
        ("0x33#3", "paired", None, "x.txt", "y.txt"),
        ("0x44#4", "incomplete", UnpairedReason.NEW_WITHOUT_OLD, None, "z.txt"),
    ]

    assert result[0].evidence[0] == "file reference 0x2a#1: segment 42, sequence 1"
    assert result[0].evidence[1] == "RENAME_OLD_NAME usn 100 precedes RENAME_NEW_NAME usn 110"
    assert result[0].evidence[2].endswith("no missing-page gap between them")
    assert result[1].evidence[-1].startswith("journal gap 0x1000-0x2000")
    assert result[2].evidence[0] == "file reference 0x2a#2: segment 42, sequence 2"
    assert result[4].evidence[-1] == "no pending RENAME_OLD_NAME for usn 230 on this file reference"
