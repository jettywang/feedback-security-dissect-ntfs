from __future__ import annotations

import io
import struct
from typing import TYPE_CHECKING

import pytest

from dissect.ntfs.c_ntfs import c_ntfs
from dissect.ntfs.exceptions import (
    SecurityDescriptorConflictError,
    SecurityDescriptorCorruptionError,
)
from dissect.ntfs.secure import SDS_MIRROR_STRIDE, STATUS_TRUNCATED, Secure, SecurityDescriptorEvidence

if TYPE_CHECKING:
    from collections.abc import Iterator


def _sid_bytes(authority: int, sub_authorities: tuple[int, ...]) -> bytes:
    return (
        struct.pack("<BB", 1, len(sub_authorities))
        + authority.to_bytes(6, "big")
        + b"".join(sub_authority.to_bytes(4, "little") for sub_authority in sub_authorities)
    )


SYSTEM_SID = _sid_bytes(5, (18,))
ADMIN_SID = _sid_bytes(5, (32, 544))


def build_descriptor(owner_sid: bytes, group_sid: bytes) -> bytes:
    aces = b""
    for sid in (SYSTEM_SID, ADMIN_SID):
        aces += struct.pack("<BBH", 0x00, 0x00, 8 + len(sid)) + struct.pack("<I", 0x120089) + sid

    acl = struct.pack("<BBHHH", 2, 0, 8 + len(aces), 2, 0) + aces
    relative_size = len(c_ntfs._SECURITY_DESCRIPTOR_RELATIVE)
    header = c_ntfs._SECURITY_DESCRIPTOR_RELATIVE(
        Revision=1,
        Control=c_ntfs.SECURITY_DESCRIPTOR_CONTROL.SE_SELF_RELATIVE
        | c_ntfs.SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PRESENT,
        Owner=relative_size,
        Group=relative_size + len(owner_sid),
        Sacl=0,
        Dacl=relative_size + len(owner_sid) + len(group_sid),
    ).dumps()
    return header + owner_sid + group_sid + acl


def build_entry(security_id: int, descriptor: bytes, offset: int) -> bytes:
    length = len(c_ntfs._SECURITY_DESCRIPTOR_HEADER) + len(descriptor)
    header = c_ntfs._SECURITY_DESCRIPTOR_HEADER(
        HashId=0,
        SecurityId=security_id,
        Offset=offset,
        Length=length,
    ).dumps()
    return header + descriptor


def build_sds(entries: dict[int, bytes], mirrors: int = 1) -> bytes:
    stream = bytearray(SDS_MIRROR_STRIDE * mirrors)
    for mirror in range(mirrors):
        base = mirror * SDS_MIRROR_STRIDE
        offset = 0
        for security_id, descriptor in entries.items():
            entry = build_entry(security_id, descriptor, offset)
            stream[base + offset : base + offset + len(entry)] = entry
            offset += len(entry)
            offset += -offset & 0xF
    return bytes(stream)


class FakeIndexEntry:
    def __init__(self, key: int, data: bytes, offset: int = 0) -> None:
        self.key = struct.pack("<I", key)
        self.data = data
        self.offset = offset

    @property
    def key_length(self) -> int:
        return 4


class FakeIndex:
    def __init__(self, entries: list[FakeIndexEntry]) -> None:
        self._entries = entries

    def search(self, security_id: int) -> FakeIndexEntry:
        for entry in self._entries:
            if entry.key == struct.pack("<I", security_id):
                return entry
        raise KeyError(f"Value not found: {security_id}")

    def entries(self) -> Iterator[FakeIndexEntry]:
        yield from self._entries


def index_header(security_id: int, offset: int, length: int, hash_id: int = 0) -> bytes:
    return c_ntfs._SECURITY_DESCRIPTOR_HEADER(
        HashId=hash_id,
        SecurityId=security_id,
        Offset=offset,
        Length=length,
    ).dumps()


def make_secure(sds_bytes: bytes, index_entries: list[FakeIndexEntry] | None = None) -> Secure:
    secure = Secure(sds=io.BytesIO(sds_bytes))
    if index_entries is not None:
        secure.sii = FakeIndex(index_entries)
    return secure


def test_consistent_mirrors_merge_into_one_evidence() -> None:
    descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    secure = make_secure(build_sds({256: descriptor}, mirrors=2))

    evidence = secure.audit(256)
    assert isinstance(evidence, SecurityDescriptorEvidence)
    assert evidence.consistent
    assert not evidence.conflicts
    assert evidence.selected == descriptor
    assert evidence.selection_reason.startswith("no $SII index available")
    assert [(loc.offset, loc.mirror, loc.status) for loc in evidence.valid_locations] == [
        (0, 0, "ok"),
        (SDS_MIRROR_STRIDE, SDS_MIRROR_STRIDE, "ok"),
    ]

    sd = secure.lookup(256)
    assert sd.owner == "S-1-5-18"
    assert sd.group == "S-1-5-32-544"
    assert [ace.sid for ace in sd.dacl.ace] == ["S-1-5-18", "S-1-5-32-544"]


def test_consistent_mirrors_with_index_merge() -> None:
    descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    sds = build_sds({256: descriptor}, mirrors=2)
    secure = make_secure(sds, [FakeIndexEntry(256, index_header(256, 0, 20 + len(descriptor)))])

    evidence = secure.audit(256)
    assert evidence.consistent
    assert evidence.selected == descriptor
    assert evidence.selection_reason.startswith("2 identical valid copies agree")
    assert all(loc.indexed for loc in evidence.valid_locations)

    sd = secure.lookup(256)
    assert sd.owner == "S-1-5-18"


def test_one_truncated_mirror_still_yields_the_indexed_copy() -> None:
    descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    entry = build_entry(256, descriptor, 0)
    sds = bytearray(SDS_MIRROR_STRIDE)
    sds[0 : len(entry)] = entry
    second = build_sds({256: descriptor}, mirrors=2)[SDS_MIRROR_STRIDE : SDS_MIRROR_STRIDE + 60]

    secure = make_secure(bytes(sds) + second)
    evidence = secure.audit(256)

    assert evidence.consistent
    assert evidence.selected == descriptor
    statuses = {loc.mirror: loc.status for loc in evidence.locations}
    assert statuses[0] == "ok"
    assert statuses[SDS_MIRROR_STRIDE] == STATUS_TRUNCATED
    assert evidence.selection_reason.startswith("no $SII index available")

    assert secure.lookup(256).owner == "S-1-5-18"


def test_truncated_stream_reports_corruption_not_a_descriptor() -> None:
    descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    entry = build_entry(256, descriptor, 0)
    secure = make_secure(entry[: len(entry) - 8])

    evidence = secure.audit(256)
    assert len(evidence.locations) == 1
    assert evidence.locations[0].status == STATUS_TRUNCATED
    assert evidence.selected is None
    assert evidence.selection_reason.startswith("all candidate copies are truncated")

    with pytest.raises(SecurityDescriptorCorruptionError) as exc_info:
        secure.lookup(256)
    assert exc_info.value.evidence is not None
    assert exc_info.value.evidence.locations[0].status == STATUS_TRUNCATED


def test_same_id_content_conflict_retains_every_location() -> None:
    first = build_descriptor(SYSTEM_SID, ADMIN_SID)
    second = build_descriptor(ADMIN_SID, SYSTEM_SID)
    sds = bytearray(SDS_MIRROR_STRIDE * 2)
    entry_first = build_entry(256, first, 0)
    entry_second = build_entry(256, second, 0)
    sds[0 : len(entry_first)] = entry_first
    sds[SDS_MIRROR_STRIDE : SDS_MIRROR_STRIDE + len(entry_second)] = entry_second

    secure = make_secure(bytes(sds))
    evidence = secure.audit(256)

    assert evidence.conflicts
    assert not evidence.consistent
    assert evidence.selected is None
    assert evidence.selection_reason.startswith("conflicting contents")
    assert len(evidence.copies) == 2
    assert len(evidence.valid_locations) == 2
    assert {loc.mirror for loc in evidence.valid_locations} == {0, SDS_MIRROR_STRIDE}
    assert {sd.owner for sd in evidence.descriptors} == {"S-1-5-18", "S-1-5-32-544"}

    with pytest.raises(SecurityDescriptorConflictError) as exc_info:
        secure.lookup(256)
    assert exc_info.value.evidence is not None
    assert exc_info.value.evidence.conflicts
    assert "content 1" in exc_info.value.evidence.selection_reason
    assert "content 2" in exc_info.value.evidence.selection_reason
    assert exc_info.value.evidence.copies == evidence.copies


def test_indexed_corrupt_copy_falls_back_to_identical_mirror() -> None:
    descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    entry = build_entry(256, descriptor, 0)
    corrupted = bytearray(entry)
    # Point the Owner offset outside the descriptor body: the entry is structurally invalid.
    struct.pack_into("<I", corrupted, 20 + 4, 0x1000)

    sds = bytearray(SDS_MIRROR_STRIDE * 2)
    sds[0 : len(corrupted)] = corrupted
    sds[SDS_MIRROR_STRIDE : SDS_MIRROR_STRIDE + len(entry)] = entry

    secure = make_secure(bytes(sds), [FakeIndexEntry(256, index_header(256, 0, len(entry)))])
    evidence = secure.audit(256)

    assert evidence.locations[0].status == "invalid"
    assert evidence.locations[1].status == "ok"
    assert evidence.consistent
    assert evidence.selected == descriptor
    assert [loc.indexed for loc in evidence.valid_locations] == [True]
    assert secure.lookup(256).owner == "S-1-5-18"


def test_identical_candidate_of_a_corrupt_indexed_copy_is_selected_with_basis() -> None:
    descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    entry = build_entry(256, descriptor, 0)
    corrupted = bytearray(entry)
    # Corrupt only the entry's SecurityId field; the descriptor body bytes remain identical.
    struct.pack_into("<I", corrupted, 4, 999)

    sds = bytearray(SDS_MIRROR_STRIDE)
    sds[0 : len(corrupted)] = corrupted
    candidate_offset = 0x80
    candidate = build_entry(256, descriptor, candidate_offset)
    sds[candidate_offset : candidate_offset + len(candidate)] = candidate

    secure = make_secure(bytes(sds), [FakeIndexEntry(256, index_header(256, 0, len(entry)))])

    evidence = secure.audit(256)
    assert evidence.selected == descriptor
    assert evidence.selection_reason.startswith(
        "indexed copy is structurally invalid but its stored bytes match the candidate"
    )
    assert evidence.locations[0].status == "invalid"
    assert evidence.locations[0].content == descriptor
    assert secure.lookup(256).owner == "S-1-5-18"


def test_different_candidate_of_a_corrupt_indexed_copy_is_not_selected_silently() -> None:
    indexed_descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    other_descriptor = build_descriptor(ADMIN_SID, SYSTEM_SID)
    entry = build_entry(256, indexed_descriptor, 0)
    corrupted = bytearray(entry)
    struct.pack_into("<I", corrupted, 20 + 4, 0x1000)

    sds = bytearray(SDS_MIRROR_STRIDE)
    sds[0 : len(corrupted)] = corrupted
    candidate_offset = 0x80
    candidate = build_entry(256, other_descriptor, candidate_offset)
    sds[candidate_offset : candidate_offset + len(candidate)] = candidate

    secure = make_secure(bytes(sds), [FakeIndexEntry(256, index_header(256, 0, len(entry)))])

    evidence = secure.audit(256)
    assert evidence.selected is None
    assert evidence.copies == {other_descriptor: evidence.valid_locations}
    assert evidence.selection_reason.startswith("no complete indexed copy exists")
    assert f"{candidate_offset:#x}" in evidence.selection_reason

    with pytest.raises(SecurityDescriptorCorruptionError):
        secure.lookup(256)


def test_sds_only_mode_without_index() -> None:
    descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    secure = make_secure(build_sds({256: descriptor}, mirrors=2))

    assert secure.sii is None
    sd = secure.lookup(256)
    assert sd.owner == "S-1-5-18"

    evidence = secure.audit(256)
    assert evidence.index_entries == []
    assert evidence.consistent


def test_index_security_id_mismatch_is_flagged_and_scan_finds_the_entry() -> None:
    descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    secure = make_secure(
        build_sds({256: descriptor}, mirrors=2),
        [FakeIndexEntry(256, index_header(257, 0, 20 + len(descriptor)))],
    )

    evidence = secure.audit(256)
    assert any(issue.kind == "invalid-index-entry" for issue in evidence.issues)
    assert evidence.consistent
    assert evidence.selected is None
    assert {loc.offset for loc in evidence.valid_locations} == {0, SDS_MIRROR_STRIDE}
    assert evidence.selection_reason.startswith("no complete indexed copy exists")


def test_index_length_mismatch_is_reported() -> None:
    descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    secure = make_secure(
        build_sds({256: descriptor}, mirrors=2),
        [FakeIndexEntry(256, index_header(256, 0, 20 + len(descriptor) + 16))],
    )

    evidence = secure.audit(256)
    assert any(issue.kind == "mismatch-length" for issue in evidence.issues)
    assert evidence.consistent


class BrokenIndex:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def entries(self) -> Iterator[FakeIndexEntry]:
        raise self.error


def test_unreadable_index_falls_back_to_sds_candidates() -> None:
    descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    sds = build_sds({256: descriptor}, mirrors=2)
    secure = make_secure(sds)
    secure.sii = BrokenIndex(EOFError("broken index allocation"))

    evidence = secure.audit(256)
    assert evidence.index_error is not None
    assert evidence.consistent
    assert evidence.selected == descriptor
    assert evidence.selection_reason.startswith("$SII index unreadable")
    assert "broken index allocation" in evidence.selection_reason

    assert secure.lookup(256).owner == "S-1-5-18"


def test_entry_crossing_mirror_boundary_is_truncated() -> None:
    descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    entry = build_entry(256, descriptor, 0)
    stride = 0x200
    # Place the entry so it starts inside the first region but ends past its boundary.
    start = stride - 0x40
    stream = bytearray(stride * 2)
    # Rewrite the embedded offset so only the mirror boundary makes this copy unusable.
    stream[start : start + len(entry)] = build_entry(256, descriptor, start)
    secure = Secure(sds=io.BytesIO(bytes(stream)), mirror_stride=stride)

    evidence = secure.audit(256)
    assert evidence.locations[0].offset == start
    assert evidence.locations[0].status == STATUS_TRUNCATED
    assert evidence.selected is None
    with pytest.raises(SecurityDescriptorCorruptionError):
        secure.lookup(256)


def test_index_without_entry_falls_back_to_sds_but_reports_no_index_entry() -> None:
    descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    sds = build_sds({256: descriptor}, mirrors=2)
    secure = make_secure(sds, [])

    evidence = secure.audit(256)
    assert evidence.index_entries == []
    assert evidence.index_error is not None
    assert evidence.index_readable is True
    assert evidence.selected == descriptor
    assert evidence.selection_reason.startswith("no $SII index entry")

    assert secure.lookup(256).owner == "S-1-5-18"


def test_index_hash_mismatch_is_reported() -> None:
    descriptor = build_descriptor(SYSTEM_SID, ADMIN_SID)
    secure = make_secure(
        build_sds({256: descriptor}, mirrors=2),
        [FakeIndexEntry(256, index_header(256, 0, 20 + len(descriptor), hash_id=0xDEADBEEF))],
    )

    evidence = secure.audit(256)
    assert any(issue.kind == "mismatch-hash" for issue in evidence.issues)
    assert evidence.selected == descriptor
