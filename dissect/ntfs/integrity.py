from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, BinaryIO

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
from dissect.ntfs.exceptions import StreamVerificationError
from dissect.ntfs.util import segment_reference
from dissect.util.stream import RunlistStream

if TYPE_CHECKING:
    from dissect.ntfs.attr import Attribute, AttributeList
    from dissect.ntfs.mft import MftRecord
    from dissect.ntfs.util import AttributeCollection


class IntegrityStatus(enum.IntFlag):
    """Integrity states of an assembled non-resident stream.

    The flags classify why a stream is not fully backed by verified evidence. They are deliberately
    kept separate so that forensics tooling can tell explicit on-disk zero filling from missing or
    conflicting data:

    - :attr:`SPARSE`: the range is an explicit sparse (zero-filled) run declared in a datarun.
    - :attr:`GAP`: no fragment covers the range at all; this is an evidence gap, not a sparse run.
    - :attr:`OVERLAP`: two fragments claim the same VCN range; the conflicting bytes are not trusted.
    - :attr:`FOREIGN_FRAGMENT`: a fragment does not belong to the base record (base reference,
      attribute type/name or reference sequence number mismatch).
    - :attr:`ATTRIBUTE_LIST_MISSING`: a multi-fragment stream has no parseable ``$ATTRIBUTE_LIST``
      to cross-check the fragments against.
    """

    OK = 0
    SPARSE = enum.auto()
    GAP = enum.auto()
    OVERLAP = enum.auto()
    FOREIGN_FRAGMENT = enum.auto()
    ATTRIBUTE_LIST_MISSING = enum.auto()

    @property
    def complete(self) -> bool:
        """Return whether the stream can be assembled without an evidence gap or conflict."""
        return not bool(self & (IntegrityStatus.GAP | IntegrityStatus.OVERLAP | IntegrityStatus.FOREIGN_FRAGMENT))


@dataclass(slots=True)
class Fragment:
    """A single non-resident attribute fragment that contributes a VCN range to a stream.

    Args:
        attribute: The :class:`~dissect.ntfs.attr.Attribute` that produced this fragment.
        segment: The MFT segment number the attribute was read from.
        sequence: The sequence number of that MFT record.
        lowest_vcn: The lowest VCN covered by this fragment.
        highest_vcn: The highest VCN covered by this fragment (inclusive).
        runs: The parsed dataruns of this fragment as ``(lcn, count)`` tuples.
        sparse_vcns: The VCN ranges declared as explicit sparse runs within this fragment.
        runlist_complete: Whether the dataruns cover every VCN claimed by this fragment.
        issues: Human readable verification issues recorded for this fragment.
    """

    attribute: Attribute
    segment: int | None
    sequence: int | None
    lowest_vcn: int
    highest_vcn: int
    runs: list[tuple[int | None, int]]
    sparse_vcns: list[tuple[int, int]] = field(default_factory=list)
    runlist_complete: bool = True
    issues: list[str] = field(default_factory=list)

    @property
    def vcn_count(self) -> int:
        """Return the amount of clusters (VCNs) this fragment claims to cover."""
        return self.highest_vcn - self.lowest_vcn + 1

    def covers(self, vcn: int) -> bool:
        """Return whether this fragment claims the given VCN."""
        return self.lowest_vcn <= vcn <= self.highest_vcn


@dataclass(slots=True)
class StreamIntegrity:
    """The verification result of assembling a non-resident stream from MFT fragments.

    Args:
        status: The combined :class:`IntegrityStatus` flags of the assembled stream.
        fragments: The fragments that contributed to the stream, ordered by ``lowest_vcn``.
        issues: Human readable descriptions of every verification problem encountered.
        sparse_vcns: The VCN ranges that are explicitly zero-filled via sparse dataruns.
        gap_vcns: The VCN ranges without any backing fragment (evidence gaps).
        overlap_vcns: The VCN ranges claimed by more than one fragment.
        expected_vcns: The amount of clusters the stream is expected to span.
        cluster_size: The cluster size used to translate VCN ranges into byte offsets.
    """

    status: IntegrityStatus = IntegrityStatus.OK
    fragments: list[Fragment] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    sparse_vcns: list[tuple[int, int]] = field(default_factory=list)
    gap_vcns: list[tuple[int, int]] = field(default_factory=list)
    overlap_vcns: list[tuple[int, int]] = field(default_factory=list)
    expected_vcns: int = 0
    cluster_size: int = 0

    @property
    def complete(self) -> bool:
        """Return whether the stream is fully backed by verified, non-conflicting evidence."""
        return self.status.complete and not self.issues

    @property
    def verified(self) -> bool:
        """Return whether verification passed without any issue at all."""
        return self.status is IntegrityStatus.OK and not self.issues

    def source_at(self, offset: int) -> list[Fragment]:
        """Return the verified fragments that claim the cluster containing the given byte offset.

        Args:
            offset: A byte offset within the stream.

        Returns:
            The fragments covering the underlying VCN. More than one fragment indicates an overlap,
            an empty list means the offset falls in an evidence gap, a sparse or a conflict range.
        """
        vcn = offset // self.cluster_size
        return [fragment for fragment in self.fragments if fragment.covers(vcn)]

    def describe_ranges(self) -> dict[str, list[tuple[int, int]]]:
        """Return the classified VCN ranges, keyed by their integrity classification."""
        return {
            "sparse": self.sparse_vcns,
            "gap": self.gap_vcns,
            "overlap": self.overlap_vcns,
        }


class VerifiedRunlistStream(RunlistStream):
    """A :class:`~dissect.util.stream.RunlistStream` carrying the :class:`StreamIntegrity` of its data.

    Reads from ranges that are not backed by a single verified fragment (evidence gaps and overlap
    conflicts) return explicit zero bytes. This guarantees the caller never silently receives data
    from an arbitrary fragment, while still allowing the rest of a damaged stream to be recovered.
    Sparse runs and these zero-filled untrusted ranges are distinguished through :attr:`integrity`.

    Args:
        fh: The source file-like object (the raw volume).
        runlist: The verified runlist, with ``None`` runs for gap and conflict ranges.
        size: The size of the stream.
        block_size: The cluster size.
        integrity: The verification result this stream was built from.
    """

    def __init__(
        self,
        fh: BinaryIO,
        runlist: list[tuple[int | None, int]],
        size: int,
        block_size: int,
        integrity: StreamIntegrity,
    ):
        super().__init__(fh, runlist, size, block_size)
        self.integrity = integrity


def verify_stream(collection: AttributeCollection, strict: bool = False) -> StreamIntegrity:
    """Verify and assemble the non-resident fragments of an attribute collection into an integrity report.

    The verification cross-checks every fragment against the base record's ``$ATTRIBUTE_LIST`` and
    validates the ``LowestVcn``/``HighestVcn`` chain, so that damaged fragments can never be stitched
    together into a seemingly complete file:

    - The base record ownership, attribute type code and attribute name of every fragment must match
      the corresponding ``$ATTRIBUTE_LIST`` entry.
    - The reference sequence number in the ``$ATTRIBUTE_LIST`` entry must match the sequence number of
      the referenced extension record; a mismatch means the extension record has been reused.
    - Consecutive fragments must connect exactly (``next.LowestVcn == prev.HighestVcn + 1``). A missing
      range is an evidence :attr:`~IntegrityStatus.GAP`, never confused with an explicit sparse run.
    - Overlapping VCN ranges are flagged as :attr:`~IntegrityStatus.OVERLAP`; no fragment is preferred
      over another by sort order.

    Args:
        collection: The :class:`~dissect.ntfs.util.AttributeCollection` holding the stream fragments.
        strict: Raise :class:`~dissect.ntfs.exceptions.StreamVerificationError` instead of returning a
            report when the stream cannot be assembled completely.

    Raises:
        StreamVerificationError: If ``strict=True`` and verification finds a gap, overlap or a fragment
            that does not verifiably belong to the stream.
    """
    fragments = [_build_fragment(attr) for attr in collection if not attr.header.resident]
    fragments.sort(key=lambda fragment: fragment.lowest_vcn)

    integrity = StreamIntegrity(fragments=fragments)

    base_record = _base_record(collection)
    cluster_size = base_record.ntfs.cluster_size if base_record and base_record.ntfs else 0
    integrity.cluster_size = cluster_size

    attribute_list = _attribute_list(base_record)
    if attribute_list is None and len(fragments) > 1:
        integrity.status |= IntegrityStatus.ATTRIBUTE_LIST_MISSING
        integrity.issues.append(
            "Multi-fragment stream has no $ATTRIBUTE_LIST to verify extension record references against"
        )

    entries = _index_entries(attribute_list) if attribute_list is not None else {}

    for fragment in fragments:
        _verify_fragment(fragment, base_record, entries, integrity)

    _verify_vcn_chain(fragments, integrity, cluster_size)
    integrity.expected_vcns = _expected_vcns(fragments, cluster_size)

    if strict and not integrity.complete:
        detail = "; ".join(integrity.issues) or "stream could not be assembled completely"
        raise StreamVerificationError(f"Stream verification failed: {detail}")

    return integrity


def build_verified_stream(
    collection: AttributeCollection,
    fh: BinaryIO,
    size: int,
    strict: bool = False,
) -> VerifiedRunlistStream:
    """Build a :class:`VerifiedRunlistStream` from a verified attribute collection.

    Only VCN ranges backed by exactly one verified fragment contribute real dataruns. Gap and overlap
    ranges are inserted as sparse runs so reads return explicit zero bytes instead of data picked from
    an arbitrary fragment.

    Args:
        collection: The attribute collection holding the stream fragments.
        fh: The raw volume file-like object to read allocated clusters from.
        size: The declared stream size.
        strict: Raise :class:`~dissect.ntfs.exceptions.StreamVerificationError` on an incomplete stream.

    Raises:
        StreamVerificationError: If ``strict=True`` and the stream is not fully verified.
    """
    integrity = verify_stream(collection, strict=strict)
    runlist = _verified_runlist(integrity)
    return VerifiedRunlistStream(fh, runlist, size, integrity.cluster_size, integrity)


def _build_fragment(attr: Attribute) -> Fragment:
    header = attr.header
    runs = header.dataruns()

    fragment = Fragment(
        attribute=attr,
        segment=attr.record.segment if attr.record else None,
        sequence=attr.record.header.SequenceNumber if attr.record and attr.record.header else None,
        lowest_vcn=header.lowest_vcn,
        highest_vcn=header.highest_vcn,
        runs=runs,
    )

    vcn = header.lowest_vcn
    runlist_vcns = 0
    for lcn, count in runs:
        if lcn is None:
            fragment.sparse_vcns.append((vcn, vcn + count - 1))
        vcn += count
        runlist_vcns += count

    if runlist_vcns != fragment.vcn_count or fragment.lowest_vcn > fragment.highest_vcn:
        fragment.runlist_complete = False
        fragment.issues.append(
            f"Dataruns of segment {fragment.segment} cover {runlist_vcns} VCNs but the header claims "
            f"{fragment.vcn_count} VCNs ({fragment.lowest_vcn}..{fragment.highest_vcn})"
        )

    return fragment


def _base_record(collection: AttributeCollection) -> MftRecord | None:
    """Resolve the base MFT record that owns the fragments in this collection.

    The collection only contains the stream's fragments, which usually live in extension records and
    therefore do not include the base record holding the ``$ATTRIBUTE_LIST``. Extension records point
    back to their base record through ``BaseFileRecordSegment``; resolve that reference through the MFT
    and fall back to any record that is its own base.
    """
    candidate: MftRecord | None = None
    for attr in collection:
        record = attr.record
        if record is None:
            continue

        base_ref = record.header.BaseFileRecordSegment
        base_segment = segment_reference(base_ref)
        if base_segment == 0 and base_ref.SequenceNumber == 0:
            # This fragment lives in the base record itself.
            return record

        if record.ntfs is not None and record.ntfs.mft is not None:
            try:
                base_record = record.ntfs.mft.get(base_segment)
            except Exception:
                candidate = candidate or record
                continue
            base_base = base_record.header.BaseFileRecordSegment
            if segment_reference(base_base) == 0 and base_base.SequenceNumber == 0:
                return base_record

        candidate = candidate or record

    return candidate


def _attribute_list(base_record: MftRecord | None) -> AttributeList | None:
    if base_record is None:
        return None
    for attr in base_record.attributes[ATTRIBUTE_TYPE_CODE.ATTRIBUTE_LIST]:
        if attr.attribute is not None:
            return attr.attribute
    return None


def _index_entries(attribute_list: AttributeList) -> dict[tuple[int, int], object]:
    # Index the raw entries directly: unlike referenced_attributes(), this retains entries that point at
    # the base record itself (e.g. a LowestVcn 0 fragment stored in the base record) and never skips one.
    entries = {}
    for entry in attribute_list.entries:
        entries[(int(entry.AttributeTypeCode), entry.LowestVcn)] = entry
    return entries


def _verify_fragment(
    fragment: Fragment,
    base_record: MftRecord | None,
    entries: dict[tuple[int, int], object],
    integrity: StreamIntegrity,
) -> None:
    attr = fragment.attribute
    header = attr.header
    record = attr.record

    if not fragment.runlist_complete:
        integrity.status |= IntegrityStatus.FOREIGN_FRAGMENT
        integrity.issues.extend(fragment.issues)

    if record is None or base_record is None:
        return

    base_segment = segment_reference(record.header.BaseFileRecordSegment)
    is_base_record = fragment.segment == base_record.segment and base_segment == 0
    if not is_base_record and base_segment != base_record.segment:
        integrity.status |= IntegrityStatus.FOREIGN_FRAGMENT
        message = (
            f"Fragment {header.type.name} VCN {fragment.lowest_vcn}..{fragment.highest_vcn} lives in segment "
            f"{fragment.segment} whose base record reference is {base_segment} but the stream base record is "
            f"segment {base_record.segment}"
        )
        fragment.issues.append(message)
        integrity.issues.append(message)

    if not entries:
        # Nothing to cross-check against; a missing attribute list was already flagged when relevant.
        return

    entry = entries.get((header.type.value, fragment.lowest_vcn))
    if entry is None:
        integrity.status |= IntegrityStatus.FOREIGN_FRAGMENT
        message = (
            f"No $ATTRIBUTE_LIST entry references {header.type.name} at LowestVcn {fragment.lowest_vcn} "
            f"(segment {fragment.segment})"
        )
        fragment.issues.append(message)
        integrity.issues.append(message)
        return

    entry_name = _entry_name(entry)
    if entry_name != header.name:
        integrity.status |= IntegrityStatus.FOREIGN_FRAGMENT
        message = (
            f"Attribute name mismatch for {header.type.name} VCN {fragment.lowest_vcn}: $ATTRIBUTE_LIST entry "
            f"declares {entry_name!r} but the fragment in segment {fragment.segment} is named {header.name!r}"
        )
        fragment.issues.append(message)
        integrity.issues.append(message)

    referenced_segment = segment_reference(entry.SegmentReference)
    if referenced_segment != fragment.segment:
        integrity.status |= IntegrityStatus.FOREIGN_FRAGMENT
        message = (
            f"$ATTRIBUTE_LIST entry for {header.type.name} VCN {fragment.lowest_vcn} references segment "
            f"{referenced_segment} but the fragment was read from segment {fragment.segment}"
        )
        fragment.issues.append(message)
        integrity.issues.append(message)

    if entry.SegmentReference.SequenceNumber != fragment.sequence:
        integrity.status |= IntegrityStatus.FOREIGN_FRAGMENT
        message = (
            f"Extension record segment {fragment.segment} has been reused: $ATTRIBUTE_LIST expects sequence "
            f"{entry.SegmentReference.SequenceNumber} but the record now has sequence {fragment.sequence}"
        )
        fragment.issues.append(message)
        integrity.issues.append(message)


def _verify_vcn_chain(fragments: list[Fragment], integrity: StreamIntegrity, cluster_size: int) -> None:
    if not fragments:
        return

    claimed: dict[int, list[Fragment]] = {}
    for fragment in fragments:
        for vcn in range(fragment.lowest_vcn, fragment.highest_vcn + 1):
            claimed.setdefault(vcn, []).append(fragment)

    overlaps = sorted(vcn for vcn, owners in claimed.items() if len(owners) > 1)
    for start, end in _merge_ranges(overlaps):
        integrity.overlap_vcns.append((start, end))
    if overlaps:
        integrity.status |= IntegrityStatus.OVERLAP
        for start, end in integrity.overlap_vcns:
            owners = sorted({fragment.segment for fragment in claimed[start]})
            integrity.issues.append(
                f"Overlapping fragments claim VCN {start}..{end} from segments {owners}; no fragment was preferred"
            )

    expected_end = max(fragment.highest_vcn for fragment in fragments)
    missing = sorted(vcn for vcn in range(expected_end + 1) if vcn not in claimed)
    for start, end in _merge_ranges(missing):
        integrity.gap_vcns.append((start, end))
    if missing:
        integrity.status |= IntegrityStatus.GAP
        for start, end in integrity.gap_vcns:
            integrity.issues.append(
                f"Evidence gap: no fragment covers VCN {start}..{end} "
                f"(bytes {start * cluster_size}..{(end + 1) * cluster_size - 1}); not treated as sparse"
            )

    sparse = sorted(
        vcn
        for fragment in fragments
        for start, end in fragment.sparse_vcns
        for vcn in range(start, end + 1)
    )
    for start, end in _merge_ranges(sparse):
        integrity.sparse_vcns.append((start, end))
    if sparse:
        integrity.status |= IntegrityStatus.SPARSE


def _expected_vcns(fragments: list[Fragment], cluster_size: int) -> int:
    if not fragments:
        return 0
    file_size = fragments[0].attribute.header.size
    if cluster_size:
        return (file_size + cluster_size - 1) // cluster_size
    return max(fragment.highest_vcn for fragment in fragments) + 1


def _verified_runlist(integrity: StreamIntegrity) -> list[tuple[int | None, int]]:
    if not integrity.fragments:
        return []

    conflict_vcns = {vcn for start, end in integrity.overlap_vcns for vcn in range(start, end + 1)}
    gap_vcns = {vcn for start, end in integrity.gap_vcns for vcn in range(start, end + 1)}
    untrusted = conflict_vcns | gap_vcns

    runs: list[tuple[int | None, int]] = []
    cursor = 0
    for fragment in sorted(integrity.fragments, key=lambda item: item.lowest_vcn):
        if fragment.lowest_vcn > cursor:
            runs.append((None, fragment.lowest_vcn - cursor))
        runs.extend(_fragment_runs(fragment, untrusted))
        cursor = max(cursor, fragment.highest_vcn + 1)

    if integrity.expected_vcns > cursor:
        runs.append((None, integrity.expected_vcns - cursor))

    return _coalesce_sparse(runs)


def _fragment_runs(
    fragment: Fragment, untrusted_vcns: set[int]
) -> list[tuple[int | None, int]]:
    runs: list[tuple[int | None, int]] = []
    vcn = fragment.lowest_vcn
    for lcn, count in fragment.runs:
        for offset in range(count):
            current_vcn = vcn + offset
            if current_vcn in untrusted_vcns:
                runs.append((None, 1))
            else:
                # Sparse runs already have lcn == None; allocated runs advance the LCN per cluster.
                runs.append((None, 1) if lcn is None else (lcn + offset, 1))
        vcn += count
    return _coalesce_sparse(runs)


def _merge_ranges(values: list[int]) -> list[tuple[int, int]]:
    if not values:
        return []
    ranges = []
    start = previous = values[0]
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        ranges.append((start, previous))
        start = previous = value
    ranges.append((start, previous))
    return ranges


def _coalesce_sparse(runs: list[tuple[int | None, int]]) -> list[tuple[int | None, int]]:
    merged: list[tuple[int | None, int]] = []
    for lcn, count in runs:
        if lcn is None and merged and merged[-1][0] is None:
            merged[-1] = (None, merged[-1][1] + count)
        else:
            merged.append((lcn, count))
    return merged


def _entry_name(entry: object) -> str:
    name_offset = entry.AttributeNameOffset
    name_length = entry.AttributeNameLength
    if not name_length:
        return ""
    # The name offset is relative to the start of the serialized attribute list entry.
    raw = entry.dumps()[name_offset : name_offset + name_length * 2]
    return raw.decode("utf-16-le")
