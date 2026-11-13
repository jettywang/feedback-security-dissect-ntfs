"""Read-only forensic cross-checking of NTFS allocation metadata.

This module reconciles three independent sources of allocation information:

1. The volume ``$Bitmap`` (segment 6), whose bits claim whether a data cluster
   is allocated on disk.
2. The MFT record bitmap (the ``$BITMAP`` attribute of the ``$MFT`` file),
   whose bits claim whether an MFT segment is still in use.
3. The non-resident runlists of selected files, which claim the physical
   clusters (LCNs) that hold attribute data.

Three distinct facts are kept separate and never collapsed into one another:

- A record being *in use* (MFT bitmap / record flags).
- A data cluster being *allocated* (volume ``$Bitmap``).
- A file's content being *recoverable* (its runlist is intact and the clusters
  are not shared).

Hard links reference a single MFT record, so they never count as duplicated
allocation: claims are keyed by record segment number. Sparse runs
(``lcn is None``) occupy no physical clusters and are not checked against the
volume bitmap.

Everything in this module is strictly read-only. It only observes and reports;
it never repairs the volume, rewrites a bitmap, or asserts that an
inconsistency is the result of malicious tampering. A contradiction is evidence
of a discrepancy between metadata structures, nothing more.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING

from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_TYPE_CODE,
    FILE_RECORD_SEGMENT_IN_USE,
)
from dissect.ntfs.exceptions import BrokenMftError

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from dissect.ntfs.mft import MftRecord
    from dissect.ntfs.ntfs import NTFS


class AllocationIssue:
    """Stable string identifiers for the kinds of discrepancies that can be observed.

    These are evidence labels, not verdicts. They do not imply a cause and must
    not be interpreted as proof of tampering.
    """

    # Cluster-level issues.
    CROSS_LINKED = "cross_linked_cluster"
    FREED_BUT_REFERENCED = "freed_cluster_referenced"
    BITMAP_UNKNOWN = "bitmap_bit_unknown"
    # Record-level issues.
    RECORD_FLAGS_CONFLICT = "record_flags_conflict"
    RECORD_BITMAP_UNKNOWN = "record_bitmap_unknown"
    # Truncation / coverage issues.
    VOLUME_BITMAP_TRUNCATED = "volume_bitmap_truncated"
    MFT_BITMAP_TRUNCATED = "mft_bitmap_truncated"
    # Structural issues found while parsing.
    RUNLIST_PARSE_ERROR = "runlist_parse_error"


# Issues that represent a hard contradiction rather than missing information.
_CONFLICT_ISSUES = frozenset(
    {
        AllocationIssue.CROSS_LINKED,
        AllocationIssue.FREED_BUT_REFERENCED,
        AllocationIssue.RECORD_FLAGS_CONFLICT,
    }
)


@dataclass(frozen=True, slots=True)
class ClusterClaim:
    """A single cluster (LCN) claimed by one non-resident attribute.

    Args:
        lcn: Logical cluster number on disk.
        segment: MFT segment number of the owning record.
        attribute_type: The attribute type code containing the run.
        stream_name: The name of the stream (empty string for the default stream).
        vcn: Virtual cluster number within the stream this LCN corresponds to.
        reference: A human readable reference to the owning file or record.
    """

    lcn: int
    segment: int
    attribute_type: ATTRIBUTE_TYPE_CODE
    stream_name: str
    vcn: int
    reference: str


@dataclass(frozen=True, slots=True)
class AllocationRange:
    """A contiguous, inclusive range of clusters or segments with a shared observation.

    Args:
        start: First unit (LCN or segment number) in the range.
        end: Last unit (inclusive) in the range.
        issue: The :class:`AllocationIssue` observed across the range.
        references: File/record references involved in the observation.
    """

    start: int
    end: int
    issue: str
    references: frozenset[str] = frozenset()

    @property
    def length(self) -> int:
        """Return the number of units covered by this range."""
        return self.end - self.start + 1


@dataclass(frozen=True, slots=True)
class RecordStatus:
    """The reconciled status of a single MFT segment.

    Args:
        segment: MFT segment number.
        flag_in_use: Whether the record header has the in-use flag set.
        bitmap_in_use: Whether the MFT bitmap marks the segment as in use, or
            ``None`` when the bitmap does not cover this segment.
        reference: A human readable reference to the record.
    """

    segment: int
    flag_in_use: bool
    bitmap_in_use: bool | None
    reference: str

    @property
    def in_use(self) -> bool:
        """Return whether this record is observed to be in use.

        The record header flag is the authoritative on-disk claim for the
        record itself; the bitmap is a separate claim that is cross-checked
        against it.
        """
        return self.flag_in_use

    @property
    def issues(self) -> tuple[str, ...]:
        """Return the issues observed for this record."""
        if self.bitmap_in_use is None:
            return (AllocationIssue.RECORD_BITMAP_UNKNOWN,)
        if self.bitmap_in_use != self.flag_in_use:
            return (AllocationIssue.RECORD_FLAGS_CONFLICT,)
        return ()


@dataclass(frozen=True, slots=True)
class ClusterAudit:
    """The per-cluster reconciliation of all three allocation facts.

    Args:
        lcn: Logical cluster number.
        bitmap_allocated: Whether the volume bitmap marks the cluster allocated,
            or ``None`` when the bitmap does not cover this cluster.
        claims: The claims made against this cluster by active (in-use) records.
        deleted_claims: Claims made by records that are no longer in use.
        issues: The issues observed for this cluster.
    """

    lcn: int
    bitmap_allocated: bool | None
    claims: tuple[ClusterClaim, ...]
    deleted_claims: tuple[ClusterClaim, ...]
    issues: tuple[str, ...]

    @property
    def referenced(self) -> bool:
        """Return whether any record (active or deleted) references this cluster."""
        return bool(self.claims or self.deleted_claims)

    @property
    def allocated(self) -> bool:
        """Return whether the cluster is allocated according to the volume bitmap."""
        return self.bitmap_allocated is True

    @property
    def cross_linked(self) -> bool:
        """Return whether multiple distinct active records claim this cluster."""
        return len({claim.segment for claim in self.claims}) > 1

    @property
    def recoverable(self) -> bool:
        """Return whether file content at this cluster is potentially recoverable.

        Content is potentially recoverable when a single active record still
        references the cluster, the bitmap marks it allocated, and no other
        active record shares the cluster. A freed cluster referenced only by a
        deleted record is a *carving* candidate, not an allocated file, and is
        therefore not reported as recoverable here. Bitmap truncation makes the
        allocation fact unknowable and likewise prevents a positive recovery
        claim.
        """
        if self.bitmap_allocated is not True:
            return False
        if len({claim.segment for claim in self.claims}) != 1:
            return False
        return not self.issues

    @property
    def references(self) -> frozenset[str]:
        """Return all file/record references involved with this cluster."""
        return frozenset(claim.reference for claim in self.claims + self.deleted_claims)


@dataclass(frozen=True, slots=True)
class ParseError:
    """A structural problem encountered while parsing a record or runlist.

    Args:
        segment: The MFT segment involved, or ``None`` when unavailable.
        reference: A human readable reference to the record or stream.
        detail: A human readable description of the parse failure.
    """

    segment: int | None
    reference: str
    detail: str


@dataclass(frozen=True, slots=True)
class AllocationReport:
    """The result of an allocation cross-check.

    All findings are observations. The report offers no repair operation and no
    judgment about intent.

    Args:
        record_statuses: Reconciled status for every scanned MFT segment.
        cluster_audits: Per-cluster reconciliation for every audited cluster.
        ranges: Contiguous ranges of clusters carrying an issue.
        volume_bitmap_issue: Truncation issue for the volume bitmap, if any.
        mft_bitmap_issue: Truncation issue for the MFT bitmap, if any.
        parse_errors: Structural parse failures encountered during the scan.
    """

    record_statuses: tuple[RecordStatus, ...]
    cluster_audits: tuple[ClusterAudit, ...]
    ranges: tuple[AllocationRange, ...]
    volume_bitmap_issue: AllocationRange | None
    mft_bitmap_issue: AllocationRange | None
    parse_errors: tuple[ParseError, ...]

    def issues(self) -> frozenset[str]:
        """Return the set of distinct issue identifiers present in the report."""
        found = {issue for audit in self.cluster_audits for issue in audit.issues}
        found.update(issue for status in self.record_statuses for issue in status.issues)
        for range_item in self.ranges:
            found.add(range_item.issue)
        if self.volume_bitmap_issue:
            found.add(self.volume_bitmap_issue.issue)
        if self.mft_bitmap_issue:
            found.add(self.mft_bitmap_issue.issue)
        if self.parse_errors:
            found.add(AllocationIssue.RUNLIST_PARSE_ERROR)
        return frozenset(found)

    def has_conflicts(self) -> bool:
        """Return whether any hard metadata contradiction was observed."""
        return bool(self.issues() & _CONFLICT_ISSUES)

    def ranges_for(self, issue: str) -> tuple[AllocationRange, ...]:
        """Return all contiguous ranges carrying the given issue."""
        return tuple(range_item for range_item in self.ranges if range_item.issue == issue)

    def audit(self, lcn: int) -> ClusterAudit | None:
        """Return the :class:`ClusterAudit` for a cluster, if it was audited."""
        for cluster_audit in self.cluster_audits:
            if cluster_audit.lcn == lcn:
                return cluster_audit
        return None

    def record(self, segment: int) -> RecordStatus | None:
        """Return the :class:`RecordStatus` for a segment, if it was scanned."""
        for status in self.record_statuses:
            if status.segment == segment:
                return status
        return None


class _Bitmap:
    """Minimal read-only view over an NTFS-style bitmap (LSB of first byte first)."""

    __slots__ = ("_data",)

    def __init__(self, data: bytes):
        self._data = data

    def __len__(self) -> int:
        return len(self._data) * 8

    def get(self, index: int) -> bool | None:
        """Return the bit at ``index``, or ``None`` when outside the bitmap."""
        byte_index = index >> 3
        if byte_index >= len(self._data):
            return None
        return bool(self._data[byte_index] & (1 << (index & 7)))


def _merge_ranges(items: Iterable[tuple[int, str, frozenset[str]]]) -> tuple[AllocationRange, ...]:
    """Merge ``(unit, issue, references)`` observations into contiguous ranges per issue."""
    ranges: list[AllocationRange] = []
    for unit, issue, references in sorted(items, key=lambda item: (item[1], item[0])):
        if ranges and ranges[-1].issue == issue and ranges[-1].end + 1 == unit:
            previous = ranges[-1]
            ranges[-1] = AllocationRange(
                previous.start,
                unit,
                issue,
                previous.references | references,
            )
        else:
            ranges.append(AllocationRange(unit, unit, issue, frozenset(references)))
    return tuple(sorted(ranges, key=lambda range_item: (range_item.start, range_item.issue)))


def _record_reference(record: MftRecord) -> str:
    """Build a stable, best-effort human reference for a record."""
    try:
        name = record.filename or record.full_path()
    except Exception:  # noqa: BLE001 - reference building must never break the scan
        name = None
    return name if name else f"<segment {record.segment}>"


class AllocationCrossChecker:
    """Cross-check NTFS allocation metadata in a strictly read-only fashion.

    The checker is decoupled from a live volume so it can be driven by small,
    synthetic bitmaps and runlists in unit tests without a disk image:

    - Bitmaps are plain :class:`bytes` in NTFS bitmap order.
    - Runlists are the same ``(lcn, count)`` tuples produced by
      :meth:`AttributeHeader.dataruns <dissect.ntfs.attr.AttributeHeader.dataruns>`,
      where a sparse run has ``lcn is None``.

    Args:
        volume_bitmap: Bytes of the volume ``$Bitmap``, or ``None`` if unavailable.
        mft_bitmap: Bytes of the ``$MFT`` ``$BITMAP`` attribute, or ``None``.
        total_clusters: Total number of clusters on the volume, used to detect a
            truncated volume bitmap. ``None`` means unknown.
        mft_record_count: Number of MFT segments, used to detect a truncated MFT
            bitmap. ``None`` means unknown.
    """

    def __init__(
        self,
        volume_bitmap: bytes | None = None,
        mft_bitmap: bytes | None = None,
        total_clusters: int | None = None,
        mft_record_count: int | None = None,
    ):
        self._volume_bitmap = _Bitmap(volume_bitmap) if volume_bitmap is not None else None
        self._mft_bitmap = _Bitmap(mft_bitmap) if mft_bitmap is not None else None
        self._total_clusters = total_clusters
        self._mft_record_count = mft_record_count

        self._records: dict[int, MftRecord] = {}
        self._manual_claims: list[ClusterClaim] = []
        self._manual_statuses: dict[int, bool] = {}
        self._manual_references: dict[int, str] = {}
        self._sparse_clusters = 0
        self._parse_errors: list[ParseError] = []

    @cached_property
    def volume_bitmap_size(self) -> int | None:
        """Return the number of clusters covered by the volume bitmap."""
        return len(self._volume_bitmap) if self._volume_bitmap else None

    @cached_property
    def mft_bitmap_size(self) -> int | None:
        """Return the number of segments covered by the MFT bitmap."""
        return len(self._mft_bitmap) if self._mft_bitmap else None

    def add_record(self, record: MftRecord) -> None:
        """Register an :class:`~dissect.ntfs.mft.MftRecord` and its non-resident runlists.

        Only ``$DATA`` attributes are considered by default; hard links share a
        segment number and therefore never duplicate claims. Sparse runs are
        counted but occupy no cluster.

        Args:
            record: The MFT record to register.
        """
        self._records[record.segment] = record
        self._manual_references.setdefault(record.segment, _record_reference(record))
        in_use = bool(record.header.Flags & FILE_RECORD_SEGMENT_IN_USE)

        for attribute in record.attributes[ATTRIBUTE_TYPE_CODE.DATA]:
            if attribute.header.resident:
                continue
            try:
                runlist = attribute.dataruns()
            except Exception as exc:  # noqa: BLE001 - keep collecting evidence
                detail = f"failed to parse runlist of {attribute.header.type.name} {attribute.header.name!r}: {exc}"
                self._parse_errors.append(
                    ParseError(
                        record.segment,
                        _record_reference(record),
                        detail,
                    )
                )
                continue
            self.add_runlist(
                runlist,
                segment=record.segment,
                attribute_type=attribute.header.type,
                stream_name=attribute.header.name,
                reference=_record_reference(record),
                in_use=in_use,
            )

    def add_runlist(
        self,
        runlist: Sequence[tuple[int | None, int]],
        segment: int,
        attribute_type: ATTRIBUTE_TYPE_CODE = ATTRIBUTE_TYPE_CODE.DATA,
        stream_name: str = "",
        reference: str | None = None,
        in_use: bool = True,
    ) -> None:
        """Register a raw runlist, optionally without a backing MFT record.

        This is the synthetic entry point used by tests and by tooling that
        already holds decoded runlists.

        Args:
            runlist: ``(lcn, count)`` tuples; ``lcn is None`` marks a sparse run.
            segment: The owning MFT segment number.
            attribute_type: The attribute type the runlist belongs to.
            stream_name: The stream name (empty string for the default stream).
            reference: Human readable reference; defaults to the segment number.
            in_use: Whether the owning record is still in use. Freed records'
                claims are tracked separately as stale references.
        """
        reference = reference or f"<segment {segment}>"
        self._manual_references.setdefault(segment, reference)
        self._manual_statuses[segment] = in_use

        vcn = 0
        for lcn, count in runlist:
            if count <= 0:
                continue
            if lcn is None:
                self._sparse_clusters += count
            else:
                for offset in range(count):
                    self._manual_claims.append(
                        ClusterClaim(
                            lcn=lcn + offset,
                            segment=segment,
                            attribute_type=attribute_type,
                            stream_name=stream_name,
                            vcn=vcn + offset,
                            reference=reference,
                        )
                    )
            vcn += count

    @classmethod
    def from_ntfs(
        cls,
        ntfs: NTFS,
        segments: Iterable[int] | None = None,
        attr_types: Iterable[ATTRIBUTE_TYPE_CODE] = (ATTRIBUTE_TYPE_CODE.DATA,),
    ) -> AllocationCrossChecker:
        """Build a checker from a parsed, read-only :class:`~dissect.ntfs.ntfs.NTFS` object.

        The supplied object is only read, never modified. When no volume file is
        attached (MFT-only parsing), the volume bitmap is unavailable and those
        checks are reported as indeterminate rather than guessed.

        Args:
            ntfs: A parsed NTFS object.
            segments: Segment numbers to scan. Defaults to every segment the MFT
                knows about.
            attr_types: Attribute types whose non-resident runlists are scanned.
        """
        volume_bitmap: bytes | None = None
        total_clusters: int | None = None
        if ntfs.fh and ntfs.boot_sector:
            total_clusters = ntfs.boot_sector.NumberSectors // (ntfs.cluster_size // ntfs.sector_size)
            try:
                volume_bitmap = ntfs.mft.get(6).open().read()
            except Exception:  # noqa: BLE001 - missing bitmap is evidence, not fatal
                volume_bitmap = None

        mft_bitmap: bytes | None = None
        mft_record_count: int | None = None
        if ntfs.mft:
            mft_record_count = ntfs.mft.get(0).size() // ntfs._record_size
            mft_bitmap_attributes = ntfs.mft.get(0).attributes[ATTRIBUTE_TYPE_CODE.BITMAP]
            if mft_bitmap_attributes:
                try:
                    mft_bitmap = mft_bitmap_attributes[0].data()
                except Exception:  # noqa: BLE001
                    mft_bitmap = None

        checker = cls(
            volume_bitmap=volume_bitmap,
            mft_bitmap=mft_bitmap,
            total_clusters=total_clusters,
            mft_record_count=mft_record_count,
        )

        attr_type_codes = tuple(attr_types)
        selected = list(segments) if segments is not None else list(range(mft_record_count or 0))
        for segment in selected:
            try:
                record = ntfs.mft.get(segment)
            except BrokenMftError:
                # An uninitialized slot (no "FILE" signature) is a normal free MFT
                # segment, not evidence of a contradiction; skip it silently.
                continue
            except Exception as exc:  # noqa: BLE001 - keep scanning other records
                checker._parse_errors.append(ParseError(segment, f"<segment {segment}>", str(exc)))
                continue
            checker._records[segment] = record
            checker._manual_references.setdefault(segment, _record_reference(record))
            for attr_type in attr_type_codes:
                for attribute in record.attributes[attr_type]:
                    if attribute.header.resident:
                        continue
                    try:
                        runlist = attribute.dataruns()
                    except Exception as exc:  # noqa: BLE001
                        message = f"failed to parse runlist of {attribute.header.type.name} {attribute.header.name!r}"
                        detail = f"{message}: {exc}"
                        checker._parse_errors.append(
                            ParseError(
                                segment,
                                _record_reference(record),
                                detail,
                            )
                        )
                        continue
                    checker.add_runlist(
                        runlist,
                        segment=segment,
                        attribute_type=attribute.header.type,
                        stream_name=attribute.header.name,
                        reference=_record_reference(record),
                        in_use=bool(record.header.Flags & FILE_RECORD_SEGMENT_IN_USE),
                    )

        return checker

    def _active_segments(self) -> frozenset[int]:
        active: set[int] = set()
        for segment, record in self._records.items():
            if record.header.Flags & FILE_RECORD_SEGMENT_IN_USE:
                active.add(segment)
        for segment, in_use in self._manual_statuses.items():
            if in_use:
                active.add(segment)
        return frozenset(active)

    def _record_flag_in_use(self, segment: int) -> bool:
        record = self._records.get(segment)
        if record is not None:
            return bool(record.header.Flags & FILE_RECORD_SEGMENT_IN_USE)
        return self._manual_statuses.get(segment, True)

    def _build_record_statuses(self) -> tuple[RecordStatus, ...]:
        segments = set(self._records) | set(self._manual_statuses)
        statuses: list[RecordStatus] = []
        for segment in sorted(segments):
            flag_in_use = self._record_flag_in_use(segment)
            bitmap_in_use = self._mft_bitmap.get(segment) if self._mft_bitmap else None
            statuses.append(
                RecordStatus(
                    segment=segment,
                    flag_in_use=flag_in_use,
                    bitmap_in_use=bitmap_in_use,
                    reference=self._manual_references.get(segment, f"<segment {segment}>"),
                )
            )
        return tuple(statuses)

    def _build_cluster_audits(self, active_segments: frozenset[int]) -> tuple[ClusterAudit, ...]:
        # De-duplicate identical claims (e.g. the same run added twice); distinct
        # hard links always resolve to one segment and therefore stay unique.
        unique_claims = tuple(dict.fromkeys(self._manual_claims))
        by_lcn: dict[int, list[ClusterClaim]] = {}
        max_lcn = -1
        for claim in unique_claims:
            by_lcn.setdefault(claim.lcn, []).append(claim)
            max_lcn = max(max_lcn, claim.lcn)

        audit_cap = max_lcn
        if self._total_clusters is not None:
            audit_cap = max(audit_cap, self._total_clusters - 1)
        if self._volume_bitmap:
            audit_cap = max(audit_cap, len(self._volume_bitmap) - 1)

        audits: list[ClusterAudit] = []
        for lcn in range(audit_cap + 1):
            bitmap_allocated = self._volume_bitmap.get(lcn) if self._volume_bitmap else None
            claims_here = by_lcn.get(lcn, [])
            active_claims = tuple(claim for claim in claims_here if claim.segment in active_segments)
            deleted_claims = tuple(claim for claim in claims_here if claim.segment not in active_segments)

            issues: list[str] = []
            if bitmap_allocated is None:
                issues.append(AllocationIssue.BITMAP_UNKNOWN)
            else:
                if len({claim.segment for claim in active_claims}) > 1:
                    issues.append(AllocationIssue.CROSS_LINKED)
                if bitmap_allocated is False and (active_claims or deleted_claims):
                    issues.append(AllocationIssue.FREED_BUT_REFERENCED)

            audits.append(
                ClusterAudit(
                    lcn=lcn,
                    bitmap_allocated=bitmap_allocated,
                    claims=active_claims,
                    deleted_claims=deleted_claims,
                    issues=tuple(issues),
                )
            )
        return tuple(audits)

    def _build_ranges(self, cluster_audits: Sequence[ClusterAudit]) -> tuple[AllocationRange, ...]:
        items: list[tuple[int, str, frozenset[str]]] = []
        for audit in cluster_audits:
            for issue in audit.issues:
                items.append((audit.lcn, issue, audit.references))
        return _merge_ranges(items)

    def _bitmap_truncation(self) -> tuple[AllocationRange | None, AllocationRange | None]:
        volume_issue = None
        if self._volume_bitmap and self._total_clusters is not None:
            covered = len(self._volume_bitmap)
            if covered < self._total_clusters:
                volume_issue = AllocationRange(
                    covered,
                    self._total_clusters - 1,
                    AllocationIssue.VOLUME_BITMAP_TRUNCATED,
                )

        mft_issue = None
        if self._mft_bitmap and self._mft_record_count is not None:
            covered = len(self._mft_bitmap)
            if covered < self._mft_record_count:
                mft_issue = AllocationRange(
                    covered,
                    self._mft_record_count - 1,
                    AllocationIssue.MFT_BITMAP_TRUNCATED,
                )
        return volume_issue, mft_issue

    def check(self) -> AllocationReport:
        """Run all cross-checks and return an immutable :class:`AllocationReport`."""
        record_statuses = self._build_record_statuses()
        active_segments = self._active_segments()
        cluster_audits = self._build_cluster_audits(active_segments)
        ranges = self._build_ranges(cluster_audits)
        volume_issue, mft_issue = self._bitmap_truncation()

        return AllocationReport(
            record_statuses=record_statuses,
            cluster_audits=cluster_audits,
            ranges=ranges,
            volume_bitmap_issue=volume_issue,
            mft_bitmap_issue=mft_issue,
            parse_errors=tuple(self._parse_errors),
        )

    @property
    def sparse_clusters(self) -> int:
        """Return the number of sparse (cluster-less) VCNs observed."""
        return self._sparse_clusters
