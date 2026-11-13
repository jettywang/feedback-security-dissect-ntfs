from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from dissect.ntfs.c_ntfs import c_ntfs
from dissect.ntfs.usnjrnl import UsnJournalGap
from dissect.ntfs.util import segment_reference

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.ntfs.usnjrnl import UsnRecord


class RenameStatus(str, Enum):
    """The correlation status of a :class:`RenameTrace`."""

    PAIRED = "paired"
    INCOMPLETE = "incomplete"


class UnpairedReason(str, Enum):
    """Why a rename event could not be correlated into a complete rename trace."""

    NEW_WITHOUT_OLD = "new_without_old"
    """A ``RENAME_NEW_NAME`` record has no preceding ``RENAME_OLD_NAME`` record for the same file reference."""

    OLD_WITHOUT_NEW = "old_without_new"
    """The journal ended before a matching ``RENAME_NEW_NAME`` record was seen."""

    JOURNAL_GAP = "journal_gap"
    """Missing journal pages lie between the ``RENAME_OLD_NAME`` record and any possible matching record."""

    OLD_SUPERSEDED = "old_superseded"
    """Another ``RENAME_OLD_NAME`` record for the same file reference arrived before a matching
    ``RENAME_NEW_NAME`` record."""

    INVALID_ORDER = "invalid_order"
    """A candidate ``RENAME_NEW_NAME`` record does not follow the pending ``RENAME_OLD_NAME`` record in USN order."""

    AMBIGUOUS_REASON = "ambiguous_reason"
    """A single record carries both ``RENAME_OLD_NAME`` and ``RENAME_NEW_NAME``."""

    PENDING_LIMIT = "pending_limit"
    """The pending-event memory limit was reached and the oldest pending rename was evicted."""


@dataclass(frozen=True, slots=True)
class RenameIdentity:
    """The identity of a file in the USN journal.

    A file is identified by the MFT segment number *and* the sequence number of its file reference. The sequence
    number distinguishes a file from an earlier file that reused the same MFT slot, so pairing must never use the
    segment number alone.

    Args:
        segment: The MFT segment (slot) number.
        sequence: The file reference sequence number.
    """

    segment: int
    sequence: int

    @classmethod
    def from_record(cls, record: UsnRecord) -> RenameIdentity:
        """Create a :class:`RenameIdentity` from a version 2 USN record.

        Args:
            record: The USN record to derive the identity from.

        Raises:
            ValueError: If the record is not a version 2 USN record.
        """
        if record.header.MajorVersion != 2:
            raise ValueError(f"Rename correlation requires version 2 USN records, got {record.header.MajorVersion}")

        reference = record.record.FileReferenceNumber
        return cls(segment_reference(reference), reference.SequenceNumber)

    @property
    def label(self) -> str:
        """Return a compact identity label, e.g. ``0x2a#7``."""
        return f"0x{self.segment:x}#{self.sequence}"


@dataclass(frozen=True, slots=True)
class RenameTrace:
    """A correlated rename, or an incomplete rename association.

    The original :class:`~dissect.ntfs.usnjrnl.UsnRecord` objects are retained on the trace. Their raw fields,
    including the original file names, parent references, reasons and USN values, are not rewritten. No full path is
    synthesized: ``old`` and ``new`` describe only what the journal records actually contain.

    Args:
        status: Whether the trace is a definite pair or an incomplete association.
        old: The ``RENAME_OLD_NAME`` record, if one was seen.
        new: The ``RENAME_NEW_NAME`` record, if one was seen.
        identity: The file reference identity the trace belongs to.
        reason: The reason an incomplete trace was not paired, if applicable.
        evidence: Human-readable, itemized evidence for the pairing decision.
        gap: The journal gap that prevented pairing, if applicable.
    """

    status: RenameStatus
    old: UsnRecord | None
    new: UsnRecord | None
    identity: RenameIdentity | None
    reason: UnpairedReason | None = None
    evidence: tuple[str, ...] = ()
    gap: UsnJournalGap | None = None

    @property
    def paired(self) -> bool:
        """Return whether this trace is a definite, complete pair."""
        return self.status is RenameStatus.PAIRED

    @property
    def old_name(self) -> str | None:
        """Return the original file name from the ``RENAME_OLD_NAME`` record."""
        return self.old.filename if self.old is not None else None

    @property
    def new_name(self) -> str | None:
        """Return the new file name from the ``RENAME_NEW_NAME`` record."""
        return self.new.filename if self.new is not None else None

    def __str__(self) -> str:
        identity = self.identity.label if self.identity is not None else "<unknown>"
        if self.paired:
            return f"<RenameTrace paired {identity} {self.old_name!r} -> {self.new_name!r}>"
        return f"<RenameTrace incomplete {identity} reason={self.reason.value if self.reason else None}>"


class RenameTracker:
    """Incrementally correlate ``RENAME_OLD_NAME`` and ``RENAME_NEW_NAME`` USN records.

    The tracker consumes :meth:`UsnJrnl.events` output, so it sees both parsed records and missing journal pages.
    Pairing uses three facts, in this order:

    1. The file reference identity, i.e. MFT segment number *and* sequence number.
    2. USN event order: the ``RENAME_OLD_NAME`` record must precede the ``RENAME_NEW_NAME`` record.
    3. Absence of a missing-page gap between the two records.

    Names and MFT slot numbers alone are never used as the file identity. When a slot is reused, the new file gets a
    different sequence number and its records are tracked independently.

    At most ``max_pending`` ``RENAME_OLD_NAME`` records are held in memory. When the limit is exceeded, the oldest
    pending record is emitted as an incomplete trace with :attr:`UnpairedReason.PENDING_LIMIT`.

    Args:
        max_pending: The maximum number of pending rename events to retain. Use ``0`` to disable retention.
    """

    def __init__(self, *, max_pending: int = 256):
        if max_pending < 0:
            raise ValueError("max_pending must be zero or greater")

        self.max_pending = max_pending
        self._pending: dict[RenameIdentity, _Pending] = {}
        self._pending_by_segment: dict[int, set[RenameIdentity]] = {}
        self._last_gap: UsnJournalGap | None = None

    @property
    def pending_count(self) -> int:
        """Return the number of currently retained pending rename events."""
        return len(self._pending)

    def feed(self, event: UsnRecord | UsnJournalGap) -> Iterator[RenameTrace]:
        """Consume one journal event and yield any rename traces it completes.

        Records unrelated to renames are consumed but not emitted, leaving the original record untouched.

        Args:
            event: A parsed USN record or a missing journal page span.
        """
        if isinstance(event, UsnJournalGap):
            self._last_gap = event
            yield from self._flush_gap(event)
            return

        yield from self._feed_record(event)

    def finish(self) -> Iterator[RenameTrace]:
        """Flush all pending rename events at the end of the journal.

        Pending records are emitted as incomplete traces with :attr:`UnpairedReason.OLD_WITHOUT_NEW`.
        """
        while self._pending:
            identity, pending = next(iter(self._pending.items()))
            self._drop(identity)
            yield RenameTrace(
                status=RenameStatus.INCOMPLETE,
                old=pending.record,
                new=None,
                identity=identity,
                reason=UnpairedReason.OLD_WITHOUT_NEW,
                evidence=(
                    *pending.evidence,
                    "the journal ended without a matching RENAME_NEW_NAME record",
                ),
            )

    def _flush_gap(self, gap: UsnJournalGap) -> Iterator[RenameTrace]:
        # A gap may contain the matching NEW_NAME record, a superseding OLD_NAME record, or events for a reused
        # slot. Pending records therefore cannot be paired conclusively and are emitted as incomplete.
        while self._pending:
            identity, pending = next(iter(self._pending.items()))
            self._drop(identity)
            yield RenameTrace(
                status=RenameStatus.INCOMPLETE,
                old=pending.record,
                new=None,
                identity=identity,
                reason=UnpairedReason.JOURNAL_GAP,
                evidence=(
                    *pending.evidence,
                    f"journal gap {gap.start_offset:#x}-{gap.end_offset:#x} follows before a matching "
                    "RENAME_NEW_NAME record",
                ),
                gap=gap,
            )

    def _feed_record(self, record: UsnRecord) -> Iterator[RenameTrace]:
        has_old = _has_reason(record, c_ntfs.USN_REASON.RENAME_OLD_NAME)
        has_new = _has_reason(record, c_ntfs.USN_REASON.RENAME_NEW_NAME)

        if not has_old and not has_new:
            return

        # A gap stays relevant until a rename record consumes it: unrelated records in between do not rule out
        # that the missing page contained the RENAME_OLD_NAME for a later orphan RENAME_NEW_NAME.
        last_gap, self._last_gap = self._last_gap, None

        identity = RenameIdentity.from_record(record)
        base_evidence = (
            f"file reference {identity.label}: segment {identity.segment}, sequence {identity.sequence}",
        )

        if has_old and has_new:
            yield RenameTrace(
                status=RenameStatus.INCOMPLETE,
                old=record,
                new=None,
                identity=identity,
                reason=UnpairedReason.AMBIGUOUS_REASON,
                evidence=(
                    *base_evidence,
                    f"usn {record.Usn} carries both RENAME_OLD_NAME and RENAME_NEW_NAME in one record",
                ),
            )
            return

        if has_new:
            yield from self._feed_new(record, identity, base_evidence, last_gap)
            return

        yield from self._feed_old(record, identity, base_evidence)

    def _feed_old(
        self, record: UsnRecord, identity: RenameIdentity, base_evidence: tuple[str, ...]
    ) -> Iterator[RenameTrace]:
        superseded = self._pending.get(identity)
        if superseded is not None:
            self._drop(identity)
            yield RenameTrace(
                status=RenameStatus.INCOMPLETE,
                old=superseded.record,
                new=None,
                identity=identity,
                reason=UnpairedReason.OLD_SUPERSEDED,
                evidence=(
                    *superseded.evidence,
                    f"a later RENAME_OLD_NAME record (usn {record.Usn}) arrived before a matching "
                    "RENAME_NEW_NAME record",
                ),
            )

        evidence = list(base_evidence)
        reused = [
            other
            for other in self._pending_by_segment.get(identity.segment, ())
            if other.sequence != identity.sequence
        ]
        if reused:
            generations = ", ".join(sorted(other.label for other in reused))
            evidence.append(
                f"segment {identity.segment} is also pending for {generations}; "
                "different sequence numbers are different files (slot reuse), so they are tracked separately"
            )

        pending = _Pending(record=record, evidence=tuple(evidence))
        self._pending[identity] = pending
        self._pending_by_segment.setdefault(identity.segment, set()).add(identity)

        if len(self._pending) > self.max_pending:
            evicted_identity, evicted = next(iter(self._pending.items()))
            self._drop(evicted_identity)
            yield RenameTrace(
                status=RenameStatus.INCOMPLETE,
                old=evicted.record,
                new=None,
                identity=evicted_identity,
                reason=UnpairedReason.PENDING_LIMIT,
                evidence=(
                    *evicted.evidence,
                    f"pending limit of {self.max_pending} rename events exceeded; oldest pending event evicted",
                ),
            )

    def _feed_new(
        self,
        record: UsnRecord,
        identity: RenameIdentity,
        base_evidence: tuple[str, ...],
        gap: UsnJournalGap | None,
    ) -> Iterator[RenameTrace]:
        pending = self._pending.get(identity)
        if pending is None:
            evidence = list(base_evidence)
            reused = [
                other
                for other in self._pending_by_segment.get(identity.segment, ())
                if other.sequence != identity.sequence
            ]
            if reused:
                generations = ", ".join(sorted(other.label for other in reused))
                evidence.append(
                    f"segment {identity.segment} is pending for {generations}, a different file generation; "
                    "no RENAME_OLD_NAME exists for this sequence"
                )
            evidence.append(f"no pending RENAME_OLD_NAME for usn {record.Usn} on this file reference")
            if gap is not None:
                evidence.append(
                    f"the preceding journal gap {gap.start_offset:#x}-{gap.end_offset:#x} may have "
                    "contained the RENAME_OLD_NAME record; no complete rename is inferred"
                )

            yield RenameTrace(
                status=RenameStatus.INCOMPLETE,
                old=None,
                new=record,
                identity=identity,
                reason=UnpairedReason.NEW_WITHOUT_OLD,
                evidence=tuple(evidence),
                gap=gap,
            )
            return

        old_usn = pending.record.Usn
        if record.Usn <= old_usn:
            self._drop(identity)
            yield RenameTrace(
                status=RenameStatus.INCOMPLETE,
                old=pending.record,
                new=record,
                identity=identity,
                reason=UnpairedReason.INVALID_ORDER,
                evidence=(
                    *pending.evidence,
                    f"RENAME_NEW_NAME usn {record.Usn} does not follow RENAME_OLD_NAME usn {old_usn}; "
                    "event order is inconclusive",
                ),
            )
            return

        self._drop(identity)
        yield RenameTrace(
            status=RenameStatus.PAIRED,
            old=pending.record,
            new=record,
            identity=identity,
            evidence=(
                *pending.evidence,
                f"RENAME_OLD_NAME usn {old_usn} precedes RENAME_NEW_NAME usn {record.Usn}",
                f"journal offsets {pending.record.offset:#x} -> {record.offset:#x} have no missing-page gap "
                "between them",
                f"rename {pending.record.filename!r} -> {record.filename!r}",
                f"parent reference {_parent_label(pending.record)} -> {_parent_label(record)}",
            ),
        )

    def _drop(self, identity: RenameIdentity) -> None:
        self._pending.pop(identity)
        identities = self._pending_by_segment.get(identity.segment)
        if identities is not None:
            identities.discard(identity)
            if not identities:
                del self._pending_by_segment[identity.segment]


@dataclass(slots=True)
class _Pending:
    record: UsnRecord
    evidence: tuple[str, ...]


def track_renames(
    events: Iterable[UsnRecord | UsnJournalGap], *, max_pending: int = 256
) -> Iterator[RenameTrace]:
    """Correlate rename events from an iterable of USN journal events.

    This is a streaming helper around :class:`RenameTracker`. Every original event is consumed in order; completed
    and incomplete rename traces are yielded as soon as a decision can be made.

    Args:
        events: An iterable of USN records and journal gaps, typically :meth:`UsnJrnl.events`.
        max_pending: The maximum number of pending rename events to retain.
    """
    tracker = RenameTracker(max_pending=max_pending)
    for event in events:
        yield from tracker.feed(event)
    yield from tracker.finish()


def _has_reason(record: UsnRecord, reason: c_ntfs.USN_REASON) -> bool:
    return bool(int(record.Reason) & int(reason))


def _parent_label(record: UsnRecord) -> str:
    reference = record.record.ParentFileReferenceNumber
    return f"0x{segment_reference(reference):x}#{reference.SequenceNumber}"
