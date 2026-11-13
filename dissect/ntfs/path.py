from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Any

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, FILE_NUMBER_ROOT

if TYPE_CHECKING:
    from dissect.ntfs.c_ntfs import c_ntfs
    from dissect.ntfs.mft import Mft, MftRecord


NAMESPACE_MASK = 0x03


class FilenameNamespace(IntEnum):
    """The namespace of a ``$FILE_NAME`` attribute.

    The namespace is stored in the lower two bits of the ``Flags`` field of a ``$FILE_NAME``. A single
    record can contain a Win32 name and a DOS 8.3 name for the same hard link, so callers must not
    collapse them into one name.
    """

    POSIX = 0
    WIN32 = 1
    DOS = 2
    WIN32_AND_DOS = 3

    @classmethod
    def from_flags(cls, flags: int) -> FilenameNamespace:
        """Derive the namespace from the raw ``$FILE_NAME`` flags."""
        return cls(flags & NAMESPACE_MASK)


class PathStatus(Enum):
    """Resolution status of a path candidate."""

    RESOLVED = "resolved"
    """Every parent reference in the chain resolved to a record of the expected generation."""

    BROKEN_REFERENCE = "broken_reference"
    """A parent reference points at a record whose sequence number does not match the reference.

    This happens when a directory entry outlives its target and the MFT slot is reused by a new record.
    """

    MISSING_RECORD = "missing_record"
    """The referenced MFT record could not be read, for example because only part of the MFT is available."""

    NO_FILENAME = "no_filename"
    """The referenced record has no usable ``$FILE_NAME`` attribute to continue the chain with."""

    CYCLE = "cycle"
    """The parent chain returns to a record generation that was already visited."""

    LIMIT_EXCEEDED = "limit_exceeded"
    """The configured candidate or depth limit was reached before the chain could be completed."""


class PathReference(tuple):
    """A raw MFT segment reference: slot number and the generation (sequence number) in that slot.

    Path evidence must keep the reference exactly as it was stored, including the generation. Comparing
    it with the record actually found in the slot is what detects reused parent records.
    """

    __slots__ = ()

    def __new__(cls, segment: int, sequence: int) -> PathReference:  # noqa: PYI034
        return super().__new__(cls, (segment, sequence))

    @classmethod
    def from_reference(cls, reference: c_ntfs._MFT_SEGMENT_REFERENCE) -> PathReference:
        """Create a reference from a cstruct ``_MFT_SEGMENT_REFERENCE``."""
        return cls(
            reference.SegmentNumberLowPart | (reference.SegmentNumberHighPart << 32),
            reference.SequenceNumber,
        )

    @property
    def segment(self) -> int:
        return self[0]

    @property
    def sequence(self) -> int:
        return self[1]

    @property
    def segment_number(self) -> int:
        return self[0]

    @property
    def sequence_number(self) -> int:
        return self[1]

    def __str__(self) -> str:
        return f"0x{self.segment:x}#{self.sequence}"


@dataclass(frozen=True, slots=True)
class PathElement:
    """One ``$FILE_NAME`` in a path chain, with the raw references needed to audit the chain.

    Attributes:
        name: The file name, or ``None`` for a placeholder element describing a failed reference.
        namespace: The namespace of the file name, or ``None`` for a placeholder element.
        reference: The slot and generation of the record that owns this file name.
        parent_reference: The raw parent reference stored in this file name.
        status: The resolution status of this element.
        reason: Optional human readable detail, for example the generation actually found in a slot.
        flags: The raw ``$FILE_NAME`` flags.
    """

    name: str | None
    namespace: FilenameNamespace | None
    reference: PathReference
    parent_reference: PathReference | None
    status: PathStatus
    reason: str | None = None
    flags: int | None = None

    @property
    def segment(self) -> int:
        return self.reference.segment

    @property
    def sequence(self) -> int:
        return self.reference.sequence

    @property
    def parent_segment(self) -> int | None:
        return self.parent_reference.segment if self.parent_reference is not None else None

    @property
    def parent_sequence(self) -> int | None:
        return self.parent_reference.sequence if self.parent_reference is not None else None

    @property
    def resolved(self) -> bool:
        return self.status == PathStatus.RESOLVED and self.name is not None


def placeholder(reference: PathReference, status: PathStatus) -> str:
    """Render a placeholder for an unresolved raw reference, preserving slot and generation."""
    return f"<{status.value}_0x{reference.segment:x}#{reference.sequence}>"


@dataclass(frozen=True, slots=True)
class PathCandidate:
    """A single path candidate for a record, derived from one ``$FILE_NAME`` and all parent branches.

    A record with multiple hard links and/or both a Win32 and DOS name yields multiple candidates.
    Each candidate keeps the namespace, raw parent reference and resolution status of every element
    in its chain, so a backend can present the complete set instead of silently selecting one path.

    Attributes:
        name: The name of the record this candidate belongs to.
        namespace: The namespace of that name.
        reference: The slot and generation of the record this candidate belongs to.
        parent_reference: The raw parent reference of that name.
        status: The status of the complete chain.
        elements: The chain from the record towards the root (excluding the root itself). Unresolved
            chains end with a placeholder element that keeps the raw reference that failed.
        reason: Optional human readable detail about the failure.
    """

    name: str | None
    namespace: FilenameNamespace | None
    reference: PathReference
    parent_reference: PathReference | None
    status: PathStatus
    elements: tuple[PathElement, ...]
    reason: str | None = None

    @property
    def segment(self) -> int:
        return self.reference.segment

    @property
    def sequence(self) -> int:
        return self.reference.sequence

    @property
    def parent_segment(self) -> int | None:
        return self.parent_reference.segment if self.parent_reference is not None else None

    @property
    def parent_sequence(self) -> int | None:
        return self.parent_reference.sequence if self.parent_reference is not None else None

    @property
    def resolved(self) -> bool:
        return self.status == PathStatus.RESOLVED

    @property
    def path(self) -> str | None:
        """Return the reconstructed path if the complete chain resolved, else ``None``.

        A partially resolved chain deliberately has no path: joining a validated prefix with an
        unverified parent would present a unique-looking path that the evidence does not support.
        Use :attr:`legacy_path` or :attr:`elements` to inspect the raw references.
        """
        if not self.resolved:
            return None
        return "\\".join(element.name for element in reversed(self.elements) if element.name is not None)

    @property
    def legacy_path(self) -> str:
        """Render a path for the legacy string API, keeping placeholders for unresolved references."""
        parts = [
            element.name if element.name is not None else placeholder(element.reference, element.status)
            for element in self.elements
        ]
        return "\\".join(reversed(parts))

    def __str__(self) -> str:
        return self.path or self.legacy_path

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON friendly representation for a backend."""
        return {
            "name": self.name,
            "namespace": self.namespace.name if self.namespace is not None else None,
            "namespace_value": int(self.namespace) if self.namespace is not None else None,
            "reference": list(self.reference),
            "segment": self.segment,
            "sequence": self.sequence,
            "parent_reference": list(self.parent_reference) if self.parent_reference is not None else None,
            "parent_segment": self.parent_segment,
            "parent_sequence": self.parent_sequence,
            "status": self.status.value,
            "resolved": self.resolved,
            "path": self.path,
            "legacy_path": self.legacy_path,
            "reason": self.reason,
            "elements": [
                {
                    "name": element.name,
                    "namespace": element.namespace.name if element.namespace is not None else None,
                    "namespace_value": int(element.namespace) if element.namespace is not None else None,
                    "segment": element.segment,
                    "sequence": element.sequence,
                    "reference": list(element.reference),
                    "parent_reference": list(element.parent_reference)
                    if element.parent_reference is not None
                    else None,
                    "parent_segment": element.parent_segment,
                    "parent_sequence": element.parent_sequence,
                    "status": element.status.value,
                    "flags": element.flags,
                    "reason": element.reason,
                }
                for element in self.elements
            ],
        }


def _filename_attributes(record: MftRecord, ignore_dos: bool) -> list[Any]:
    attrs = record.attributes[ATTRIBUTE_TYPE_CODE.FILE_NAME]
    if ignore_dos:
        attrs = [attr for attr in attrs if FilenameNamespace.from_flags(attr.flags) != FilenameNamespace.DOS]
    return list(attrs)


def _make_candidate(
    elements: tuple[PathElement, ...],
    status: PathStatus,
    failure: PathReference | None = None,
    reason: str | None = None,
) -> PathCandidate:
    target = elements[0]
    if status != PathStatus.RESOLVED and failure is not None:
        elements = (*elements, PathElement(None, None, failure, None, status, reason))

    return PathCandidate(
        name=target.name,
        namespace=target.namespace,
        reference=target.reference,
        parent_reference=target.parent_reference,
        status=status,
        elements=elements,
        reason=reason,
    )


@dataclass(slots=True)
class _Enumeration:
    candidates: list[PathCandidate]
    max_candidates: int
    max_depth: int
    truncated: bool = False


def _walk_parents(
    mft: Mft,
    parent: PathReference,
    elements: tuple[PathElement, ...],
    visited: set[PathReference],
    state: _Enumeration,
    ignore_dos: bool,
) -> None:
    out = state.candidates
    if len(out) >= state.max_candidates:
        state.truncated = True
        return

    if len(elements) >= state.max_depth:
        out.append(_make_candidate(elements, PathStatus.LIMIT_EXCEEDED, parent, "parent chain depth limit reached"))
        return

    if parent.segment == FILE_NUMBER_ROOT:
        root_record = mft.get_generation(parent.segment, parent.sequence)
        if root_record is None:
            try:
                actual = mft.get(parent.segment)
            except Exception as exc:
                out.append(
                    _make_candidate(
                        elements,
                        PathStatus.MISSING_RECORD,
                        parent,
                        f"{type(exc).__name__}: {exc}",
                    )
                )
                return

            out.append(
                _make_candidate(
                    elements,
                    PathStatus.BROKEN_REFERENCE,
                    parent,
                    f"root slot now contains generation {actual.header.SequenceNumber}, "
                    f"reference expects {parent.sequence}",
                )
            )
            return

        out.append(_make_candidate(elements, PathStatus.RESOLVED))
        return

    if parent in visited:
        out.append(_make_candidate(elements, PathStatus.CYCLE, parent, "parent reference was already visited"))
        return

    try:
        parent_record = mft.get(parent.segment)
    except Exception as exc:
        out.append(_make_candidate(elements, PathStatus.MISSING_RECORD, parent, f"{type(exc).__name__}: {exc}"))
        return

    actual = PathReference(parent.segment, parent_record.header.SequenceNumber)
    if actual.sequence != parent.sequence:
        out.append(
            _make_candidate(
                elements,
                PathStatus.BROKEN_REFERENCE,
                parent,
                f"slot now contains generation {actual.sequence}, reference expects {parent.sequence}",
            )
        )
        return

    visited = visited | {actual}

    try:
        attrs = _filename_attributes(parent_record, ignore_dos)
    except Exception as exc:
        out.append(_make_candidate(elements, PathStatus.MISSING_RECORD, parent, f"{type(exc).__name__}: {exc}"))
        return

    if not attrs:
        out.append(_make_candidate(elements, PathStatus.NO_FILENAME, parent, "parent record has no $FILE_NAME"))
        return

    for attr in attrs:
        element = PathElement(
            name=attr.file_name,
            namespace=FilenameNamespace.from_flags(attr.flags),
            reference=actual,
            parent_reference=PathReference.from_reference(attr.attr.ParentDirectory),
            status=PathStatus.RESOLVED,
            flags=attr.flags,
        )
        _walk_parents(
            mft,
            element.parent_reference,
            (*elements, element),
            visited,
            state,
            ignore_dos,
        )

        if state.truncated:
            return


def path_candidates(
    mft: Mft,
    record: MftRecord,
    ignore_dos: bool = False,
    max_candidates: int = 1024,
    max_depth: int = 256,
) -> list[PathCandidate]:
    """Enumerate all path candidates for an MFT record.

    Every ``$FILE_NAME`` of the record starts its own chain, and every ancestor with multiple names
    branches the chain further. References are validated against the generation (sequence number) of
    the record actually occupying the slot, so a reused parent slot cannot contribute a stale name.
    Unresolvable chains keep the raw reference that failed instead of inventing a directory component.

    Args:
        mft: The MFT to resolve references with.
        record: The record to enumerate paths for.
        ignore_dos: Ignore DOS namespace names entirely.
        max_candidates: Upper bound on candidates returned for a single record.
        max_depth: Upper bound on the length of a parent chain.

    Returns:
        One candidate per ``$FILE_NAME`` and ancestor branch, in deterministic order. Candidates with
        :attr:`PathCandidate.status` :attr:`PathStatus.RESOLVED` have a reconstructed
        :attr:`PathCandidate.path`; all other candidates only expose raw references and the legacy
        rendering.
    """
    try:
        target_reference = PathReference(record.segment, record.header.SequenceNumber)
        attrs = _filename_attributes(record, ignore_dos)
    except Exception:
        return []

    state = _Enumeration([], max_candidates, max_depth)
    for attr in attrs:
        element = PathElement(
            name=attr.file_name,
            namespace=FilenameNamespace.from_flags(attr.flags),
            reference=target_reference,
            parent_reference=PathReference.from_reference(attr.attr.ParentDirectory),
            status=PathStatus.RESOLVED,
            flags=attr.flags,
        )
        _walk_parents(
            mft,
            element.parent_reference,
            (element,),
            {target_reference},
            state,
            ignore_dos,
        )

        if state.truncated:
            break

    if state.truncated:
        state.candidates.append(
            PathCandidate(
                None,
                None,
                target_reference,
                None,
                PathStatus.LIMIT_EXCEEDED,
                (
                    PathElement(
                        None,
                        None,
                        target_reference,
                        None,
                        PathStatus.LIMIT_EXCEEDED,
                        "candidate limit reached; remaining branches were not enumerated",
                    ),
                ),
                "candidate limit reached; remaining branches were not enumerated",
            )
        )

    return sorted(
        state.candidates,
        key=lambda candidate: (
            not candidate.resolved,
            candidate.namespace.value if candidate.namespace is not None else -1,
            candidate.legacy_path,
        ),
    )
