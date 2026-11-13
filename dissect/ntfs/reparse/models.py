"""Offline, evidence-preserving data model for NTFS reparse points.

Nothing in this module (or its siblings) opens, stats or resolves a path on the
host filesystem. Every value that originates from the image is wrapped together
with the byte range it came from so a forensic reviewer can trace any displayed
string back to the on-disk bytes.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class ValueStatus(enum.Enum):
    """Lifecycle state of a single decoded field."""

    PRESENT = "present"
    ABSENT = "absent"
    EMPTY = "empty"
    TRUNCATED = "truncated"
    OUT_OF_BOUNDS = "out_of_bounds"
    UNDECODABLE = "undecodable"
    NOT_PARSED = "not_parsed"


class TagFamily(enum.Enum):
    """Coarse classification of a reparse tag, independent of a fixed enum.

    A tag that dissect.ntfs does not know by name is still classified from its
    high flag bits, so callers get an explanation rather than a hard failure.
    """

    NAME_SURROGATE = "name_surrogate"
    LX_SYMLINK = "lx_symlink"
    FILTER_MANAGED = "filter_managed"
    OTHER_KNOWN = "other_known"
    UNKNOWN = "unknown"


class PathKind(enum.Enum):
    """How a substitute name should be read, determined offline from its text."""

    RELATIVE = "relative"
    DOS_DRIVE = "dos_drive"
    VOLUME_GUID = "volume_guid"
    NT_NAMESPACE = "nt_namespace"
    UNC = "unc"
    OBJECT_ROOTED = "object_rooted"
    EMPTY = "empty"
    OTHER = "other"


class Certainty(enum.Enum):
    """Confidence a reviewer can place in a resolution candidate."""

    STRUCTURAL = "structural"
    CONDITIONAL = "conditional"
    UNRESOLVED = "unresolved"


class Severity(enum.Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ByteRange:
    """Half-open byte range inside the reparse buffer (post-header offset)."""

    offset: int
    length: int

    @property
    def end(self) -> int:
        return self.offset + self.length


@dataclass(frozen=True, slots=True)
class Evidence:
    """Provenance for one observation: where it came from and how confident it is."""

    source: str
    attribute_type: str
    tag: int
    range: ByteRange | None = None
    detail: str | None = None

    def describe(self) -> str:
        location = self.source
        if self.range is not None:
            location = f"{location}[{self.range.offset}:{self.range.end}]"
        text = f"{location} tag=0x{self.tag:08X} ({self.attribute_type})"
        if self.detail:
            text = f"{text} {self.detail}"
        return text


@dataclass(frozen=True, slots=True)
class Notice:
    """A non-fatal observation; parsing continues and uncertainty is retained."""

    severity: Severity
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class DecodedName:
    """One name field plus its raw bytes, decode state and byte-level evidence."""

    role: str
    text: str | None
    status: ValueStatus
    raw_utf16le: bytes
    evidence: Evidence
    notices: tuple[Notice, ...] = ()

    @property
    def is_usable(self) -> bool:
        return self.status is ValueStatus.PRESENT


@dataclass(frozen=True, slots=True)
class PathClassification:
    """Offline structural reading of a substitute name."""

    kind: PathKind
    raw: str
    stripped: str | None
    namespace_prefix: str | None
    volume_guid: str | None
    drive_letter: str | None
    uncertainty: str | None = None


@dataclass(frozen=True, slots=True)
class ResolutionCandidate:
    """One way the target could be interpreted; never an instruction to jump."""

    label: str
    kind: PathKind
    value: str | None
    certainty: Certainty
    requires: tuple[str, ...]
    evidence: Evidence
    uncertainty: str | None = None


@dataclass(frozen=True, slots=True)
class ReparseInterpretation:
    """The full offline reading of one reparse buffer.

    This is the interface the backend renders from. It deliberately separates the
    user-facing :attr:`display` from the authoritative :attr:`substitute` target,
    keeps every :class:`ResolutionCandidate`, and never performs host I/O.
    """

    source: str
    tag: int
    tag_name: str | None
    family: TagFamily
    reparse_data_length: int
    buffer_length: int
    substitute: DecodedName | None
    print_name: DecodedName | None
    symlink_relative: bool | None
    name_consistent: bool | None
    classification: PathClassification | None
    candidates: tuple[ResolutionCandidate, ...]
    notices: tuple[Notice, ...] = field(default_factory=tuple)
    raw_header_evidence: Evidence | None = None

    @property
    def display_value(self) -> DecodedName | None:
        """What a UI should show first, with consistency caveats attached."""
        return self.print_name if self.print_name and self.print_name.is_usable else self.substitute

    def evidence_lines(self) -> tuple[str, ...]:
        lines = []
        if self.raw_header_evidence:
            lines.append(self.raw_header_evidence.describe())
        for name in (self.substitute, self.print_name):
            if name is not None:
                lines.append(name.evidence.describe())
        return tuple(lines)
