"""Tolerant, offline interpreter for raw NTFS reparse buffers.

The interpreter only reads bytes handed to it. It never opens a path, calls
``stat``/``open`` on the host, or follows a link. Malformed length fields are
reported as :class:`~dissect.ntfs.reparse.models.Notice` entries instead of being
silently truncated or raising, so a damaged image still yields partial evidence.
"""

from __future__ import annotations

import io
import re
import struct
from dataclasses import dataclass

from dissect.ntfs.c_ntfs import IO_REPARSE_TAG

from .models import (
    ByteRange,
    Certainty,
    DecodedName,
    Evidence,
    Notice,
    PathClassification,
    PathKind,
    ReparseInterpretation,
    ResolutionCandidate,
    Severity,
    TagFamily,
    ValueStatus,
)

REPARSE_HEADER_SIZE = 8
SYMLINK_HEADER_SIZE = 12
MOUNTPOINT_HEADER_SIZE = 8
NAME_SURROGATE_TAGS = frozenset(
    {
        int(IO_REPARSE_TAG.SYMLINK),
        int(IO_REPARSE_TAG.MOUNT_POINT),
        int(IO_REPARSE_TAG.GLOBAL_REPARSE),
        int(IO_REPARSE_TAG.WCI_TOMBSTONE),
        int(IO_REPARSE_TAG.PROJFS_TOMBSTONE),
        int(IO_REPARSE_TAG.WCI_LINK),
        int(IO_REPARSE_TAG.WCI_LINK_1),
    }
)
_DRIVE_RE = re.compile(r"^([A-Za-z]):[\\/]")
_GUID_RE = re.compile(r"Volume\{[0-9a-fA-F-]{36}\}")
UNC_PREFIXES = ("\\??\\UNC\\", "\\\\?\\UNC\\")


@dataclass(frozen=True, slots=True)
class _RawNameField:
    role: str
    offset: int
    length: int
    evidence_attr: str


def classify_tag(tag: int) -> tuple[TagFamily, str | None]:
    """Return a family and, when known, the symbolic name of ``tag``."""
    try:
        tag_name = IO_REPARSE_TAG(tag).name
    except ValueError:
        tag_name = None

    if tag == int(IO_REPARSE_TAG.LX_SYMLINK):
        return TagFamily.LX_SYMLINK, tag_name
    if tag in NAME_SURROGATE_TAGS or bool(tag & 0x20000000):
        return TagFamily.NAME_SURROGATE, tag_name
    if bool(tag & 0x80000000):
        return TagFamily.FILTER_MANAGED, tag_name
    if tag_name is not None:
        return TagFamily.OTHER_KNOWN, tag_name
    return TagFamily.UNKNOWN, None


def _strip_namespace(text: str) -> tuple[str, str | None]:
    for prefix in ("\\??\\", "\\\\?\\", "\\\\.\\"):
        if text.startswith(prefix):
            return text[len(prefix) :], prefix
    return text, None


def classify_path(text: str, symlink_relative: bool | None) -> PathClassification:
    """Read the *structure* of a name without resolving it anywhere."""
    if text == "":
        return PathClassification(PathKind.EMPTY, text, None, None, None, None)

    lowered = text
    guid_match = _GUID_RE.search(text)
    volume_guid = guid_match.group(0) if guid_match else None

    stripped, prefix = _strip_namespace(text)

    if any(text.startswith(p) for p in UNC_PREFIXES):
        unc = "\\\\" + stripped[len("UNC\\") :]
        return PathClassification(PathKind.UNC, text, unc, prefix, None, None)
    if text.startswith("\\\\"):
        return PathClassification(PathKind.UNC, text, text, None, None, None)
    if volume_guid is not None:
        return PathClassification(
            PathKind.VOLUME_GUID,
            text,
            stripped,
            prefix,
            volume_guid,
            None,
            uncertainty="Volume{GUID} cannot be bound to a drive or image volume offline.",
        )
    drive_match = _DRIVE_RE.match(stripped) if stripped else None
    if drive_match:
        return PathClassification(
            PathKind.DOS_DRIVE,
            text,
            stripped,
            prefix,
            None,
            drive_match.group(1).upper(),
            uncertainty="Drive letter is guest-relative and may not exist in the acquisition host.",
        )
    if prefix is not None:
        return PathClassification(PathKind.NT_NAMESPACE, text, stripped, prefix, None, None)
    if text.startswith("\\"):
        return PathClassification(
            PathKind.OBJECT_ROOTED,
            text,
            text,
            None,
            None,
            None,
            uncertainty="Object-manager rooted path needs the image's NT namespace, not the host.",
        )
    if symlink_relative:
        return PathClassification(
            PathKind.RELATIVE,
            text,
            text,
            None,
            None,
            None,
            uncertainty="Relative target is anchored at the link's parent directory inside the image.",
        )
    return PathClassification(PathKind.OTHER, text, text, None, None, None)


def _decode_field(field: _RawNameField, path_buffer: bytes, source: str, tag: int) -> DecodedName:
    notices: list[Notice] = []
    range_obj = ByteRange(field.offset, field.length)
    evidence = Evidence(source, field.evidence_attr, tag, range_obj)
    upper = len(path_buffer)

    if field.length == 0:
        return DecodedName(field.role, "", ValueStatus.EMPTY, b"", evidence)
    if field.offset < 0 or field.offset >= upper:
        notices.append(
            Notice(
                Severity.ERROR,
                "name_offset_out_of_bounds",
                f"{field.role} offset {field.offset} outside reparse buffer of {upper} bytes.",
            )
        )
        return DecodedName(field.role, None, ValueStatus.OUT_OF_BOUNDS, b"", evidence, tuple(notices))
    if field.length % 2 != 0:
        notices.append(
            Notice(
                Severity.WARNING,
                "name_length_odd",
                f"{field.role} length {field.length} is not a whole UTF-16 code unit count.",
            )
        )

    end = field.offset + field.length
    raw = path_buffer[field.offset : min(end, upper)]
    status = ValueStatus.PRESENT
    if end > upper:
        status = ValueStatus.TRUNCATED
        notices.append(
            Notice(
                Severity.ERROR,
                "name_length_out_of_bounds",
                f"{field.role} declares {field.length} bytes but only {upper - field.offset} remain.",
            )
        )
    try:
        text = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        text = raw.decode("utf-16-le", errors="replace")
        status = ValueStatus.UNDECODABLE
        notices.append(
            Notice(Severity.WARNING, "name_undecodable", f"{field.role} contains invalid UTF-16LE units.")
        )
    return DecodedName(field.role, text, status, raw, evidence, tuple(notices))


def _parse_name_header(tag: int, payload: bytes) -> tuple[dict | None, bytes, list[Notice]]:
    notices: list[Notice] = []
    if tag == int(IO_REPARSE_TAG.SYMLINK):
        if len(payload) < SYMLINK_HEADER_SIZE:
            notices.append(
                Notice(Severity.ERROR, "header_truncated", "Symbolic link header shorter than 12 bytes.")
            )
            return None, payload, notices
        sub_off, sub_len, print_off, print_len, flags = struct.unpack("<HHHHI", payload[:SYMLINK_HEADER_SIZE])
        header = {
            "fields": (
                _RawNameField("substitute_name", sub_off, sub_len, "SYMBOLIC_LINK_REPARSE_BUFFER"),
                _RawNameField("print_name", print_off, print_len, "SYMBOLIC_LINK_REPARSE_BUFFER"),
            ),
            "relative": bool(flags & 0x1),
            "flags": flags,
        }
        return header, payload[SYMLINK_HEADER_SIZE:], notices
    if tag == int(IO_REPARSE_TAG.MOUNT_POINT):
        if len(payload) < MOUNTPOINT_HEADER_SIZE:
            notices.append(
                Notice(Severity.ERROR, "header_truncated", "Mount point header shorter than 8 bytes.")
            )
            return None, payload, notices
        sub_off, sub_len, print_off, print_len = struct.unpack("<HHHH", payload[:MOUNTPOINT_HEADER_SIZE])
        header = {
            "fields": (
                _RawNameField("substitute_name", sub_off, sub_len, "MOUNT_POINT_REPARSE_BUFFER"),
                _RawNameField("print_name", print_off, print_len, "MOUNT_POINT_REPARSE_BUFFER"),
            ),
            "relative": False,
            "flags": None,
        }
        return header, payload[MOUNTPOINT_HEADER_SIZE:], notices

    family, _ = classify_tag(tag)
    if family is TagFamily.NAME_SURROGATE:
        # Unknown name-surrogate tags commonly reuse the generic four-USHORT
        # SubstituteName/PrintName layout. Parse it best-effort and label the
        # result as inferred so a reviewer never mistakes it for a known schema.
        if len(payload) < MOUNTPOINT_HEADER_SIZE:
            notices.append(
                Notice(Severity.ERROR, "header_truncated", "Inferred name-surrogate header shorter than 8 bytes.")
            )
            return None, payload, notices
        sub_off, sub_len, print_off, print_len = struct.unpack("<HHHH", payload[:MOUNTPOINT_HEADER_SIZE])
        header = {
            "fields": (
                _RawNameField("substitute_name", sub_off, sub_len, "INFERRED_NAME_SURROGATE_BUFFER"),
                _RawNameField("print_name", print_off, print_len, "INFERRED_NAME_SURROGATE_BUFFER"),
            ),
            "relative": None,
            "flags": None,
            "inferred": True,
        }
        notices.append(
            Notice(
                Severity.WARNING,
                "inferred_name_layout",
                f"Tag 0x{tag:08X} is unknown; SubstituteName/PrintName parsed from the generic layout by inference.",
            )
        )
        return header, payload[MOUNTPOINT_HEADER_SIZE:], notices
    return None, payload, notices


def _build_candidates(
    sub: DecodedName | None,
    print_decoded: DecodedName | None,
    classification: PathClassification | None,
    source: str,
    tag: int,
) -> tuple[ResolutionCandidate, ...]:
    candidates: list[ResolutionCandidate] = []
    if sub is not None and sub.is_usable and sub.text is not None and classification is not None:
        candidates.append(
            ResolutionCandidate(
                label="raw_substitute_name",
                kind=classification.kind,
                value=classification.raw,
                certainty=Certainty.STRUCTURAL,
                requires=(),
                evidence=sub.evidence,
            )
        )
        if classification.namespace_prefix and classification.stripped is not None:
            candidates.append(
                ResolutionCandidate(
                    label="substitute_without_namespace_prefix",
                    kind=classification.kind,
                    value=classification.stripped,
                    certainty=Certainty.CONDITIONAL,
                    requires=("NT namespace prefix is an implementation detail, not a host path.",),
                    evidence=sub.evidence,
                )
            )
        if classification.kind is PathKind.VOLUME_GUID:
            candidates.append(
                ResolutionCandidate(
                    label="volume_guid_binding",
                    kind=PathKind.VOLUME_GUID,
                    value=classification.volume_guid,
                    certainty=Certainty.UNRESOLVED,
                    requires=("Image Mount Manager / registry $Volume mapping.",),
                    evidence=sub.evidence,
                    uncertainty=classification.uncertainty,
                )
            )
        if classification.kind is PathKind.DOS_DRIVE:
            candidates.append(
                ResolutionCandidate(
                    label="dos_drive_binding",
                    kind=PathKind.DOS_DRIVE,
                    value=classification.drive_letter,
                    certainty=Certainty.UNRESOLVED,
                    requires=("Guest drive-letter assignment; verify against image, not this host.",),
                    evidence=sub.evidence,
                    uncertainty=classification.uncertainty,
                )
            )
        if classification.kind is PathKind.RELATIVE:
            candidates.append(
                ResolutionCandidate(
                    label="relative_join",
                    kind=PathKind.RELATIVE,
                    value=classification.raw,
                    certainty=Certainty.CONDITIONAL,
                    requires=("Link parent directory path, computed inside the image only.",),
                    evidence=sub.evidence,
                    uncertainty=classification.uncertainty,
                )
            )
    if print_decoded is not None and print_decoded.is_usable and print_decoded.text is not None:
        candidates.append(
            ResolutionCandidate(
                label="print_name_display",
                kind=PathKind.OTHER,
                value=print_decoded.text,
                certainty=Certainty.CONDITIONAL,
                requires=("Author-supplied display string; not authoritative for resolution.",),
                evidence=print_decoded.evidence,
            )
        )
    return tuple(candidates)


def _consistency(sub: DecodedName | None, print_decoded: DecodedName | None) -> bool | None:
    if (
        sub is None
        or print_decoded is None
        or not sub.is_usable
        or not print_decoded.is_usable
        or sub.text is None
        or print_decoded.text is None
    ):
        return None
    stripped, _ = _strip_namespace(sub.text)
    if any(sub.text.startswith(p) for p in UNC_PREFIXES):
        stripped = "\\\\" + stripped[len("UNC\\") :]
    return stripped.rstrip("\\") == print_decoded.text.rstrip("\\")


def interpret_reparse_buffer(data: bytes, source: str = "<memory>") -> ReparseInterpretation:
    """Interpret a raw ``$REPARSE_POINT`` value (attribute value bytes).

    ``data`` is the full attribute value, i.e. an 8-byte
    ``REPARSE_DATA_BUFFER`` header followed by ``ReparseDataLength`` payload bytes.
    """
    notices: list[Notice] = []
    if len(data) < REPARSE_HEADER_SIZE:
        raise ValueError("Reparse buffer must contain at least the 8-byte REPARSE_DATA_BUFFER header.")

    tag, data_length, _reserved = struct.unpack("<IHH", data[:REPARSE_HEADER_SIZE])
    family, tag_name = classify_tag(tag)
    header_evidence = Evidence(
        source,
        "REPARSE_DATA_BUFFER",
        tag,
        ByteRange(0, REPARSE_HEADER_SIZE),
        detail=f"ReparseDataLength={data_length}",
    )

    payload = data[REPARSE_HEADER_SIZE : REPARSE_HEADER_SIZE + data_length]
    if REPARSE_HEADER_SIZE + data_length > len(data):
        notices.append(
            Notice(
                Severity.ERROR,
                "reparse_data_length_overflow",
                f"ReparseDataLength {data_length} exceeds available {len(data) - REPARSE_HEADER_SIZE} bytes.",
            )
        )
        payload = data[REPARSE_HEADER_SIZE:]
    elif REPARSE_HEADER_SIZE + data_length < len(data):
        notices.append(
            Notice(
                Severity.WARNING,
                "reparse_data_length_underflow",
                f"{len(data) - (REPARSE_HEADER_SIZE + data_length)} trailing bytes ignored by length field.",
            )
        )

    parsed_header, path_buffer, header_notices = _parse_name_header(tag, payload)
    notices.extend(header_notices)

    substitute: DecodedName | None = None
    print_decoded: DecodedName | None = None
    symlink_relative: bool | None = None
    classification: PathClassification | None = None

    if parsed_header is not None:
        if tag == int(IO_REPARSE_TAG.SYMLINK):
            symlink_relative = parsed_header["relative"]
        elif parsed_header.get("inferred"):
            symlink_relative = None
        else:
            symlink_relative = False
        sub_field, print_field = parsed_header["fields"]
        substitute = _decode_field(sub_field, path_buffer, source, tag)
        print_decoded = _decode_field(print_field, path_buffer, source, tag)
        notices.extend(substitute.notices)
        notices.extend(print_decoded.notices)
        if substitute.is_usable and substitute.text is not None:
            classification = classify_path(substitute.text, symlink_relative)
    else:
        notices.append(
            Notice(
                Severity.INFO,
                "tag_not_name_surrogate",
                f"Tag 0x{tag:08X} ({family.value}) carries no SubstituteName/PrintName name pair.",
            )
        )

    consistent = _consistency(substitute, print_decoded)
    if consistent is False:
        notices.append(
            Notice(
                Severity.WARNING,
                "print_substitute_mismatch",
                "PrintName does not match the stripped SubstituteName; display value may be misleading.",
            )
        )

    candidates = _build_candidates(substitute, print_decoded, classification, source, tag)
    return ReparseInterpretation(
        source=source,
        tag=tag,
        tag_name=tag_name,
        family=family,
        reparse_data_length=data_length,
        buffer_length=len(data),
        substitute=substitute,
        print_name=print_decoded,
        symlink_relative=symlink_relative,
        name_consistent=consistent,
        classification=classification,
        candidates=candidates,
        notices=tuple(notices),
        raw_header_evidence=header_evidence,
    )


def interpret_attribute(attribute, source: str | None = None) -> ReparseInterpretation:
    """Adapt a :class:`dissect.ntfs.attr.ReparsePoint` without re-opening anything."""
    tag = int(attribute.tag)
    location = source or repr(attribute)
    header = struct.pack("<IHH", tag, attribute.attr.ReparseDataLength, attribute.attr.Reserved)
    if attribute.tag_header is None:
        payload = bytes(attribute.buffer)
    else:
        stream = io.BytesIO()
        attribute.tag_header.write(stream)
        payload = stream.getvalue() + bytes(attribute.buffer)
    return interpret_reparse_buffer(header + payload, source=location)
