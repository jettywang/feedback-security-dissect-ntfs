from __future__ import annotations

import io
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from dissect.util.sid import read_sid

from dissect.ntfs.c_ntfs import ACE_OBJECT_FLAGS, ACE_TYPE, c_ntfs
from dissect.ntfs.exceptions import (
    SecurityDescriptorConflictError,
    SecurityDescriptorCorruptionError,
    SecurityDescriptorError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.ntfs.mft import MftRecord


#: Distance between the redundant copies of ``$SDS`` in the stream.
SDS_MIRROR_STRIDE = 0x40000
#: Maximum length accepted for a single ``$SDS`` entry.
SDS_MAX_ENTRY_LENGTH = 0x10000
#: Minimum length accepted for a single ``$SDS`` entry (header plus a relative descriptor).
SDS_MIN_ENTRY_LENGTH = len(c_ntfs._SECURITY_DESCRIPTOR_HEADER) + len(c_ntfs._SECURITY_DESCRIPTOR_RELATIVE)

# Validation statuses for a copy of a security descriptor.
STATUS_OK = "ok"
STATUS_TRUNCATED = "truncated"
STATUS_INVALID = "invalid"
STATUS_MISSING = "missing"


@dataclass
class SDSLocation:
    """Physical location of one ``$SDS`` entry copy.

    Args:
        mirror: The base offset of the mirrored ``$SDS`` region (a multiple of ``0x40000``).
        offset: The absolute stream offset where the entry header was found.
        relative_offset: The offset relative to the start of the mirrored region.
        length: The declared entry length, if a header could be read.
        status: Validation status for this copy (``ok``, ``truncated``, ``invalid`` or ``missing``).
        reason: Human readable explanation for a non-``ok`` status.
        indexed: Whether the ``$SII`` index pointed at this location.
        hash_id: The ``HashId`` recorded in this entry's header, if available.
        content: The raw descriptor body bytes, when they are fully present in the stream.
    """

    mirror: int
    offset: int
    relative_offset: int
    length: int | None = None
    status: str = STATUS_OK
    reason: str | None = None
    indexed: bool = False
    hash_id: int | None = None
    content: bytes | None = None

    @property
    def valid(self) -> bool:
        """Return whether this copy is a complete, well formed entry."""
        return self.status == STATUS_OK

    @property
    def truncated(self) -> bool:
        """Return whether this copy is cut short by the end of the stream or an internal boundary."""
        return self.status == STATUS_TRUNCATED


@dataclass
class SecureIndexEntry:
    """An entry from the ``$SII`` index together with the location it points at.

    Args:
        security_id: The indexed security ID.
        hash_id: The hash ID recorded in the index entry.
        offset: The block-relative offset recorded in the index entry.
        length: The length recorded in the index entry.
        index_offset: The offset of this entry in the ``$SII`` index stream.
        valid: Whether the index entry itself is structurally usable.
        reason: Explanation for an unusable index entry.
    """

    security_id: int
    hash_id: int | None
    offset: int | None
    length: int | None
    index_offset: int | None = None
    valid: bool = True
    reason: str | None = None


@dataclass
class SDSIssue:
    """A structural problem found while validating an index entry or a descriptor body.

    Args:
        kind: Short machine readable issue kind, e.g. ``mismatch-sii``.
        location: The ``$SDS`` location the issue relates to, if any.
        detail: Human readable detail.
    """

    kind: str
    detail: str
    location: SDSLocation | None = None


@dataclass
class SecurityDescriptorEvidence:
    """All copies of a security descriptor that were inspected for one security ID.

    Copies that are byte-for-byte identical are merged into a single evidence entry. Conflicting contents are
    all retained, together with the reason each copy was or was not selected.

    Args:
        security_id: The security ID this evidence describes.
        copies: The distinct descriptor contents, keyed by their byte content.
        locations: Every inspected location, including corrupt or truncated ones.
        index_entries: The ``$SII`` entries that refer to this security ID.
        issues: Structural problems discovered during validation.
        index_error: Set when the ``$SII`` index could not be read or had no entry for this security ID.
        index_readable: ``True`` when the ``$SII`` index was read, ``False`` when it was present but unreadable,
            and ``None`` when no index is available at all.
        selected: The content selected as authoritative, if any.
        selection_reason: Why the selected content was chosen, or why no content could be selected.
    """

    security_id: int
    copies: dict[bytes, list[SDSLocation]] = field(default_factory=dict)
    locations: list[SDSLocation] = field(default_factory=list)
    index_entries: list[SecureIndexEntry] = field(default_factory=list)
    issues: list[SDSIssue] = field(default_factory=list)
    index_error: str | None = None
    index_readable: bool | None = None
    selected: bytes | None = None
    selection_reason: str | None = None

    @property
    def all_locations(self) -> list[SDSLocation]:
        """Return all inspected locations, valid copies first."""
        return sorted(self.locations, key=lambda loc: (not loc.valid, loc.mirror))

    @property
    def valid_locations(self) -> list[SDSLocation]:
        """Return only the locations that contain a complete entry."""
        return [loc for loc in self.locations if loc.valid]

    @property
    def distinct_contents(self) -> list[tuple[bytes, list[SDSLocation]]]:
        """Return the distinct descriptor contents with all of their mirror locations."""
        return list(self.copies.items())

    @property
    def descriptors(self) -> list[SecurityDescriptor]:
        """Parse every distinct descriptor content, in discovery order."""
        return [SecurityDescriptor(io.BytesIO(content)) for content in self.copies]

    @property
    def consistent(self) -> bool:
        """Return whether all valid copies agree on a single descriptor content."""
        return len(self.copies) == 1

    @property
    def conflicts(self) -> bool:
        """Return whether more than one distinct descriptor content was found."""
        return len(self.copies) > 1

    @property
    def indexed_locations(self) -> list[SDSLocation]:
        """Return the locations the ``$SII`` index pointed at."""
        return [loc for loc in self.locations if loc.indexed]

    @property
    def indexed_valid_locations(self) -> list[SDSLocation]:
        """Return the indexed locations that contain a complete, verified entry."""
        return [loc for loc in self.indexed_locations if loc.valid]

    def descriptor(self) -> SecurityDescriptor:
        """Parse the selected descriptor content.

        Raises:
            SecurityDescriptorError: If no content could be selected.
        """
        if self.selected is None:
            raise SecurityDescriptorError(self.selection_reason or "No descriptor content selected", self)
        return SecurityDescriptor(io.BytesIO(self.selected))


class Secure:
    """Lookup security descriptors from the ``$Secure`` file, or optionally just a file-like object of the ``$SDS``.

    Only one the ``record`` or ``sds`` arguments needs to be provided.

    Args:
        record: The MFT record of the ``$Secure`` file, used when opening from a full NTFS volume.
        sds: A file-like object of the ``$SDS`` stream, used when opening from separate system files.
        sii: An optional index to use as ``$SII`` when opening from separate system files.
        verify: Verify every mirrored ``$SDS`` copy for the requested security ID. Enabled by default.
        mirror_stride: Distance between mirrored ``$SDS`` regions. Defaults to the NTFS 0x40000 layout.
    """

    def __init__(
        self,
        record: MftRecord | None = None,
        sds: BinaryIO | None = None,
        sii: object | None = None,
        verify: bool = True,
        mirror_stride: int = SDS_MIRROR_STRIDE,
    ):
        self.record = record
        self.sds = None
        self.sii = None
        self.verify = verify
        self.mirror_stride = mirror_stride

        if record:
            self.sds = sds or record.open("$SDS")
            self.sii = sii or record.index("$SII")
        elif sds:
            self.sds = sds
            self.sii = sii

        if not self.sds:
            raise ValueError("Either record or SDS stream is required")

        # Hack for file-like objects that don't have a .size attribute
        if not hasattr(self.sds, "size"):
            self.sds.size = self.sds.seek(0, io.SEEK_END)

        self.lookup = lru_cache(4096)(self.lookup)

    def _read_entry(self, offset: int) -> tuple[c_ntfs._SECURITY_DESCRIPTOR_HEADER | None, int]:
        """Read a single ``$SDS`` entry header at ``offset`` without interpreting it."""
        fh = self.sds
        if offset >= self.sds.size:
            return None, 0

        fh.seek(offset)
        try:
            entry = c_ntfs._SECURITY_DESCRIPTOR_HEADER(fh)
        except EOFError:
            return None, 0

        return entry, offset

    def _validate_copy(self, entry: c_ntfs._SECURITY_DESCRIPTOR_HEADER, offset: int, mirror: int) -> SDSLocation:
        """Validate one ``$SDS`` copy against the stream contents and its own header."""
        relative_offset = offset - mirror
        location = SDSLocation(
            mirror=mirror,
            offset=offset,
            relative_offset=relative_offset,
            length=entry.Length,
            hash_id=entry.HashId,
        )

        if entry.Length == 0:
            location.status = STATUS_MISSING
            location.reason = "zero length entry"
            return location

        if entry.Length < SDS_MIN_ENTRY_LENGTH or entry.Length > SDS_MAX_ENTRY_LENGTH:
            location.status = STATUS_INVALID
            location.reason = f"implausible entry length {entry.Length}"
            return location

        end = offset + entry.Length
        content_length = entry.Length - len(c_ntfs._SECURITY_DESCRIPTOR_HEADER)
        if end > min(mirror + self.mirror_stride, self.sds.size):
            location.status = STATUS_TRUNCATED
            location.reason = (
                f"entry extends past the end of its mirrored region ({end:#x} > "
                f"{min(mirror + self.mirror_stride, self.sds.size):#x})"
            )
            available_end = min(mirror + self.mirror_stride, self.sds.size)
            if offset + len(c_ntfs._SECURITY_DESCRIPTOR_HEADER) <= available_end:
                # Retain the bytes that are present so a truncated copy can still be compared with candidates.
                fh = self.sds
                fh.seek(offset + len(c_ntfs._SECURITY_DESCRIPTOR_HEADER))
                location.content = fh.read(available_end - offset - len(c_ntfs._SECURITY_DESCRIPTOR_HEADER))
            return location

        if entry.Offset != relative_offset:
            location.status = STATUS_INVALID
            location.reason = f"embedded offset {entry.Offset:#x} does not match relative offset {relative_offset:#x}"
            return location

        fh = self.sds
        fh.seek(offset)
        data = fh.read(entry.Length)
        if len(data) != entry.Length:
            location.status = STATUS_TRUNCATED
            location.reason = f"short read, expected {entry.Length} bytes but got {len(data)}"
            return location

        if content_length > 0:
            location.content = data[len(c_ntfs._SECURITY_DESCRIPTOR_HEADER) :]

        issue = _descriptor_header_issue(data[len(c_ntfs._SECURITY_DESCRIPTOR_HEADER) :])
        if issue:
            location.status = STATUS_INVALID
            location.reason = issue

        return location

    def _copy_for_offset(self, offset: int, mirror: int, security_id: int) -> SDSLocation:
        """Return the validated location of a descriptor copy at ``offset`` in a specific mirrored region."""
        entry, _ = self._read_entry(offset)
        if entry is None:
            return SDSLocation(
                mirror=mirror,
                offset=offset,
                relative_offset=offset - mirror,
                status=STATUS_MISSING,
                reason="no entry header",
            )

        location = self._validate_copy(entry, offset, mirror)
        if location.valid and entry.SecurityId != security_id:
            location.status = STATUS_INVALID
            location.reason = f"SecurityId {entry.SecurityId} does not match requested {security_id}"

        return location

    def _mirrors(self) -> list[int]:
        """Return the base offsets of all mirrored ``$SDS`` regions in the stream."""
        return list(range(0, self.sds.size, self.mirror_stride))

    def _index_entries(self, security_id: int) -> list[SecureIndexEntry]:
        """Return all ``$SII`` entries for ``security_id`` without trusting a single search result."""
        if not self.sii:
            return []

        candidates = []
        for entry in self.sii.entries():
            if not entry.key_length:
                continue
            key = _parse_security_id_key(entry.key)
            if key is None or key != security_id:
                continue

            candidates.append(self._to_secure_index_entry(entry, security_id))

        if not candidates:
            # Preserve the original lookup failure semantics when nothing is indexed at all.
            raise KeyError(f"Couldn't find security ID: {security_id}")

        return candidates

    def _to_secure_index_entry(self, entry: object, security_id: int) -> SecureIndexEntry:
        """Convert a ``$SII`` index entry into a validated ``SecureIndexEntry``."""
        try:
            index_header = c_ntfs._SECURITY_DESCRIPTOR_HEADER(bytes(entry.data))  # type: ignore[attr-defined]
        except (EOFError, AttributeError, TypeError):
            return SecureIndexEntry(
                security_id=security_id,
                hash_id=None,
                offset=None,
                length=None,
                index_offset=getattr(entry, "offset", None),
                valid=False,
                reason="index entry does not contain a usable descriptor header",
            )

        result = SecureIndexEntry(
            security_id=index_header.SecurityId,
            hash_id=index_header.HashId,
            offset=index_header.Offset,
            length=index_header.Length,
            index_offset=getattr(entry, "offset", None),
        )

        if index_header.SecurityId != security_id:
            result.valid = False
            result.reason = f"index entry SecurityId {index_header.SecurityId} does not match {security_id}"
        elif index_header.Length < SDS_MIN_ENTRY_LENGTH or index_header.Length > SDS_MAX_ENTRY_LENGTH:
            result.valid = False
            result.reason = f"index entry has implausible length {index_header.Length}"

        return result

    def _scan_security_id(self, security_id: int, include_all: bool = False) -> list[SDSLocation]:
        """Scan every mirrored region for complete entries with ``security_id``.

        This is the fallback when the ``$SII`` index is unusable or points at a corrupt copy. Each parse is driven by
        the entry length, and every mirror region is scanned independently so duplicate offsets do not collapse.
        A corrupt entry length makes that position unusable; scanning resumes at the next 16-byte aligned slot
        so later candidate copies in the same region are not lost.
        """
        locations: list[SDSLocation] = []
        for mirror in self._mirrors():
            offset = mirror
            while offset < min(mirror + self.mirror_stride, self.sds.size):
                entry, _ = self._read_entry(offset)
                if entry is None:
                    break

                if entry.Length == 0 or entry.Length < SDS_MIN_ENTRY_LENGTH or entry.Length > SDS_MAX_ENTRY_LENGTH:
                    if entry.Length == 0 and not include_all:
                        # Zero length entries mark the end of a region in a normal sequential scan.
                        break

                    offset += 16 - (offset % 16)
                    continue

                if entry.SecurityId == security_id:
                    location = self._validate_copy(entry, offset, mirror)
                    locations.append(location)

                offset += entry.Length
                offset += -(offset) & 0xF

        return locations

    def _evidence_for_location(self, location: SDSLocation) -> tuple[bytes | None, SDSIssue | None]:
        """Return the descriptor content at a validated location, or an issue explaining why it is unusable."""
        if not location.valid:
            return None, SDSIssue(kind=location.status, detail=location.reason or location.status, location=location)

        fh = self.sds
        fh.seek(location.offset)
        data = fh.read(location.length or 0)
        body_offset = len(c_ntfs._SECURITY_DESCRIPTOR_HEADER)
        content = data[body_offset:]

        issue = _descriptor_header_issue(content)
        if issue:
            return None, SDSIssue(kind="invalid-content", detail=issue, location=location)

        return content, None

    def audit(self, security_id: int, include_unindexed: bool = False) -> SecurityDescriptorEvidence:
        """Collect and compare all available copies of a security descriptor.

        By default the indexed offset is checked in every mirrored region. If an index entry is structurally
        inconsistent (wrong SecurityId, mismatched length or an unusable offset), or if no indexed copy is complete,
        all mirrored regions are additionally scanned for entries with the requested SecurityId and those candidates
        are reported.

        Identical contents are merged into one evidence entry with all of their locations. Distinct contents are
        all retained; no content is silently selected when they disagree.

        Args:
            security_id: The security ID to look up.
            include_unindexed: Scan all mirrored regions even if the index entries point at a valid copy.
        """
        evidence = SecurityDescriptorEvidence(security_id=security_id)
        if self.sii is not None:
            try:
                evidence.index_entries = self._index_entries(security_id)
                evidence.index_readable = True
            except KeyError as e:
                evidence.index_error = str(e)
                evidence.index_readable = True
            except Exception as e:
                # A structurally broken index must not prevent SDS candidate collection.
                evidence.index_error = f"unreadable $SII index: {e}"
                evidence.index_readable = False

        locations: dict[int, SDSLocation] = {}
        scan = include_unindexed or not self.sii or evidence.index_error is not None
        for index_entry in evidence.index_entries:
            if not index_entry.valid or index_entry.offset is None:
                scan = True
                if index_entry.reason:
                    evidence.issues.append(SDSIssue(kind="invalid-index-entry", detail=index_entry.reason))
                continue

            for mirror in self._mirrors():
                offset = mirror + index_entry.offset
                if offset >= self.sds.size:
                    evidence.issues.append(
                        SDSIssue(
                            kind="index-offset-out-of-range",
                            detail=(
                                f"index offset {index_entry.offset:#x} at mirror {mirror:#x} is outside "
                                f"the stream ({self.sds.size:#x})"
                            ),
                        )
                    )
                    continue

                location = self._copy_for_offset(offset, mirror, security_id)
                location.indexed = True
                locations[location.offset] = location

                if location.valid and index_entry.length is not None and location.length != index_entry.length:
                    evidence.issues.append(
                        SDSIssue(
                            kind="mismatch-length",
                            detail=(
                                f"index entry declares length {index_entry.length} but copy declares {location.length}"
                            ),
                            location=location,
                        )
                    )
                elif location.valid and index_entry.hash_id is not None and (location.hash_id != index_entry.hash_id):
                    evidence.issues.append(
                        SDSIssue(
                            kind="mismatch-hash",
                            detail=(
                                f"index entry declares hash {index_entry.hash_id:#x} but copy declares "
                                f"{location.hash_id:#x}"
                            ),
                            location=location,
                        )
                    )

        if not any(location.indexed and location.valid for location in locations.values()):
            # The index could not be confirmed against any mirror. Candidate copies may still be reported,
            # but they cannot be treated as the indexed descriptor.
            scan = True

        if scan:
            for location in self._scan_security_id(security_id, include_all=True):
                candidate = locations.get(location.offset)
                if candidate is None:
                    locations[location.offset] = location
                elif location.valid and not candidate.valid:
                    # A corrupt indexed copy must not hide a complete candidate at the same relative offset.
                    location.indexed = candidate.indexed
                    locations[location.offset] = location
                elif candidate.valid:
                    candidate.indexed = candidate.indexed or location.indexed

        evidence.locations = sorted(locations.values(), key=lambda loc: (loc.mirror, loc.offset))

        for location in evidence.locations:
            content, issue = self._evidence_for_location(location)
            if issue is not None:
                if issue.kind not in (STATUS_MISSING, STATUS_TRUNCATED):
                    evidence.issues.append(issue)
                continue

            evidence.copies.setdefault(content, []).append(location)

        evidence.selected, evidence.selection_reason = _select_content(evidence, locations)
        return evidence

    def normal_lookup(self, security_id: int) -> SecurityDescriptor:
        """Look up a security descriptor, returning only an unambiguously selected copy.

        Unlike :meth:`audit`, this never substitutes a different descriptor content than the one the index points at.
        If the indexed copy is corrupt, an unindexed identical copy may be used, but a copy with different content
        will cause a conflict error instead of being returned.

        Args:
            security_id: The security ID to lookup.

        Raises:
            KeyError: If the security ID can't be found.
            SecurityDescriptorConflictError: If mirrored or indexed copies disagree on content.
            SecurityDescriptorCorruptionError: If no complete copy can be selected.
        """
        evidence = self.audit(security_id)

        if evidence.selected is None:
            if evidence.conflicts:
                raise SecurityDescriptorConflictError(
                    f"Conflicting security descriptors for security ID {security_id}", evidence
                )

            if evidence.index_readable is False:
                raise SecurityDescriptorCorruptionError(
                    f"$SII index is unreadable while looking up security ID {security_id}", evidence
                ) from None

            if evidence.index_error is not None:
                raise SecurityDescriptorCorruptionError(f"Couldn't find security ID: {security_id}", evidence) from None

            raise SecurityDescriptorCorruptionError(
                f"No complete security descriptor for security ID {security_id}", evidence
            )

        return evidence.descriptor()

    def _iter_entries(self, offset: int = 0) -> Iterator[c_ntfs._SECURITY_DESCRIPTOR_HEADER]:
        """Iterate over all SDS entries, optionally starting from a specific offset.

        Args:
            offset: Optional offset to start iterating from.
        """
        fh = self.sds
        while True:
            fh.seek(offset)

            try:
                entry = c_ntfs._SECURITY_DESCRIPTOR_HEADER(fh)
            except EOFError:
                break

            if entry.Length == 0 or entry.Offset > self.sds.size or entry.Length > SDS_MAX_ENTRY_LENGTH:
                # The SDS is supposedly duplicated at 0x40000 increments (256k)? Try to parse again from there
                offset += self.mirror_stride - (offset % self.mirror_stride)
                continue

            yield entry

            offset += entry.Length
            # Align to 16 bytes with some bit magic
            offset += -(offset) & 0xF

    def lookup(self, security_id: int) -> SecurityDescriptor:
        """Lookup a security descriptor by the security ID.

        An index is used if available (``$SII``), otherwise we iterate all entries until we find the correct one.
        Every mirrored ``$SDS`` copy that the index points at is verified before a descriptor is returned.

        When copies disagree, this raises a :class:`~dissect.ntfs.exceptions.SecurityDescriptorConflictError`
        with the conflicting evidence attached. Use :meth:`audit` to inspect and report all copies instead.

        Args:
            security_id: The security ID to lookup.

        Raises:
            KeyError: If the security ID can't be found.
            SecurityDescriptorConflictError: If copies disagree on the descriptor content.
            SecurityDescriptorCorruptionError: If no complete copy can be selected.
        """
        if not self.verify:
            return self._legacy_lookup(security_id)

        return self.normal_lookup(security_id)

    def _legacy_lookup(self, security_id: int) -> SecurityDescriptor:
        """Look up a descriptor trusting the first parseable copy.

        This is the historical behaviour and is only used when :class:`Secure` was created with ``verify=False``.
        """
        if self.sii:
            # If we have an index, we can land directly at the right offset
            sii_entry = c_ntfs._SECURITY_DESCRIPTOR_HEADER(self.sii.search(security_id).data)
            offset = sii_entry.Offset
        else:
            # Otherwise we need to "bruteforce" our way to the correct offset
            offset = 0

        for entry in self._iter_entries(offset):
            if entry.SecurityId == security_id:
                # Jackpot
                return SecurityDescriptor(self.sds)

        raise KeyError(f"Couldn't find security ID: {security_id}")

    def descriptors(self) -> Iterator[SecurityDescriptor]:
        """Return all security descriptors."""
        for _ in self._iter_entries():
            yield SecurityDescriptor(self.sds)


def _parse_security_id_key(key: bytes) -> int | None:
    """Parse a ``$SII`` key (a little endian ULONG SecurityId) into an integer."""
    if len(key) < 4:
        return None

    return int.from_bytes(key[:4], "little")


def _descriptor_header_issue(content: bytes) -> str | None:
    """Validate the relative security descriptor header and the ranges it declares."""
    if len(content) < len(c_ntfs._SECURITY_DESCRIPTOR_RELATIVE):
        return f"descriptor body is too short ({len(content)} bytes)"

    header = c_ntfs._SECURITY_DESCRIPTOR_RELATIVE(bytes(content))
    if header.Revision != 1:
        return f"unsupported descriptor revision {header.Revision}"

    if not header.Control & c_ntfs.SECURITY_DESCRIPTOR_CONTROL.SE_SELF_RELATIVE:
        return "descriptor is not self relative"

    body_len = len(content)
    for field_name in ("Owner", "Group", "Sacl", "Dacl"):
        offset = getattr(header, field_name)
        if offset and offset >= body_len:
            return f"descriptor {field_name} offset {offset:#x} is outside the descriptor body"

    for field_name in ("Sacl", "Dacl"):
        offset = getattr(header, field_name)
        if offset:
            issue = _acl_issue(content, offset)
            if issue:
                return f"descriptor {field_name} {issue}"

    return None


def _acl_issue(content: bytes, offset: int) -> str | None:
    """Validate the ACL at ``offset`` within a descriptor body and its ACE ranges."""
    if offset + len(c_ntfs._ACL) > len(content):
        return "header is truncated"

    try:
        acl = c_ntfs._ACL(bytes(content[offset:]))
    except EOFError:
        return "header is truncated"

    if acl.AclSize < len(c_ntfs._ACL) or offset + acl.AclSize > len(content):
        return f"size {acl.AclSize} exceeds the descriptor body"

    position = offset + len(c_ntfs._ACL)
    acl_end = offset + acl.AclSize
    for ace_index in range(acl.AceCount):
        if position + len(c_ntfs._ACE_HEADER) > acl_end:
            return f"ACE {ace_index} header exceeds the ACL size"

        try:
            ace = c_ntfs._ACE_HEADER(bytes(content[position:acl_end]))
        except EOFError:
            return f"ACE {ace_index} header is truncated"

        if ace.AceSize < len(c_ntfs._ACE_HEADER):
            return f"ACE {ace_index} has invalid size {ace.AceSize}"

        if position + ace.AceSize > acl_end:
            return f"ACE {ace_index} extends past the ACL size"

        position += ace.AceSize

    return None


def _select_content(
    evidence: SecurityDescriptorEvidence, locations: dict[int, SDSLocation] | None = None
) -> tuple[bytes | None, str]:
    """Select a descriptor content, or explain why the evidence is ambiguous.

    Selection rules, in order:

    1. If multiple distinct contents exist, no content is selected; the conflict is reported with every location.
    2. If the index points at a complete copy, select the content shared by the valid indexed copies.
    3. If the indexed copy is corrupt but its stored bytes match a candidate byte-for-byte, the candidate can be
       selected on that explicit basis.
    4. In SDS-only mode (no ``$SII``), select the single content found across the mirrored copies.
    5. If the index exists but its target cannot be compared with any candidate, report the candidate but do not
       select it: returning it would silently substitute different content.
    """
    contents = list(evidence.copies.items())

    if len(contents) > 1:
        details = []
        for position, (_, content_locations) in enumerate(contents):
            offsets = ", ".join(f"{loc.offset:#x} (mirror {loc.mirror:#x})" for loc in content_locations)
            details.append(f"content {position + 1} at {offsets}")

        return None, "conflicting contents: " + "; ".join(details)

    if not contents:
        truncated = [loc for loc in evidence.locations if loc.truncated]
        if truncated:
            return None, "all candidate copies are truncated or structurally invalid"

        return None, "no complete security descriptor copy found"

    content, content_locations = contents[0]

    indexed = [loc for loc in content_locations if loc.indexed]
    if indexed:
        return content, (
            f"{len(content_locations)} identical valid cop{'y' if len(content_locations) == 1 else 'ies'} agree; "
            f"indexed copy verified at {indexed[0].offset:#x}"
        )

    if evidence.index_entries:
        indexed_targets = [loc for loc in (locations or {}).values() if loc.indexed and loc.content is not None]
        if indexed_targets and any(loc.content == content for loc in indexed_targets):
            return content, (
                "indexed copy is structurally invalid but its stored bytes match the candidate "
                f"at {content_locations[0].offset:#x} byte-for-byte; selection is based on that equality"
            )

        return None, (
            "no complete indexed copy exists; candidate contents are reported separately and were not verified "
            "against the index: " + ", ".join(f"{loc.offset:#x}" for loc in content_locations)
        )

    if evidence.index_readable is False:
        return content, (
            f"$SII index unreadable ({evidence.index_error}); {len(content_locations)} identical complete SDS "
            f"cop{'y' if len(content_locations) == 1 else 'ies'} found"
        )

    if evidence.index_error is not None:
        return content, (
            f"no $SII index entry ({evidence.index_error}); {len(content_locations)} identical complete SDS "
            f"cop{'y' if len(content_locations) == 1 else 'ies'} found"
        )

    return content, (
        f"no $SII index available; {len(content_locations)} identical complete SDS "
        f"cop{'y' if len(content_locations) == 1 else 'ies'}"
    )


class SecurityDescriptor:
    """Parse a security descriptor from a file-like object.

    Args:
        fh: The file-like object to parse a security descriptor from.
    """

    def __init__(self, fh: BinaryIO):
        offset = fh.tell()
        self.header = c_ntfs._SECURITY_DESCRIPTOR_RELATIVE(fh)

        self.owner = None
        self.group = None
        self.sacl = None
        self.dacl = None

        if self.header.Owner:
            fh.seek(offset + self.header.Owner)
            self.owner = read_sid(fh)

        if self.header.Group:
            fh.seek(offset + self.header.Group)
            self.group = read_sid(fh)

        if self.header.Sacl:
            fh.seek(offset + self.header.Sacl)
            self.sacl = ACL(fh)

        if self.header.Dacl:
            fh.seek(offset + self.header.Dacl)
            self.dacl = ACL(fh)


class ACL:
    """Parse an ACL from a file-like object.

    Args:
        fh: The file-like object to parse an ACL from.
    """

    def __init__(self, fh: BinaryIO):
        self.header = c_ntfs._ACL(fh)
        self.ace = [ACE(fh) for _ in range(self.header.AceCount)]


class ACE:
    """Parse an ACE from a file-like object.

    Args:
        fh: The file-like object to parse an ACE from.
    """

    def __init__(self, fh: BinaryIO):
        self.header = c_ntfs._ACE_HEADER(fh)
        self.data = fh.read(self.header.AceSize - len(c_ntfs._ACE_HEADER))

        self.mask = None
        self.flags = None
        self.object_type = None
        self.inherited_object_type = None
        self.sid = None
        self.compound_type = None
        self.server_sid = None

        buf = io.BytesIO(self.data)
        if self.is_standard_ace:
            self.mask = c_ntfs.DWORD(buf)
            self.sid = read_sid(buf)
        elif self.is_compound_ace:
            self.mask = c_ntfs.DWORD(buf)
            self.compound_type = c_ntfs.COMPOUND_ACE_TYPE(buf)
            c_ntfs.USHORT(buf)
            self.server_sid = read_sid(buf)
            self.sid = read_sid(buf)
        elif self.is_object_ace:
            self.mask = c_ntfs.DWORD(buf)
            self.flags = c_ntfs.DWORD(buf)
            if self.flags & ACE_OBJECT_FLAGS.ACE_OBJECT_TYPE_PRESENT:
                self.object_type = UUID(bytes_le=buf.read(16))
            if self.flags & ACE_OBJECT_FLAGS.ACE_INHERITED_OBJECT_TYPE_PRESENT:
                self.inherited_object_type = UUID(bytes_le=buf.read(16))
            self.sid = read_sid(buf)

        self.application_data = buf.read() or None

    def __repr__(self) -> str:
        if self.is_standard_ace:
            return f"<{self.header.AceType.name} mask=0x{self.mask:x} sid={self.sid}>"
        if self.is_compound_ace:
            return (
                f"<{self.header.AceType.name} mask=0x{self.mask:x} type={self.compound_type.name}"
                f" server_sid={self.server_sid} client_sid={self.sid}>"
            )
        if self.is_object_ace:
            return (
                f"<{self.header.AceType.name} mask=0x{self.mask:x} flags={self.flags} object_type={self.object_type}"
                f" inherited_object_type={self.inherited_object_type} sid={self.sid}>"
            )
        return f"<ACE type={self.header.AceType} flags={self.header.AceFlags} size={self.header.AceSize}>"

    @property
    def type(self) -> ACE_TYPE:
        """Return the ACE type."""
        return self.header.AceType

    @property
    def is_standard_ace(self) -> bool:
        """Return whether this ACE is a standard ACE."""
        return self.header.AceType in (
            ACE_TYPE.ACCESS_ALLOWED,
            ACE_TYPE.ACCESS_DENIED,
            ACE_TYPE.SYSTEM_AUDIT,
            ACE_TYPE.SYSTEM_ALARM,
            ACE_TYPE.ACCESS_ALLOWED_CALLBACK,
            ACE_TYPE.ACCESS_DENIED_CALLBACK,
            ACE_TYPE.SYSTEM_AUDIT_CALLBACK,
            ACE_TYPE.SYSTEM_ALARM_CALLBACK,
            ACE_TYPE.SYSTEM_MANDATORY_LABEL,
            ACE_TYPE.SYSTEM_RESOURCE_ATTRIBUTE,
            ACE_TYPE.SYSTEM_SCOPED_POLICY_ID,
            ACE_TYPE.SYSTEM_PROCESS_TRUST_LABEL,
            ACE_TYPE.SYSTEM_ACCESS_FILTER,
        )

    @property
    def is_compound_ace(self) -> bool:
        """Return whether this ACE is a compound ACE."""
        return self.header.AceType in (ACE_TYPE.ACCESS_ALLOWED_COMPOUND,)

    @property
    def is_object_ace(self) -> bool:
        """Return whether this ACE is an object ACE."""
        return self.header.AceType in (
            ACE_TYPE.ACCESS_ALLOWED_OBJECT,
            ACE_TYPE.ACCESS_DENIED_OBJECT,
            ACE_TYPE.SYSTEM_AUDIT_OBJECT,
            ACE_TYPE.SYSTEM_ALARM_OBJECT,
            ACE_TYPE.ACCESS_ALLOWED_CALLBACK_OBJECT,
            ACE_TYPE.ACCESS_DENIED_CALLBACK_OBJECT,
            ACE_TYPE.SYSTEM_AUDIT_CALLBACK_OBJECT,
            ACE_TYPE.SYSTEM_ALARM_CALLBACK_OBJECT,
        )
