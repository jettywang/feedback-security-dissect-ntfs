"""Deterministic, in-memory reparse buffer samples used by tests and demos.

These are hand-built ``REPARSE_DATA_BUFFER`` byte strings, not files on disk, so
the demo and test-suite stay fully offline and reproducible.
"""

from __future__ import annotations

import struct

from dissect.ntfs.c_ntfs import IO_REPARSE_TAG

SYMLINK = int(IO_REPARSE_TAG.SYMLINK)
MOUNT_POINT = int(IO_REPARSE_TAG.MOUNT_POINT)
LX_SYMLINK = int(IO_REPARSE_TAG.LX_SYMLINK)
UNKNOWN_TAG = 0xA0000099
FILTER_TAG = int(IO_REPARSE_TAG.FILTER_MANAGER)


def _w(text: str) -> bytes:
    return text.encode("utf-16-le")


def build_name_buffer(
    tag: int,
    substitute: str,
    print_name: str,
    relative: bool = False,
    *,
    declared_length: int | None = None,
    sub_offset: int | None = None,
    sub_length: int | None = None,
    print_offset: int | None = None,
    print_length: int | None = None,
    reserved: int = 0,
) -> bytes:
    """Build a name-surrogate (symlink/mount point) reparse buffer."""
    sub_bytes = _w(substitute)
    print_bytes = _w(print_name)
    header_size = 12 if tag == SYMLINK else 8
    # Name offsets are relative to the path buffer, i.e. the byte right after
    # the symbolic-link / mount-point header (offset 0 == first name byte).
    real_sub_offset = 0 if sub_offset is None else sub_offset
    real_print_offset = real_sub_offset + len(sub_bytes) if print_offset is None else print_offset
    path = bytearray()
    path.extend(b"\x00" * header_size)
    path.extend(sub_bytes)
    path.extend(print_bytes)

    if tag == SYMLINK:
        struct.pack_into(
            "<HHHHI",
            path,
            0,
            real_sub_offset,
            len(sub_bytes) if sub_length is None else sub_length,
            real_print_offset,
            len(print_bytes) if print_length is None else print_length,
            1 if relative else 0,
        )
    else:
        struct.pack_into(
            "<HHHH",
            path,
            0,
            real_sub_offset,
            len(sub_bytes) if sub_length is None else sub_length,
            real_print_offset,
            len(print_bytes) if print_length is None else print_length,
        )

    payload = bytes(path)
    data_length = declared_length if declared_length is not None else len(payload)
    return struct.pack("<IHH", tag, data_length, reserved) + payload


def build_raw_buffer(tag: int, payload: bytes, *, declared_length: int | None = None) -> bytes:
    data_length = declared_length if declared_length is not None else len(payload)
    return struct.pack("<IHH", tag, data_length, 0) + payload


def all_samples() -> dict[str, bytes]:
    """Return the curated sample matrix keyed by scenario name."""
    samples: dict[str, bytes] = {}

    samples["symlink_absolute_drive"] = build_name_buffer(
        SYMLINK, r"\??\C:\Windows\Fonts", r"C:\Windows\Fonts"
    )
    samples["symlink_relative"] = build_name_buffer(
        SYMLINK, r"..\..\etc\hosts", r"..\..\etc\hosts", relative=True
    )
    samples["mount_point_volume_guid"] = build_name_buffer(
        MOUNT_POINT,
        r"\??\Volume{12345678-1234-1234-1234-123456789abc}\Data",
        r"Volume{12345678-1234-1234-1234-123456789abc}\Data",
    )
    samples["mount_point_drive"] = build_name_buffer(MOUNT_POINT, r"\??\C:\Target", r"C:\Target")
    samples["symlink_unc"] = build_name_buffer(
        SYMLINK,
        r"\??\UNC\server\share\folder",
        r"\\server\share\folder",
    )

    # Counter-example: PrintName claims a benign local path while SubstituteName
    # actually points somewhere else (also across a volume GUID). Forensically the
    # substitute name is authoritative; the print name must be flagged.
    samples["print_substitute_mismatch"] = build_name_buffer(
        SYMLINK,
        r"\??\Volume{abcdefab-cdef-abcd-efab-cdefabcdefab}\Secret",
        r"C:\Users\Public\Readme.txt",
    )

    # PrintName intentionally empty: UI must fall back to substitute.
    samples["empty_print_name"] = build_name_buffer(SYMLINK, r"\??\C:\OnlySubstitute", "")

    # Corrupt metadata: declared length runs past the bytes actually present.
    good = build_name_buffer(SYMLINK, r"\??\C:\Target", r"C:\Target")
    # Declare 40 more payload bytes than are actually present; the trailing bytes
    # are missing, so the interpreter must flag an overflow rather than trust it.
    samples["declared_length_overflow"] = build_name_buffer(
        SYMLINK, r"\??\C:\Target", r"C:\Target", declared_length=(len(good) - 8 + 40)
    )

    # Corrupt metadata: substitute offset points outside the path buffer.
    samples["substitute_offset_oob"] = build_name_buffer(
        SYMLINK, r"Target", r"Target", relative=True, sub_offset=512
    )

    # Unknown name-surrogate tag: classify by flag bits, no name-pair guarantee.
    samples["unknown_name_surrogate"] = build_name_buffer(UNKNOWN_TAG, r"\??\C:\Mystery", r"C:\Mystery")

    # Filter-managed non-name tag: opaque payload, must not invent names.
    samples["filter_managed_opaque"] = build_raw_buffer(FILTER_TAG, b"\x01\x02\x03\x04" * 4)

    # LX (WSL) symlink: POSIX target, distinct family with its own semantics.
    samples["lx_symlink"] = build_raw_buffer(LX_SYMLINK, b"/var/log/syslog\x00")

    return samples
