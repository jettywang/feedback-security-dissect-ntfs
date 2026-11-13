"""Boundary tests for NTFS data stream reading.

These tests use hand-crafted MFT records and volume byte maps to pin down how
``ValidDataLength``, ``FileSize`` and ``AllocatedLength`` interact when reading
data streams, for both resident and non-resident (named) attributes.

Byte categories used in the expectations:

- valid content: bytes ``[0, ValidDataLength)``, returned as-is from disk.
- logical zeroes: bytes ``[ValidDataLength, FileSize)`` (uninitialized tail) and sparse
  runs, which must read back as ``\\x00`` even if the allocated clusters contain residue.
- slack residue: bytes ``[FileSize, AllocatedLength)``, never returned by a normal read,
  but returned with their real physical content when explicitly reading with
  ``allocated=True`` (for recovery analysis).
"""

from __future__ import annotations

import io
import struct

import pytest

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
from dissect.ntfs.exceptions import FileNotFoundError
from dissect.ntfs.mft import MftRecord
from dissect.ntfs.ntfs import NTFS

CLUSTER_SIZE = 16
RECORD_SIZE = 1024
USA_OFFSET = 0x30
FIRST_ATTRIBUTE_OFFSET = 0x38

# Volume byte map (cluster size 16). Residue bytes are deliberately non-zero so that
# zero-filled reads can never be mistaken for physical disk content.
CONTENT = b"Hello, NTFS!"  # 12 bytes of valid content (ValidDataLength = 12)
TAIL_RESIDUE = b"TAILRES!"  # 8 bytes of residue in the uninitialized tail [VDL, FileSize)
SLACK_RESIDUE = b"slack-slack!"  # 12 bytes of residue in the slack space [FileSize, AllocatedLength)
FRAGMENT_ONE = b"first-fragment00"  # 16 bytes, one full cluster
FRAGMENT_THREE = b"third-fragment00"  # 16 bytes, one full cluster
ADS_CONTENT = b"ADS-ID"  # 6 bytes of valid named stream content
ADS_SLACK = b"ads-slack!"  # 10 bytes of named stream slack residue


def _varint_bytes(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    if value >> (length * 8 - 1):
        length += 1
    return value.to_bytes(length, "little", signed=True)


def _mapping_pairs(runs: list[tuple[int | None, int]]) -> bytes:
    pairs = b""
    offset = 0
    for lcn, count in runs:
        size_bytes = _varint_bytes(count)
        if lcn is None:
            pairs += bytes([len(size_bytes)]) + size_bytes
        else:
            delta_bytes = _varint_bytes(lcn - offset)
            offset = lcn
            pairs += bytes([(len(delta_bytes) << 4) | len(size_bytes)]) + size_bytes + delta_bytes
    return pairs + b"\x00"


def _resident_attribute(type_code: int, value: bytes, name: str = "") -> bytes:
    name_bytes = name.encode("utf-16-le")
    name_offset = 0x18 if name else 0
    value_offset = 0x18 + len(name_bytes)
    record_length = (value_offset + len(value) + 7) & ~7

    header = struct.pack("<IIBBHHH", type_code, record_length, 0, len(name), name_offset, 0, 0)
    header += struct.pack("<IHBB", len(value), value_offset, 0, 0)
    return (header + name_bytes + value).ljust(record_length, b"\x00")


def _nonresident_attribute(
    type_code: int,
    runs: list[tuple[int | None, int]],
    *,
    file_size: int,
    valid_data_length: int,
    allocated_length: int,
    name: str = "",
) -> bytes:
    name_bytes = name.encode("utf-16-le")
    name_offset = 0x48 if name else 0
    mapping_pairs_offset = 0x48 + len(name_bytes)
    mapping_pairs = _mapping_pairs(runs)
    record_length = (mapping_pairs_offset + len(mapping_pairs) + 7) & ~7
    highest_vcn = sum(count for _, count in runs) - 1

    header = struct.pack("<IIBBHHH", type_code, record_length, 1, len(name), name_offset, 0, 0)
    header += struct.pack("<QQ", 0, highest_vcn)
    header += struct.pack("<HB", mapping_pairs_offset, 0) + b"\x00" * 5
    header += struct.pack("<qqq", allocated_length, file_size, valid_data_length)
    header += struct.pack("<q", allocated_length)
    return (header + name_bytes + mapping_pairs).ljust(record_length, b"\x00")


def _mft_record(*attributes: bytes) -> bytes:
    attrs = b"".join(attributes)
    end = struct.pack("<II", 0xFFFFFFFF, 0)
    bytes_in_use = FIRST_ATTRIBUTE_OFFSET + len(attrs) + len(end)

    header = struct.pack("<4sHH", b"FILE", USA_OFFSET, 3)
    header += struct.pack("<Q", 0)  # Lsn
    header += struct.pack("<HHHH", 1, 1, FIRST_ATTRIBUTE_OFFSET, 1)  # SequenceNumber, refs, offset, flags
    header += struct.pack("<II", bytes_in_use, RECORD_SIZE)  # BytesInUse, BytesAllocated
    header += struct.pack("<QH", 0, 1)  # BaseFileRecordSegment, NextAttributeInstance
    header = header.ljust(USA_OFFSET, b"\x00")
    header += b"\xff\xff" + b"\x00" * 4  # Update sequence array: sample + 2 replacements
    header = header.ljust(FIRST_ATTRIBUTE_OFFSET, b"\x00")

    record = (header + attrs + end).ljust(RECORD_SIZE, b"\x00")
    # The last two bytes of each sector must match the update sequence sample
    return record[:510] + b"\xff\xff" + record[512:1022] + b"\xff\xff"


def _ntfs_with_clusters(clusters: dict[int, bytes]) -> NTFS:
    buffer = bytearray((max(clusters) + 1) * CLUSTER_SIZE)
    for lcn, data in clusters.items():
        assert len(data) == CLUSTER_SIZE
        buffer[lcn * CLUSTER_SIZE : (lcn + 1) * CLUSTER_SIZE] = data

    ntfs = NTFS()
    ntfs.fh = io.BytesIO(bytes(buffer))
    ntfs.cluster_size = CLUSTER_SIZE
    return ntfs


@pytest.fixture
def vdl_record() -> MftRecord:
    """Unnamed non-resident $DATA with ValidDataLength < FileSize < AllocatedLength."""
    ntfs = _ntfs_with_clusters(
        {
            4: CONTENT + TAIL_RESIDUE[:4],
            5: TAIL_RESIDUE[4:] + SLACK_RESIDUE,
        }
    )
    return MftRecord.from_bytes(
        _mft_record(
            _nonresident_attribute(
                ATTRIBUTE_TYPE_CODE.DATA,
                [(4, 2)],
                file_size=20,
                valid_data_length=12,
                allocated_length=32,
            )
        ),
        ntfs,
    )


@pytest.fixture
def fragmented_record() -> MftRecord:
    """Unnamed non-resident $DATA with a sparse run between two fragments."""
    ntfs = _ntfs_with_clusters({6: FRAGMENT_ONE, 8: FRAGMENT_THREE})
    return MftRecord.from_bytes(
        _mft_record(
            _nonresident_attribute(
                ATTRIBUTE_TYPE_CODE.DATA,
                [(6, 1), (None, 1), (8, 1)],
                file_size=40,
                valid_data_length=40,
                allocated_length=48,
            )
        ),
        ntfs,
    )


@pytest.fixture
def named_record() -> MftRecord:
    """Named non-resident $DATA stream with slack space."""
    ntfs = _ntfs_with_clusters({10: ADS_CONTENT + ADS_SLACK})
    return MftRecord.from_bytes(
        _mft_record(
            _nonresident_attribute(
                ATTRIBUTE_TYPE_CODE.DATA,
                [(10, 1)],
                file_size=6,
                valid_data_length=6,
                allocated_length=16,
                name="ads",
            )
        ),
        ntfs,
    )


def test_resident_stream() -> None:
    record = MftRecord.from_bytes(
        _mft_record(
            _resident_attribute(ATTRIBUTE_TYPE_CODE.DATA, b"resident-data"),
            _resident_attribute(ATTRIBUTE_TYPE_CODE.DATA, b"named-ads-data", name="ads"),
            _resident_attribute(ATTRIBUTE_TYPE_CODE.LOGGED_UTILITY_STREAM, b"logged-utility", name="ads"),
        )
    )

    # Resident attributes have no allocated size or valid data length
    assert record.attributes.DATA.header.allocated_size is None
    assert record.attributes.DATA.header.valid_data_size is None

    # The allocated mode has no meaning for resident attributes, the value is returned as-is
    assert record.size() == 13
    assert record.size(allocated=True) == 13
    assert record.open().read() == b"resident-data"
    assert record.open(allocated=True).read() == b"resident-data"

    # A resident read is bounded by the value length and must not bleed into the record
    fh = record.open()
    fh.seek(9)
    assert fh.read(8) == b"data"
    assert fh.read() == b""

    # Two attributes with the same name but different types are selected by type
    assert record.size("ads") == 14
    assert record.open("ads").read() == b"named-ads-data"
    assert record.size("ads", ATTRIBUTE_TYPE_CODE.LOGGED_UTILITY_STREAM) == 14
    assert record.open("ads", ATTRIBUTE_TYPE_CODE.LOGGED_UTILITY_STREAM).read() == b"logged-utility"


def test_nonresident_valid_data_length(vdl_record: MftRecord) -> None:
    # ValidDataLength (12) < FileSize (20) < AllocatedLength (32)
    header = vdl_record.attributes.DATA.header
    assert header.valid_data_size == 12
    assert header.size == 20
    assert header.allocated_size == 32

    assert vdl_record.size() == 20
    assert vdl_record.size(allocated=True) == 32

    # A normal read is bounded by FileSize and zero-fills the uninitialized tail,
    # the residue on disk (TAIL_RESIDUE) must not be treated as file content
    assert vdl_record.open().read() == CONTENT + b"\x00" * 8

    # An explicit allocated read includes the slack space with its real physical content
    assert vdl_record.open(allocated=True).read() == CONTENT + TAIL_RESIDUE + SLACK_RESIDUE

    # Seeking across the ValidDataLength boundary on a normal read
    fh = vdl_record.open()
    fh.seek(10)
    assert fh.read(6) == b"S!" + b"\x00" * 4

    # Seeking across the FileSize boundary on an allocated read returns physical residue
    fh = vdl_record.open(allocated=True)
    fh.seek(14)
    assert fh.read(10) == TAIL_RESIDUE[2:] + SLACK_RESIDUE[:4]

    # The single attribute API behaves the same
    attr = vdl_record.attributes.find("", ATTRIBUTE_TYPE_CODE.DATA)[0]
    assert attr.open().read() == CONTENT + b"\x00" * 8
    assert attr.data() == CONTENT + b"\x00" * 8


def test_nonresident_sparse_fragments(fragmented_record: MftRecord) -> None:
    assert fragmented_record.dataruns() == [(6, 1), (None, 1), (8, 1)]

    assert fragmented_record.size() == 40
    assert fragmented_record.size(allocated=True) == 48

    # The sparse run reads back as logical zeroes
    assert fragmented_record.open().read() == FRAGMENT_ONE + b"\x00" * 16 + FRAGMENT_THREE[:8]

    # Seek and read across the fragment, sparse run and fragment boundary
    fh = fragmented_record.open()
    fh.seek(12)
    assert fh.read(24) == FRAGMENT_ONE[12:] + b"\x00" * 16 + FRAGMENT_THREE[:4]

    fh.seek(-8, io.SEEK_END)
    assert fh.read() == FRAGMENT_THREE[:8]

    # The allocated read includes the full last cluster from disk
    fh = fragmented_record.open(allocated=True)
    assert fh.read() == FRAGMENT_ONE + b"\x00" * 16 + FRAGMENT_THREE
    fh.seek(40)
    assert fh.read(8) == FRAGMENT_THREE[8:]


def test_named_nonresident_stream(named_record: MftRecord) -> None:
    # The record only has a named stream, the default stream does not exist
    with pytest.raises(FileNotFoundError):
        named_record.open()

    assert named_record.size("ads") == 6
    assert named_record.size("ads", allocated=True) == 16

    # A normal read of the named stream is bounded by FileSize
    assert named_record.open("ads").read() == ADS_CONTENT

    # An explicit allocated read of the named stream returns the physical slack residue
    fh = named_record.open("ads", allocated=True)
    assert fh.read() == ADS_CONTENT + ADS_SLACK
