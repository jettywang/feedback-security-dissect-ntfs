from __future__ import annotations

import io
import struct

import pytest

from dissect.ntfs import NTFS, IntegrityStatus
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, c_ntfs
from dissect.ntfs.exceptions import StreamVerificationError
from dissect.ntfs.mft import Mft

RECORD_SIZE = 1024
CLUSTER_SIZE = 4096
BASE_SEGMENT = 40
FIRST_EXTENSION = 41

FILE_RECORD_IN_USE = 0x0001
FILE_RECORD_IS_DIRECTORY = 0x0002


def encode_varint(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    length = (value.bit_length() + 8) // 8
    return value.to_bytes(length, "little", signed=value < 0)


def encode_runs(runs: list[tuple[int | None, int]]) -> bytes:
    result = b""
    previous_lcn = 0
    for lcn, count in runs:
        count_bytes = encode_varint(count)
        if lcn is None:
            result += bytes([len(count_bytes)]) + count_bytes
            continue

        delta = lcn - previous_lcn
        delta_bytes = encode_varint(delta)
        header = len(count_bytes) | (len(delta_bytes) << 4)
        result += bytes([header]) + count_bytes + delta_bytes
        previous_lcn = lcn
    return result + b"\x00"


def nonresident_data(
    lowest_vcn: int,
    highest_vcn: int,
    runs: list[tuple[int | None, int]],
    file_size: int,
    name: str = "",
) -> bytes:
    name_bytes = name.encode("utf-16-le")
    mapping = encode_runs(runs)

    # Build the fixed header first to learn where the mapping pairs begin.
    fixed_header = (
        struct.pack("=IIBBHHH", 0, 0, 1, 0, 0, 0, 0)
        + struct.pack("=QQ", lowest_vcn, highest_vcn)
        + struct.pack("=HB", 0, 0)  # mapping pairs offset placeholder, compression unit
        + b"\x00" * 5
        + struct.pack("=QQQQ", file_size, file_size, file_size, file_size)
    )
    mapping_offset = len(fixed_header)
    name_offset = mapping_offset + len(mapping) if name_bytes else 0
    record_length = (mapping_offset + len(mapping) + len(name_bytes) + 7) & ~7

    header = struct.pack(
        "=IIBBHHH",
        ATTRIBUTE_TYPE_CODE.DATA,
        record_length,
        1,  # non-resident
        len(name),
        name_offset,
        0,  # flags
        0,  # instance
    )
    header += struct.pack("=QQ", lowest_vcn, highest_vcn)
    header += struct.pack("=HB", mapping_offset, 0)
    header += b"\x00" * 5
    header += struct.pack("=QQQQ", file_size, file_size, file_size, file_size)
    assert len(header) == mapping_offset

    raw = bytearray(header)
    raw += name_bytes + mapping
    raw += b"\x00" * (record_length - len(raw))
    return bytes(raw)


def attribute_list_entry(
    lowest_vcn: int,
    segment: int,
    sequence: int,
    name: str = "",
    attr_type: int = ATTRIBUTE_TYPE_CODE.DATA,
) -> bytes:
    name_bytes = name.encode("utf-16-le")
    # Fixed portion: type(4) record length(2) name length/offset(2) lowest vcn(8) reference(8) reserved(2) = 26.
    name_offset = 26 if name_bytes else 0
    record_length = 26 + len(name_bytes)
    header = struct.pack("=IHBBQ", attr_type, record_length, len(name), name_offset, lowest_vcn)
    reference = struct.pack("=IHH", segment & 0xFFFFFFFF, segment >> 32, sequence)
    return header + reference + b"\x00\x00" + name_bytes


def resident_attribute(attr_type: int, payload: bytes) -> bytes:
    # The resident value follows the 24 byte common+resident header. cstruct reads the full union
    # footprint (72 bytes), so keep the record at least that large to parse cleanly.
    value_offset = 24
    record_length = max(72, (value_offset + len(payload) + 7) & ~7)
    header = struct.pack(
        "=IIBBHHH",
        attr_type,
        record_length,
        0,  # resident
        0,  # name length
        0,  # name offset
        0,  # flags
        0,  # instance
    )
    header += struct.pack("=IHBB", len(payload), value_offset, 0, 0)
    assert len(header) == value_offset
    raw = bytearray(header)
    raw += payload
    raw += b"\x00" * (record_length - len(raw))
    return bytes(raw)


def end_attribute() -> bytes:
    return struct.pack("<II", 0xFFFFFFFF, 0)


def mft_record(
    segment: int,
    sequence: int,
    attributes: bytes,
    base_segment: int = 0,
    base_sequence: int = 0,
    flags: int = FILE_RECORD_IN_USE,
) -> bytes:
    first_attribute_offset = 0x38
    bytes_in_use = first_attribute_offset + len(attributes)

    header = c_ntfs._FILE_RECORD_SEGMENT_HEADER()
    header.MultiSectorHeader.Signature = b"FILE"
    header.MultiSectorHeader.UpdateSequenceArrayOffset = 0x2A
    header.MultiSectorHeader.UpdateSequenceArraySize = 3
    header.SequenceNumber = sequence
    header.ReferenceCount = 1
    header.FirstAttributeOffset = first_attribute_offset
    header.Flags = flags
    header.BytesInUse = bytes_in_use
    header.BytesAllocated = RECORD_SIZE
    header.BaseFileRecordSegment.SegmentNumberLowPart = base_segment & 0xFFFFFFFF
    header.BaseFileRecordSegment.SegmentNumberHighPart = base_segment >> 32
    header.BaseFileRecordSegment.SequenceNumber = base_sequence
    header.NextAttributeInstance = 0

    data = bytearray(header.dumps())
    data += b"\x00" * (first_attribute_offset - len(data))
    assert len(data) == first_attribute_offset
    data += attributes
    data.extend(b"\x00" * (RECORD_SIZE - len(data)))

    fixup_offset = 0x2A
    fixup_sequence = 0x0001
    struct.pack_into("<H", data, fixup_offset, fixup_sequence)
    struct.pack_into("<H", data, fixup_offset + 2, struct.unpack("<H", data[510:512])[0])
    struct.pack_into("<H", data, fixup_offset + 4, struct.unpack("<H", data[1022:1024])[0])
    struct.pack_into("<H", data, 510, fixup_sequence)
    struct.pack_into("<H", data, 1022, fixup_sequence)
    return bytes(data)


def build_volume(records: dict[int, bytes], clusters: dict[int, bytes]) -> tuple[io.BytesIO, io.BytesIO]:
    # The MFT is addressed by record index, so every segment up to the highest must exist contiguously.
    mft = b"".join(records.get(index, b"\x00" * RECORD_SIZE) for index in range(max(records) + 1))
    volume = bytearray()
    for lcn in sorted(clusters):
        end = (lcn + 1) * CLUSTER_SIZE
        if len(volume) < end:
            volume.extend(b"\x00" * (end - len(volume)))
        volume[lcn * CLUSTER_SIZE : end] = clusters[lcn]
    return io.BytesIO(bytes(volume)), io.BytesIO(mft)


def make_fragmented_file(
    fragments: list[tuple[int, int, list[tuple[int | None, int]]]],
    *,
    list_entries: list[bytes] | None = None,
    extension_sequence: int = 2,
    list_sequence: int | None = None,
    extension_base: int = BASE_SEGMENT,
    file_size: int | None = None,
) -> tuple[NTFS, io.BytesIO]:
    """Build a base record with an $ATTRIBUTE_LIST plus extension records holding the fragments."""
    records: dict[int, bytes] = {}
    clusters: dict[int, bytes] = {}

    referenced_sequence = extension_sequence if list_sequence is None else list_sequence
    total_clusters = max(highest for _, highest, _ in fragments) + 1
    real_size = file_size if file_size is not None else total_clusters * CLUSTER_SIZE

    base_attributes = b""
    extension_records: dict[int, list[bytes]] = {}
    entries = list_entries if list_entries is not None else []

    for index, (lowest_vcn, highest_vcn, runs) in enumerate(fragments):
        segment = FIRST_EXTENSION + index
        extension_records.setdefault(segment, []).append(
            nonresident_data(lowest_vcn, highest_vcn, runs, real_size)
        )
        if list_entries is None:
            entries.append(attribute_list_entry(lowest_vcn, segment, referenced_sequence))

        vcn_cursor = lowest_vcn
        for lcn, count in runs:
            if lcn is None:
                vcn_cursor += count
                continue
            for offset in range(count):
                marker = (vcn_cursor + offset) & 0xFF
                clusters[lcn + offset] = bytes([marker ^ 0x5A]) * CLUSTER_SIZE
            vcn_cursor += count

    base_attributes += resident_attribute(ATTRIBUTE_TYPE_CODE.ATTRIBUTE_LIST, b"".join(entries))
    records[BASE_SEGMENT] = mft_record(BASE_SEGMENT, 1, base_attributes + end_attribute())

    for segment, data_attrs in extension_records.items():
        records[segment] = mft_record(
            segment,
            extension_sequence,
            b"".join(data_attrs) + end_attribute(),
            base_segment=extension_base,
            base_sequence=1,
        )

    volume_fh, mft_fh = build_volume(records, clusters)

    # Provide minimal system records (segment 0 = $MFT, segment 5 = root directory) so that NTFS
    # construction and its best-effort $Secure lookup succeed without a real on-disk filesystem.
    raw_mft = bytearray(mft_fh.getvalue())
    for system_segment in (0, 5):
        system_record = mft_record(
            system_segment,
            1,
            end_attribute(),
            flags=FILE_RECORD_IN_USE | (FILE_RECORD_IS_DIRECTORY if system_segment == 5 else 0),
        )
        raw_mft[system_segment * RECORD_SIZE : (system_segment + 1) * RECORD_SIZE] = system_record
    mft_fh = io.BytesIO(bytes(raw_mft))

    # Parse the MFT without a boot sector (default geometry), then attach the synthetic volume for reads.
    ntfs = NTFS(mft=mft_fh)
    ntfs.fh = volume_fh
    return ntfs, volume_fh


def test_verify_normal_fragmented_stream_with_sparse_run() -> None:
    # Three fragments, VCN 0..7, with an explicit sparse run (VCN 3) inside the first fragment.
    fragments = [
        (0, 3, [(10, 3), (None, 1)]),
        (4, 5, [(20, 2)]),
        (6, 7, [(30, 2)]),
    ]
    ntfs, _ = make_fragmented_file(fragments)

    record = ntfs.mft.get(BASE_SEGMENT)
    integrity = record.stream_integrity()

    # Sparse zero filling is declared explicitly, so the stream is complete but carries the SPARSE state.
    assert integrity.verified is False
    assert integrity.complete is True
    assert integrity.status is IntegrityStatus.SPARSE
    assert [fragment.segment for fragment in integrity.fragments] == [41, 42, 43]
    assert integrity.sparse_vcns == [(3, 3)]
    assert integrity.gap_vcns == []
    assert integrity.overlap_vcns == []

    stream = record.open_verified()
    data = stream.read()
    assert len(data) == 8 * CLUSTER_SIZE
    # Sparse cluster reads back as explicit zeros, while allocated clusters carry their markers.
    assert data[3 * CLUSTER_SIZE : 4 * CLUSTER_SIZE] == b"\x00" * CLUSTER_SIZE
    assert data[0:1] == bytes([(0 ^ 0x5A)])
    assert stream.integrity.status is IntegrityStatus.SPARSE

    # Fragment provenance resolves to the exact extension record for any byte offset.
    sources = integrity.source_at(5 * CLUSTER_SIZE + 10)
    assert len(sources) == 1
    assert sources[0].segment == 42


def test_verify_missing_fragment_is_gap_not_sparse() -> None:
    # Fragments cover VCN 0..1 and 4..5; VCN 2..3 are a genuine evidence gap.
    fragments = [
        (0, 1, [(10, 2)]),
        (4, 5, [(20, 2)]),
    ]
    ntfs, _ = make_fragmented_file(fragments)

    record = ntfs.mft.get(BASE_SEGMENT)
    integrity = record.stream_integrity()

    assert integrity.complete is False
    assert integrity.status & IntegrityStatus.GAP
    assert not (integrity.status & IntegrityStatus.SPARSE)
    assert integrity.gap_vcns == [(2, 3)]
    assert integrity.sparse_vcns == []
    assert any("Evidence gap" in issue for issue in integrity.issues)

    stream = record.open_verified()
    data = stream.read()
    # The gap must read back as explicit zeros and must not be confused with a sparse run.
    assert data[2 * CLUSTER_SIZE : 4 * CLUSTER_SIZE] == b"\x00" * (2 * CLUSTER_SIZE)
    assert data[0:1] != b"\x00"
    with pytest.raises(StreamVerificationError):
        record.open_verified(strict=True)


def test_verify_overlapping_fragments_not_arbitrarily_selected() -> None:
    # Two fragments both claim VCN 4, with conflicting on-disk content.
    fragments = [
        (0, 4, [(10, 5)]),
        (4, 6, [(40, 3)]),
    ]
    ntfs, _ = make_fragmented_file(fragments)

    record = ntfs.mft.get(BASE_SEGMENT)
    integrity = record.stream_integrity()

    assert integrity.complete is False
    assert integrity.status & IntegrityStatus.OVERLAP
    assert integrity.overlap_vcns == [(4, 4)]
    owners = {fragment.segment for fragment in integrity.source_at(4 * CLUSTER_SIZE)}
    assert owners == {41, 42}

    stream = record.open_verified()
    data = stream.read()
    # Conflicting VCN is zero filled rather than picking either fragment after sorting.
    assert data[4 * CLUSTER_SIZE : 5 * CLUSTER_SIZE] == b"\x00" * CLUSTER_SIZE
    # Non-conflicting clusters remain readable from their single verified fragment.
    assert data[0:1] != b"\x00"
    with pytest.raises(StreamVerificationError):
        record.stream_integrity(strict=True)


def test_verify_reused_extension_record_sequence_mismatch() -> None:
    fragments = [
        (0, 3, [(10, 4)]),
        (4, 7, [(20, 4)]),
    ]
    # The attribute list still references sequence 2, but the extension record was reused as seq 3.
    ntfs, _ = make_fragmented_file(fragments, extension_sequence=3, list_sequence=2)

    record = ntfs.mft.get(BASE_SEGMENT)
    integrity = record.stream_integrity()

    assert integrity.complete is False
    assert integrity.status & IntegrityStatus.FOREIGN_FRAGMENT
    assert any("reused" in issue for issue in integrity.issues)
    assert any(fragment.issues for fragment in integrity.fragments if fragment.segment == 42)
    with pytest.raises(StreamVerificationError):
        record.open_verified(strict=True)


def test_verify_foreign_base_record_reference() -> None:
    fragments = [
        (0, 3, [(10, 4)]),
        (4, 7, [(20, 4)]),
    ]
    # Extension records point at a different base record, so they do not belong to this file.
    ntfs, _ = make_fragmented_file(fragments, extension_base=99)

    record = ntfs.mft.get(BASE_SEGMENT)
    integrity = record.stream_integrity()

    assert integrity.status & IntegrityStatus.FOREIGN_FRAGMENT
    assert any("base record reference" in issue for issue in integrity.issues)
    assert integrity.complete is False


def test_verify_attribute_name_mismatch() -> None:
    # The attribute list entry is named "ads", but the actual fragment is an unnamed $DATA.
    fragments = [
        (0, 3, [(10, 4)]),
        (4, 7, [(20, 4)]),
    ]
    entries = [
        attribute_list_entry(0, 41, 2, name=""),
        attribute_list_entry(4, 42, 2, name="ads"),
    ]
    ntfs, _ = make_fragmented_file(fragments, list_entries=entries)

    record = ntfs.mft.get(BASE_SEGMENT)
    integrity = record.stream_integrity()

    assert integrity.status & IntegrityStatus.FOREIGN_FRAGMENT
    assert any("Attribute name mismatch" in issue for issue in integrity.issues)


def test_verify_missing_attribute_list_for_multi_fragment_stream() -> None:
    # Two non-resident fragments live in records without any $ATTRIBUTE_LIST to bind them together.
    first = nonresident_data(0, 3, [(10, 4)], 8 * CLUSTER_SIZE)
    second = nonresident_data(4, 7, [(20, 4)], 8 * CLUSTER_SIZE)

    records = {
        BASE_SEGMENT: mft_record(BASE_SEGMENT, 1, first + end_attribute()),
        FIRST_EXTENSION: mft_record(
            FIRST_EXTENSION, 2, second + end_attribute(), base_segment=BASE_SEGMENT, base_sequence=1
        ),
    }
    clusters = {
        10: b"\x01" * CLUSTER_SIZE,
        11: b"\x02" * CLUSTER_SIZE,
        12: b"\x03" * CLUSTER_SIZE,
        13: b"\x04" * CLUSTER_SIZE,
        20: b"\x05" * CLUSTER_SIZE,
        21: b"\x06" * CLUSTER_SIZE,
        22: b"\x07" * CLUSTER_SIZE,
        23: b"\x08" * CLUSTER_SIZE,
    }
    _, mft_fh = build_volume(records, clusters)
    raw_mft = bytearray(mft_fh.getvalue())
    for system_segment in (0, 5):
        system_record = mft_record(
            system_segment,
            1,
            end_attribute(),
            flags=FILE_RECORD_IN_USE | (FILE_RECORD_IS_DIRECTORY if system_segment == 5 else 0),
        )
        raw_mft[system_segment * RECORD_SIZE : (system_segment + 1) * RECORD_SIZE] = system_record
    ntfs = NTFS(mft=io.BytesIO(bytes(raw_mft)))

    # Manually collect both fragments into one collection, bypassing the (absent) attribute list.
    base = ntfs.mft.get(BASE_SEGMENT)
    extension = ntfs.mft.get(FIRST_EXTENSION)
    from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
    from dissect.ntfs.util import AttributeCollection

    collection = AttributeCollection(
        base.attributes[ATTRIBUTE_TYPE_CODE.DATA] + extension.attributes[ATTRIBUTE_TYPE_CODE.DATA]
    )
    integrity = collection.verify()

    assert integrity.status & IntegrityStatus.ATTRIBUTE_LIST_MISSING
    assert any("$ATTRIBUTE_LIST" in issue for issue in integrity.issues)
    assert len(integrity.fragments) == 2


def test_verify_first_fragment_lives_in_base_record() -> None:
    # The LowestVcn 0 fragment is stored in the base record itself; the second fragment is an extension.
    base_data = nonresident_data(0, 3, [(10, 4)], 8 * CLUSTER_SIZE)
    extension_data = nonresident_data(4, 7, [(20, 4)], 8 * CLUSTER_SIZE)
    entries = (
        attribute_list_entry(0, BASE_SEGMENT, 1)
        + attribute_list_entry(4, FIRST_EXTENSION, 2)
    )
    records = {
        BASE_SEGMENT: mft_record(
            BASE_SEGMENT,
            1,
            resident_attribute(ATTRIBUTE_TYPE_CODE.ATTRIBUTE_LIST, entries) + base_data + end_attribute(),
        ),
        FIRST_EXTENSION: mft_record(
            FIRST_EXTENSION, 2, extension_data + end_attribute(), base_segment=BASE_SEGMENT, base_sequence=1
        ),
    }
    clusters = {lcn: bytes([lcn & 0xFF]) * CLUSTER_SIZE for lcn in (10, 11, 12, 13, 20, 21, 22, 23)}
    volume_fh, mft_fh = build_volume(records, clusters)
    raw_mft = bytearray(mft_fh.getvalue())
    for system_segment in (0, 5):
        system_record = mft_record(
            system_segment,
            1,
            end_attribute(),
            flags=FILE_RECORD_IN_USE | (FILE_RECORD_IS_DIRECTORY if system_segment == 5 else 0),
        )
        raw_mft[system_segment * RECORD_SIZE : (system_segment + 1) * RECORD_SIZE] = system_record
    ntfs = NTFS(mft=io.BytesIO(bytes(raw_mft)))
    ntfs.fh = volume_fh

    record = ntfs.mft.get(BASE_SEGMENT)
    integrity = record.stream_integrity()

    assert integrity.complete is True
    assert integrity.verified is True
    assert [fragment.segment for fragment in integrity.fragments] == [BASE_SEGMENT, FIRST_EXTENSION]
    assert integrity.source_at(0)[0].segment == BASE_SEGMENT
    assert integrity.source_at(5 * CLUSTER_SIZE)[0].segment == FIRST_EXTENSION


def test_backward_compatible_open_still_works() -> None:
    fragments = [
        (0, 3, [(10, 4)]),
        (4, 7, [(20, 4)]),
    ]
    ntfs, _ = make_fragmented_file(fragments)

    record = ntfs.mft.get(BASE_SEGMENT)
    data = record.open().read()
    assert len(data) == 8 * CLUSTER_SIZE
    assert isinstance(record.dataruns(), list)


def test_mft_helper_is_usable_without_real_disk() -> None:
    fragments = [(0, 1, [(10, 2)])]
    ntfs, _ = make_fragmented_file(fragments)
    assert isinstance(ntfs.mft, Mft)
    assert ntfs.mft.get(BASE_SEGMENT).segment == BASE_SEGMENT
