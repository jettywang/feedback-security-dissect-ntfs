from __future__ import annotations

import io
import struct
from typing import TYPE_CHECKING

import pytest

from dissect.ntfs.stream import CompressedRunlistStream

if TYPE_CHECKING:
    from typing import BinaryIO

# Use very small clusters and compression units so a handful of compression units fits in memory
CLUSTER_SIZE = 64
COMPRESSION_UNIT = 2
CU_CLUSTERS = 1 << COMPRESSION_UNIT
CU_SIZE = CLUSTER_SIZE * CU_CLUSTERS


def _displacement(offset: int) -> int:
    result = 0
    while offset >= 0x10:
        offset >>= 1
        result += 1
    return result


def lznt1_compress(data: bytes, literal_prefix: int = 16) -> bytes:
    """Compress ``data`` into a valid, deterministic LZNT1 stream.

    This is only a test helper: every 4096 byte chunk starts with literal bytes and continues with references
    to the previous byte, which is enough to create realistic compressed data with a known decompressed size.

    Args:
        data: The data to compress.
        literal_prefix: The number of literal bytes at the start of each chunk. A larger prefix results in a
            larger compressed stream, which is useful to make a compressed unit span multiple clusters.
    """
    out = bytearray()

    for chunk_start in range(0, len(data), 0x1000):
        chunk = data[chunk_start : chunk_start + 0x1000]

        prefix = min(literal_prefix, len(chunk))
        items: list[tuple[bool, int]] = [(False, byte) for byte in chunk[:prefix]]
        pos = prefix
        while pos < len(chunk):
            remaining = len(chunk) - pos
            if remaining < 3:
                items.extend((False, byte) for byte in chunk[pos:])
                break

            length = min(remaining, (0xFFF >> _displacement(pos - 1)) + 3)
            items.append((True, length - 3))
            pos += length

        tokens = bytearray()
        for token_start in range(0, len(items), 8):
            group = items[token_start : token_start + 8]
            flags = 0
            payload = bytearray()
            for index, (is_reference, value) in enumerate(group):
                if is_reference:
                    flags |= 1 << index
                    payload += value.to_bytes(2, "little")
                else:
                    payload += bytes([value])
            tokens += bytes([flags]) + payload

        assert len(tokens) <= 0xFFF
        out += (0x3000 | 0x8000 | (len(tokens) - 1)).to_bytes(2, "little") + bytes(tokens)

    return bytes(out)


def cu_content(seed: int, length: int = CU_SIZE, prefix_length: int = 16) -> bytes:
    """Return unique, compressible content for a compression unit.

    Args:
        seed: Seed to make the content unique per compression unit.
        length: The length of the content.
        prefix_length: The number of distinct leading bytes, which control the compressed size.
    """
    prefix = bytes((seed * 41 + index * 3) & 0xFF for index in range(prefix_length)) if prefix_length else b""
    if length <= prefix_length:
        return prefix[:length]
    return prefix + (prefix[-1:] if prefix else b"\x41") * (length - prefix_length)


class RecordingFile(io.RawIOBase):
    """Minimal in-memory volume that records the physical cluster ranges that are read."""

    def __init__(self) -> None:
        super().__init__()
        self.data = bytearray(256 * CLUSTER_SIZE)
        self.touches: list[tuple[int, int]] = []
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, pos: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = pos
        elif whence == io.SEEK_CUR:
            self._pos += pos
        elif whence == io.SEEK_END:
            self._pos = len(self.data) + pos
        else:
            raise ValueError(f"invalid whence: {whence}")
        return self._pos

    def tell(self) -> int:
        return self._pos

    def read(self, size: int = -1) -> bytes:
        start = self._pos
        end = len(self.data) if size is None or size < 0 else min(len(self.data), start + size)
        if end > start:
            self.touches.append((start // CLUSTER_SIZE, (end - 1) // CLUSTER_SIZE))
        self._pos = end
        return bytes(self.data[start:end])

    def touched_clusters(self) -> set[int]:
        return {
            cluster
            for first, last in self.touches
            for cluster in range(first, last + 1)
        }

    def clear_touches(self) -> None:
        self.touches.clear()

    def write(self, offset: int, data: bytes) -> None:
        self.data[offset : offset + len(data)] = data


class Layout:
    """Builder for a compressed stream runlist and its matching physical data."""

    def __init__(self) -> None:
        self.fh = RecordingFile()
        self.runlist: list[tuple[int | None, int]] = []
        self.expected = bytearray()
        self.cu_clusters: list[set[int]] = []
        self._next_lcn = 1

    def _allocate(self, data: bytes) -> int:
        lcn = self._next_lcn
        self.fh.write(lcn * CLUSTER_SIZE, data)
        clusters = (len(data) + CLUSTER_SIZE - 1) // CLUSTER_SIZE
        self._next_lcn += clusters
        return lcn

    def _new_cu(self) -> list[tuple[int | None, int]]:
        self.cu_clusters.append(set())
        return []

    def _commit_cu(self, fragments: list[tuple[int | None, int]]) -> None:
        self.runlist += fragments
        clusters = self.cu_clusters[-1]
        for lcn, count in fragments:
            if lcn is not None:
                clusters.update(range(lcn, lcn + count))

    def uncompressed(self, seed: int) -> Layout:
        """Add a full, uncompressed compression unit."""
        data = cu_content(seed)
        fragments = self._new_cu()
        fragments.append((self._allocate(data), CU_CLUSTERS))
        self._commit_cu(fragments)
        self.expected += data
        return self

    def compressed(self, seed: int, fragments: list[int] | None = None, length: int = CU_SIZE) -> Layout:
        """Add a compressed compression unit, optionally scattered over multiple physical runs."""
        data = cu_content(seed, length)
        blob = lznt1_compress(data)
        fragments = fragments or [1]

        cu_fragments = self._new_cu()
        start = 0
        for count in fragments:
            chunk = blob[start : start + count * CLUSTER_SIZE]
            cu_fragments.append((self._allocate(chunk.ljust(count * CLUSTER_SIZE, b"\x00")), count))
            start += count * CLUSTER_SIZE
        if sum(fragments) < CU_CLUSTERS:
            cu_fragments.append((None, CU_CLUSTERS - sum(fragments)))
        self._commit_cu(cu_fragments)

        self.expected += data
        return self

    def sparse(self) -> Layout:
        """Add a fully sparse compression unit (a hole)."""
        fragments = self._new_cu()
        fragments.append((None, CU_CLUSTERS))
        self._commit_cu(fragments)
        self.expected += b"\x00" * CU_SIZE
        return self

    def partial(self, seed: int, length: int, compressed: bool = False) -> Layout:
        """Add the final, incomplete compression unit of the stream."""
        data = cu_content(seed, length)
        cu_fragments = self._new_cu()

        if compressed:
            blob = lznt1_compress(data)
            clusters = (len(blob) + CLUSTER_SIZE - 1) // CLUSTER_SIZE
            cu_fragments.append((self._allocate(blob.ljust(clusters * CLUSTER_SIZE, b"\x00")), clusters))
            if clusters < CU_CLUSTERS:
                cu_fragments.append((None, CU_CLUSTERS - clusters))
        else:
            clusters = (length + CLUSTER_SIZE - 1) // CLUSTER_SIZE
            cu_fragments.append((self._allocate(data.ljust(clusters * CLUSTER_SIZE, b"\x00")), clusters))

        self._commit_cu(cu_fragments)
        self.expected += data
        return self

    def stream(self, size: int | None = None) -> CompressedRunlistStream:
        return CompressedRunlistStream(
            self.fh,
            self.runlist,
            len(self.expected) if size is None else size,
            CLUSTER_SIZE,
            COMPRESSION_UNIT,
        )

    def clusters_for(self, offset: int, length: int) -> set[int]:
        """Return the physical clusters that should be touched when reading a range."""
        if length <= 0:
            return set()

        first_cu = offset // CU_SIZE
        last_cu = (offset + length - 1) // CU_SIZE

        clusters = set()
        for cu_block in range(first_cu, last_cu + 1):
            clusters |= self.cu_clusters[cu_block]
        return clusters


def test_sequential_read_of_all_unit_types() -> None:
    layout = Layout()
    layout.uncompressed(1)
    layout.compressed(2)
    layout.compressed(3, fragments=[2, 1])
    layout.sparse()
    layout.uncompressed(4)
    layout.partial(5, 100)

    stream = layout.stream()

    assert stream.read() == bytes(layout.expected)
    assert layout.fh.touched_clusters() == {cluster for cu in layout.cu_clusters for cluster in cu}


def test_scattered_runs_form_one_compressed_unit() -> None:
    # The compressed data of one unit is stored in three separate physical runs followed by sparse padding
    layout = Layout().compressed(1, fragments=[1, 1, 1])
    stream = layout.stream()

    assert stream.read() == bytes(layout.expected)
    # Every physical fragment of the compression unit must have been read
    assert layout.fh.touched_clusters() == {1, 2, 3}


def test_scattered_runs_are_not_independent_compressed_blocks() -> None:
    # A second layout with exactly the same expected content, but the physical runs are in a different
    # order and stored as one contiguous run. If the scattered runs were decompressed independently, the
    # result would be different.
    scattered = Layout().compressed(1, fragments=[1, 1, 1])
    contiguous = Layout().compressed(1, fragments=[3])

    assert scattered.expected == contiguous.expected
    assert scattered.stream().read() == contiguous.stream().read() == bytes(scattered.expected)


@pytest.mark.parametrize(
    ("offset", "length"),
    [
        (0, 1),
        (0, CU_SIZE),
        (1, CU_SIZE - 1),
        (CU_SIZE - 1, 2),
        (CU_SIZE, 1),
        (CU_SIZE + 7, CU_SIZE * 2),
        (CU_SIZE * 2 - 3, 6),
    ],
)
def test_random_reads_match_sequential_reads(offset: int, length: int) -> None:
    layout = Layout()
    layout.uncompressed(1)
    layout.compressed(2, fragments=[2, 1])
    layout.compressed(3, fragments=[1, 1, 1])
    layout.sparse()
    layout.uncompressed(4)

    data = bytes(layout.expected)
    stream = layout.stream()

    layout.fh.clear_touches()
    assert stream.readoffset(offset, length) == data[offset : offset + length]
    assert layout.fh.touched_clusters() == layout.clusters_for(offset, length)


def test_interleaved_random_reads_keep_physical_correspondence() -> None:
    layout = Layout()
    layout.uncompressed(1)
    layout.compressed(2, fragments=[1, 1, 1])
    layout.sparse()
    layout.compressed(3)
    layout.uncompressed(4)
    layout.partial(5, 100)

    data = bytes(layout.expected)
    stream_a = layout.stream()
    stream_b = layout.stream()

    # Compare the sequential read result with interleaved reads through two independent stream objects
    # that share the same backing file handle.
    random_reads = [
        (7, 13),
        (CU_SIZE + 5, 40),
        (CU_SIZE * 2 - 2, 6),
        (CU_SIZE * 2 + 3, 130),
        (CU_SIZE * 3 + 11, 200),
        (len(data) - 20, 20),
    ]

    for offset, length in random_reads:
        stream_a.seek(offset)
        stream_b.seek(offset)
        assert stream_a.read(length) == data[offset : offset + length]
        assert stream_b.read(length) == data[offset : offset + length]

    # Reading an offset in the middle of a unit may read (and decompress) the whole unit, but never
    # physical clusters of an unrelated compression unit.
    layout.fh.clear_touches()
    stream_a.seek(CU_SIZE + 5)
    assert stream_a.read(40) == data[CU_SIZE + 5 : CU_SIZE + 45]
    assert layout.fh.touched_clusters() == layout.clusters_for(CU_SIZE + 5, 40)


def test_corrupt_unit_raises_and_keeps_other_stream_position() -> None:
    layout = Layout()
    layout.uncompressed(1)
    layout.compressed(2, fragments=[1, 1, 1])
    layout.uncompressed(3)

    stream = layout.stream()
    other_stream = layout.stream()

    # Position the other stream in a completely healthy compression unit (the first one)
    other_stream.seek(0)
    other_data = other_stream.read(CU_SIZE)
    assert other_data == bytes(layout.expected[:CU_SIZE])
    other_pos = other_stream.tell()

    # Corrupt the LZNT1 signature of the second compression unit
    corruption_lcn = min(layout.cu_clusters[1])
    layout.fh.write(corruption_lcn * CLUSTER_SIZE, b"\x00\x00")

    with pytest.raises(IOError, match="Decompression failed"):
        stream.seek(CU_SIZE)
        stream.read(CU_SIZE)

    # A failing read must not silently return zeroes, and it must not influence another stream
    assert other_stream.tell() == other_pos
    other_stream.seek(CU_SIZE * 2)
    assert other_stream.read(CU_SIZE) == bytes(layout.expected[CU_SIZE * 2 : CU_SIZE * 3])


def test_corrupt_unit_that_decompresses_to_nothing_raises() -> None:
    layout = Layout().compressed(1)
    # Overwrite the compressed data with bytes that are not a valid LZNT1 stream
    lcn = layout.runlist[0][0]
    layout.fh.write(lcn * CLUSTER_SIZE, b"\xff" * CLUSTER_SIZE)

    with pytest.raises(IOError, match="Decompression failed"):
        layout.stream().read(CU_SIZE)


def test_decompressed_data_shorter_than_unit_raises() -> None:
    layout = Layout().compressed(1)
    # Replace the compressed data with a valid LZNT1 stream that only covers 16 bytes
    lcn = layout.runlist[0][0]
    short_blob = lznt1_compress(cu_content(1, 16))
    layout.fh.write(lcn * CLUSTER_SIZE, short_blob.ljust(CLUSTER_SIZE, b"\x00"))

    with pytest.raises(IOError, match="Decompression failed"):
        layout.stream().read(CU_SIZE)


def test_missing_compression_unit_raises() -> None:
    layout = Layout().uncompressed(1)
    # The stream size claims two compression units, but the runlist only describes one
    stream = layout.stream(size=CU_SIZE * 2)

    assert stream.read(CU_SIZE) == bytes(layout.expected)
    with pytest.raises(IOError, match="Missing compression unit"):
        stream.read(CU_SIZE)


def test_short_physical_run_raises() -> None:
    layout = Layout().uncompressed(1)
    layout.fh.data = layout.fh.data[: CLUSTER_SIZE * 3]

    with pytest.raises(IOError, match="Short read"):
        layout.stream().read()


def test_run_crossing_compression_unit_boundaries() -> None:
    layout = Layout()
    # Two full compression units stored in a single contiguous physical run. A read that crosses the CU
    # boundary must keep using the same physical run instead of restarting at the run's LCN.
    first = cu_content(1)
    second = cu_content(2)
    lcn = layout._allocate(first + second)
    layout.runlist.append((lcn, CU_CLUSTERS * 2))
    layout.cu_clusters.append(set(range(lcn, lcn + CU_CLUSTERS)))
    layout.cu_clusters.append(set(range(lcn + CU_CLUSTERS, lcn + CU_CLUSTERS * 2)))
    layout.expected += first + second
    layout._next_lcn = lcn + CU_CLUSTERS * 2

    data = bytes(layout.expected)
    stream = layout.stream()

    layout.fh.clear_touches()
    assert stream.readoffset(CU_SIZE - 10, 20) == data[CU_SIZE - 10 : CU_SIZE + 10]
    assert layout.fh.touched_clusters() == layout.clusters_for(CU_SIZE - 10, 20)

    layout.fh.clear_touches()
    assert stream.readoffset(CU_SIZE - 3, CU_SIZE + 3) == data[CU_SIZE - 3 : CU_SIZE * 2 + 3]
    assert layout.fh.touched_clusters() == layout.clusters_for(CU_SIZE - 3, CU_SIZE + 3)


def test_final_partial_compressed_unit() -> None:
    layout = Layout().uncompressed(1).partial(2, 100, compressed=True)

    assert layout.stream().read() == bytes(layout.expected)

    # Only ceil(100 / cluster_size) clusters may be read for the final compressed unit
    layout.fh.clear_touches()
    stream = layout.stream()
    stream.seek(CU_SIZE)
    assert stream.read(100) == bytes(layout.expected[CU_SIZE:])
    assert layout.fh.touched_clusters() == layout.clusters_for(CU_SIZE, 100)


def test_scattered_runs_in_descending_physical_order() -> None:
    # Logical order of the runs is defined by the runlist, not by their physical LCN. A compressed unit
    # stored at descending LCNs must still be concatenated and decompressed in runlist order.
    layout = Layout()
    data = cu_content(1)
    blob = lznt1_compress(data)
    assert len(blob) <= CLUSTER_SIZE

    first_lcn = 3
    second_lcn = 1
    layout.fh.write(first_lcn * CLUSTER_SIZE, blob.ljust(CLUSTER_SIZE, b"\x00"))
    layout.runlist.append((first_lcn, 1))
    layout.runlist.append((second_lcn, 1))
    layout.runlist.append((None, CU_CLUSTERS - 2))
    layout.cu_clusters.append({first_lcn, second_lcn})
    layout.expected += data

    stream = layout.stream()
    assert stream.read() == bytes(layout.expected)

    # The physical runs are read in runlist order, but each from its own LCN
    layout.fh.clear_touches()
    stream.seek(0)
    assert stream.read(1) == bytes(layout.expected[:1])
    assert layout.fh.touched_clusters() == {1, 3}


def test_hole_unit_reads_no_physical_clusters() -> None:
    layout = Layout().sparse()
    stream = layout.stream()

    layout.fh.clear_touches()
    assert stream.read(CU_SIZE) == b"\x00" * CU_SIZE
    assert layout.fh.touched_clusters() == set()


def test_touch_ledger_sequential_vs_interleaved() -> None:
    """Record the actual physical cluster ranges for sequential and interleaved random reads."""
    layout = Layout()
    layout.uncompressed(1)  # CU0: clusters 1-4
    layout.compressed(2, fragments=[1, 1, 1])  # CU1: clusters 5, 6, 7
    layout.sparse()  # CU2: hole
    layout.compressed(3, fragments=[2])  # CU3: clusters 8, 9
    layout.uncompressed(4)  # CU4: clusters 10-13
    layout.partial(5, 100)  # CU5: clusters 14, 15

    data = bytes(layout.expected)
    sequential = layout.stream()

    # Sequential read with a ledger of physical cluster ranges per compression unit
    ledger = []
    for cu_block, expected_clusters in enumerate(layout.cu_clusters):
        layout.fh.clear_touches()
        sequential.seek(cu_block * CU_SIZE)
        assert sequential.read(CU_SIZE) == data[cu_block * CU_SIZE : (cu_block + 1) * CU_SIZE]
        ledger.append(layout.fh.touched_clusters())
        assert ledger[-1] == expected_clusters

    # Interleaved random reads through two independent stream objects
    interleaved_a = layout.stream()
    interleaved_b = layout.stream()

    def read_unit(stream: CompressedRunlistStream, cu_block: int, offset_in_unit: int, size: int) -> bytes:
        start = cu_block * CU_SIZE + offset_in_unit
        stream.seek(start)
        return stream.read(size)

    random_order = [4, 1, 5, 0, 3, 2]
    for index, cu_block in enumerate(random_order):
        stream = interleaved_a if index % 2 == 0 else interleaved_b
        start = cu_block * CU_SIZE + 3

        layout.fh.clear_touches()
        actual = read_unit(stream, cu_block, 3, 11)
        assert actual == data[start : start + 11]
        assert layout.fh.touched_clusters() == ledger[cu_block]


def test_fragment_order_follows_runlist_not_lcn() -> None:
    # Store the two halves of a compressed unit at non-adjacent LCNs in the opposite physical order.
    # Concatenating the physical runs in LCN order would produce a different (invalid) stream.
    layout = Layout()
    data = cu_content(1)
    blob = lznt1_compress(data)
    assert len(blob) <= 2 * CLUSTER_SIZE

    first_lcn = 20
    second_lcn = 3
    layout.fh.write(first_lcn * CLUSTER_SIZE, blob[:CLUSTER_SIZE])
    layout.fh.write(second_lcn * CLUSTER_SIZE, blob[CLUSTER_SIZE:].ljust(CLUSTER_SIZE, b"\x00"))
    layout.runlist.append((first_lcn, 1))
    layout.runlist.append((second_lcn, 1))
    layout.runlist.append((None, CU_CLUSTERS - 2))
    layout.cu_clusters.append({first_lcn, second_lcn})
    layout.expected += data
    layout._next_lcn = first_lcn + 1

    assert layout.stream().read() == bytes(layout.expected)


def test_corrupt_unit_never_returns_fake_zero_bytes() -> None:
    # An all-zero physical extent is a valid "empty" LZNT1 stream shape for lznt1.decompress, but it does
    # not contain the logical data of the unit. It must raise instead of pretending to be zero-filled data.
    layout = Layout()
    data = cu_content(1)
    blob = lznt1_compress(data)
    lcn = layout._allocate(blob.ljust(CLUSTER_SIZE, b"\x00"))
    layout.runlist.append((lcn, 1))
    layout.runlist.append((None, CU_CLUSTERS - 1))
    layout.cu_clusters.append({lcn})
    layout.expected += data

    layout.fh.write(lcn * CLUSTER_SIZE, b"\x00" * CLUSTER_SIZE)

    with pytest.raises(IOError, match="Decompression failed"):
        layout.stream().read(CU_SIZE)


def test_compressed_unit_spanning_multiple_clusters_is_concatenated() -> None:
    # Make the compressed byte stream itself span more than one cluster, so the unit has multiple
    # non-sparse runs. A low-compressibility prefix keeps the compressed stream large enough.
    layout = Layout()
    data = cu_content(1, prefix_length=100)
    blob = lznt1_compress(data, literal_prefix=100)
    assert len(blob) > CLUSTER_SIZE

    fragments = (len(blob) + CLUSTER_SIZE - 1) // CLUSTER_SIZE
    assert fragments == 2

    cu_fragments = layout._new_cu()
    start = 0
    for index in range(fragments):
        chunk = blob[start : start + CLUSTER_SIZE]
        # Place each fragment at a non-adjacent LCN, in reverse physical order
        lcn = 9 - index * 2
        layout.fh.write(lcn * CLUSTER_SIZE, chunk.ljust(CLUSTER_SIZE, b"\x00"))
        cu_fragments.append((lcn, 1))
        start += CLUSTER_SIZE
    cu_fragments.append((None, CU_CLUSTERS - fragments))
    layout._commit_cu(cu_fragments)
    layout.expected += data

    # Both fragments are required; each on its own is not a valid compressed stream for this unit
    assert layout.stream().read() == bytes(layout.expected)


def test_real_compressed_attribute_matches_sequential_and_random_reads(ntfs_bin: BinaryIO) -> None:
    # Large.txt in the sample image is a genuinely NTFS-compressed attribute: each 64 KiB compression unit
    # is stored as one allocated cluster followed by 15 sparse clusters. Compare the sequential read result
    # with random reads through two interleaved stream objects on the same volume file handle.
    from dissect.ntfs.ntfs import NTFS

    fs = NTFS(ntfs_bin)
    record = fs.mft.get("Large.txt")

    sequential = record.open()
    data = sequential.read()
    assert data == record.size() * b"A"

    stream_a = record.open()
    stream_b = record.open()
    unit_size = 1 << 16
    offsets = (0, 1234, unit_size - 17, unit_size + 5, unit_size * 7 + 4093, len(data) - 100)

    for index, offset in enumerate(offsets):
        stream = stream_a if index % 2 == 0 else stream_b
        length = 257 if offset + 257 <= len(data) else len(data) - offset
        stream.seek(offset)
        assert stream.read(length) == data[offset : offset + length]
