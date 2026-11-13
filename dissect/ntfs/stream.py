from __future__ import annotations

import io
from typing import BinaryIO

from dissect.util import lznt1
from dissect.util.stream import RunlistStream


class CompressedRunlistStream(RunlistStream):
    """Specialized :class:`~dissect.util.stream.RunlistStream` for reading NTFS compressed streams.

    NTFS stores compressed data in compression units (usually 64 KiB, or 16 clusters). Each compression unit
    is either stored uncompressed (every cluster of the unit is allocated), compressed (the compressed data
    is followed by sparse clusters that pad the unit to its full size), or completely sparse (a hole that
    reads as zeroes). A compression unit can consist of multiple physical runs when the stored data is
    fragmented; all of those runs form a single compressed byte stream and must be concatenated before
    decompressing.

    Reads are aligned to the compression unit size by :class:`~dissect.util.stream.AlignedStream`, so a
    small read in the middle of a unit may cause the entire unit to be read and decompressed. The logical
    stream position is still tracked by the base class, and every physical read is preceded by a seek, so
    reading from one stream does not influence the position or data of another stream using the same source
    file-like object.

    Args:
        fh: The source file-like object.
        runlist: The runlist for this stream in block units.
        size: The size of the stream. This can be smaller than the total sum of blocks (to account for slack space).
        cluster_size: The cluster size in bytes.
        compression_unit: The compression unit of for this stream, as a power of two number of clusters.
    """

    def __init__(
        self, fh: BinaryIO, runlist: list[tuple[int, int]], size: int, cluster_size: int, compression_unit: int
    ):
        # RunlistStream has block_size but we want to make cluster_size available to be more in line with NTFS naming
        self.cluster_size = cluster_size
        self.compression_unit = compression_unit
        self.compression_unit_size = cluster_size << compression_unit
        self._cu_clusters = 1 << compression_unit

        # Build the CU blocks ourselves, so start from an empty list in case the runlist is set multiple times
        self._cu_blocks: list[list[tuple[int | None, int]]] = []

        # First use the compression_unit_size to set the alignment of AlignedStream
        super().__init__(fh, runlist, size, self.compression_unit_size)
        # This also sets the block_size of RunlistStream, so reset that to the correct cluster_size
        self.block_size = cluster_size

    @property
    def runlist(self) -> list[tuple[int, int]]:
        return self._runlist

    @runlist.setter
    def runlist(self, runlist: list[tuple[int, int]]) -> None:
        # Let RunlistStream keep its own lookup structures in sync, even though reading compressed data
        # uses the compression unit blocks built below.
        RunlistStream.runlist.fset(self, runlist)

        # Split the runlist into compression units, retaining every physical fragment of each unit.
        # A run can cross a compression unit boundary, in which case it is split and the physical LCN
        # offset continues in the next compression unit.
        cu_blocks: list[list[tuple[int | None, int]]] = []
        fragments: list[tuple[int | None, int]] = []
        remaining = self._cu_clusters

        for lcn, count in runlist:
            while count > 0:
                use = min(count, remaining)
                fragments.append((lcn, use))

                remaining -= use
                count -= use
                if lcn is not None:
                    lcn += use

                if remaining == 0:
                    cu_blocks.append(fragments)
                    fragments = []
                    remaining = self._cu_clusters

        # The final compression unit may be incomplete, for example when the stream ends in the middle of
        # a unit or when only part of the unit was allocated.
        if fragments:
            cu_blocks.append(fragments)

        self._cu_blocks = cu_blocks
        self._buf = None

    def _read(self, offset: int, length: int) -> bytes:
        """Read (aligned) data from one or more compression units.

        Args:
            offset: The offset in the stream to read from.
            length: The number of bytes to read.
        """
        read_list = []

        cu_block = offset // self.compression_unit_size
        cu_pos = offset - (cu_block * self.compression_unit_size)

        while length > 0:
            if cu_block >= len(self._cu_blocks):
                # The base RunlistStream stops reading when the runlist is exhausted. For a compressed
                # stream that means the metadata does not describe the requested logical data.
                if cu_block * self.compression_unit_size >= self.size:
                    break
                raise IOError(f"Missing compression unit at offset {cu_block * self.compression_unit_size}")

            read_count = min(length, self.compression_unit_size - cu_pos)
            cu_data = self._read_cu_block(cu_block, cu_pos + read_count)
            read_list.append(cu_data[cu_pos : cu_pos + read_count])

            length -= read_count
            cu_block += 1
            cu_pos = 0

        return b"".join(read_list)

    def _read_cu_block(self, cu_block: int, needed: int) -> bytes:
        """Read, and if necessary decompress, a single compression unit.

        The returned data is always exactly one compression unit in size. Bytes beyond the logical stream
        size are zero padded, so aligned buffer fills near the end of the stream yield a full unit while
        callers only ever observe the logical bytes they requested.

        Args:
            cu_block: The index of the compression unit to read.
            needed: The number of bytes from the start of the compression unit that the caller requires.

        Raises:
            IOError: If a physical run can not be read completely, if the unit is corrupt, or if the stored
                data does not cover the requested logical bytes.
        """
        fragments = self._cu_blocks[cu_block]
        cu_size = self.compression_unit_size
        cu_offset = cu_block * cu_size

        # The amount of logical data in this compression unit. For the final unit this can be smaller than
        # a full compression unit.
        logical_size = min(cu_size, max(0, self.size - cu_offset))
        needed = min(needed, logical_size)

        data_runs = [(lcn, count) for lcn, count in fragments if lcn is not None]
        has_sparse = len(data_runs) != len(fragments)

        if not data_runs:
            # A compression unit that consists only of sparse runs is a hole
            return b"\x00" * cu_size

        physical_size = sum(count * self.block_size for _, count in data_runs)

        if has_sparse:
            # A sparse run in a unit marks the stored data as compressed. All physical runs of the unit
            # together form a single LZNT1 byte stream, so concatenate them before decompressing.
            data = self._read_fragments(data_runs, cu_block)
            data = self._decompress_cu_block(cu_block, data, logical_size)
        elif needed <= physical_size:
            # Fully allocated unit: stored uncompressed
            data = self._read_fragments(data_runs, cu_block, needed)
        else:
            # A unit without sparse padding must be fully allocated. If its physical extent can not hold
            # the logical bytes it is supposed to contain, the metadata or the data is corrupt.
            raise IOError(
                f"Truncated compression unit {cu_block}: "
                f"got {physical_size} bytes, expected at least {needed} bytes"
            )

        if len(data) < needed:
            raise IOError(
                f"Truncated compression unit {cu_block}: got {len(data)} bytes, expected at least {needed} bytes"
            )

        # Units are read (and decompressed) in full by AlignedStream, but the last unit of a stream can be
        # shorter than a complete compression unit. Zero pad it so aligned buffer fills always get a full
        # unit, and ignore any allocated slack beyond the compression unit.
        if len(data) > cu_size:
            data = data[:cu_size]
        elif len(data) < cu_size:
            data += b"\x00" * (cu_size - len(data))

        return data

    def _read_fragments(self, data_runs: list[tuple[int, int]], cu_block: int, limit: int | None = None) -> bytes:
        """Read the physical fragments of a compression unit.

        Every fragment is read from its own LCN, so a unit that is scattered over multiple runs keeps the
        physical order of those runs intact. Reading only ``limit`` bytes still seeks to the right physical
        offset for every fragment that is needed.

        Args:
            data_runs: The non-sparse fragments of the compression unit.
            cu_block: The index of the compression unit, used for error reporting.
            limit: The maximum number of bytes to read, or ``None`` to read all fragments in full.

        Raises:
            IOError: If a physical run can not be read completely.
        """
        buf = []
        remaining = limit

        for lcn, count in data_runs:
            run_size = count * self.block_size
            read_size = run_size if remaining is None else min(run_size, remaining)

            if read_size <= 0:
                break

            self._fh.seek(lcn * self.block_size)
            data = self._fh.read(read_size)
            if len(data) != read_size:
                raise IOError(
                    f"Short read for compression unit {cu_block}: "
                    f"expected {read_size} bytes at cluster {lcn}, got {len(data)}"
                )

            buf.append(data)
            if remaining is not None:
                remaining -= read_size

        return b"".join(buf)

    def _decompress_cu_block(self, cu_block: int, data: bytes, logical_size: int) -> bytes:
        """Decompress the concatenated physical data of a compression unit.

        Args:
            cu_block: The index of the compression unit being decompressed.
            data: The concatenated physical data of the compression unit.
            logical_size: The number of logical bytes this compression unit must contain.

        Raises:
            IOError: If decompression fails or yields an invalid amount of data.
        """
        try:
            result = lznt1.decompress(io.BytesIO(data))
        except Exception as e:
            raise IOError(f"Decompression failed for compression unit {cu_block}") from e

        # A corrupt compressed unit must fail explicitly. LZNT1 silently stops at an invalid block header,
        # so an empty or truncated result may otherwise look like a successful (short or zero) read.
        if len(result) < logical_size:
            raise IOError(
                f"Decompression failed for compression unit {cu_block}: "
                f"got {len(result)} bytes, expected at least {logical_size} bytes"
            )

        if len(result) > self.compression_unit_size:
            raise IOError(
                f"Decompression failed for compression unit {cu_block}: "
                f"got {len(result)} bytes, expected at most {self.compression_unit_size} bytes"
            )

        return result
