from __future__ import annotations

import csv
import gzip
import io
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest
from dissect.util.stream import MappingStream

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def make_upcase_table(overrides: dict[str, str] | None = None) -> bytes:
    """Build a small ``$UpCase``-like mapping for tests.

    Maps every UTF-16 code unit to its single-character Unicode uppercase (or itself if the
    uppercase form would change the character count), then applies the given overrides.
    """
    table = bytearray(0x20000)
    for unit in range(0x10000):
        char = chr(unit)
        upper = char.upper()
        mapped = ord(upper) if len(upper) == 1 else unit
        table[unit * 2 : unit * 2 + 2] = mapped.to_bytes(2, "little")
    for source, target in (overrides or {}).items():
        table[ord(source) * 2 : ord(source) * 2 + 2] = ord(target).to_bytes(2, "little")
    return bytes(table)


def open_file_gz(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(name), mode) as f:
        yield f


@pytest.fixture
def ntfs_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ntfs.bin.gz")


@pytest.fixture
def mft_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/mft.bin.gz")


@pytest.fixture
def ntfs_cloud_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ntfs-cloud.bin.gz")


@pytest.fixture
def sds_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/sds.bin.gz")


@pytest.fixture
def sds_complex_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/sds_complex.bin.gz")


@pytest.fixture
def boot_2m_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/boot_2m.bin.gz")


@pytest.fixture
def ntfs_fragmented_mft_fh() -> BinaryIO:
    # Test data from https://github.com/msuhanov/ntfs-samples
    # This is from the file ntfs_extremely_fragmented_mft.raw which has, as the name implies, a heavily fragmented MFT
    # The entire file is way too large, so only take just enough data that we actually need to make dissect.ntfs happy
    # We use a MappingStream to stitch everything together at the correct offsets

    stream = MappingStream(align=512)
    with io.TextIOWrapper(gzip.open(absolute_path("_data/ntfs_fragmented_mft.csv.gz"), "r")) as fh:
        for offset, data in csv.reader(fh):
            buf = bytes.fromhex(data)
            stream.add(int(offset), len(buf), io.BytesIO(buf), 0)

    return stream
