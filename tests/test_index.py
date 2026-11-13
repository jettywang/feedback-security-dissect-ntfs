from __future__ import annotations

import io
import struct
from typing import BinaryIO
from unittest.mock import Mock

import pytest

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, COLLATION, INDEX_ENTRY_END, c_ntfs
from dissect.ntfs.exceptions import FileNotFoundError
from dissect.ntfs.index import Index, IndexEntry, Match, _cmp_filename, _cmp_ulong
from dissect.ntfs.ntfs import NTFS
from dissect.ntfs.upcase import UpcaseTable
from tests.conftest import make_upcase_table


def _filename_entry_bytes(filename: str) -> bytes:
    attribute = c_ntfs._FILE_NAME(
        FileNameLength=len(filename),
        FileName=filename,
    ).dumps()
    header = c_ntfs._INDEX_ENTRY(
        Length=len(c_ntfs._INDEX_ENTRY) + len(attribute),
        KeyLength=len(attribute),
    )
    return header.dumps() + attribute


def mock_filename_entry(filename: str) -> IndexEntry:
    data = _filename_entry_bytes(filename)

    mock_root = Mock(attribute_type=ATTRIBUTE_TYPE_CODE.FILE_NAME)
    mock_index = Mock(root=mock_root)
    return IndexEntry(mock_index, io.BytesIO(data), 0)


def mock_index(filenames: list[str], upcase_table: UpcaseTable | None, ntfs: Mock | None = ...) -> Index:
    """Build a real :class:`Index` on a mock record, with filenames stored in the given order."""
    entries = b"".join(_filename_entry_bytes(filename) for filename in filenames)
    entries += c_ntfs._INDEX_ENTRY(
        Length=len(c_ntfs._INDEX_ENTRY),
        KeyLength=0,
        Flags=INDEX_ENTRY_END,
    ).dumps()

    index_root = c_ntfs._INDEX_ROOT(
        AttributeType=ATTRIBUTE_TYPE_CODE.FILE_NAME,
        CollationRule=COLLATION.FILE_NAME,
        BytesPerIndexBuffer=4096,
        ClustersPerIndexBuffer=1,
        IndexHeader=c_ntfs._INDEX_HEADER(
            FirstEntryOffset=len(c_ntfs._INDEX_HEADER),
            TotalSizeOfEntries=len(entries),
            AllocatedSize=len(entries),
            Flags=0,
        ),
    )
    root_fh = io.BytesIO(index_root.dumps() + entries)

    def open_stream(name: str, attr_type: ATTRIBUTE_TYPE_CODE) -> BinaryIO:
        if attr_type == ATTRIBUTE_TYPE_CODE.INDEX_ROOT:
            return root_fh
        raise FileNotFoundError(name)

    if ntfs is ...:
        ntfs = Mock(upcase_table=upcase_table, cluster_size=4096, cluster_size_shift=12)
    record = Mock(ntfs=ntfs)
    record.open = Mock(side_effect=open_stream)
    return Index(record, "$I30")


def mock_ulong_entry(value: int) -> IndexEntry:
    header = c_ntfs._INDEX_ENTRY(
        Length=len(c_ntfs._INDEX_ENTRY) + 4,
        KeyLength=4,
    )
    data = header.dumps() + struct.pack("<I", value)

    mock_root = Mock(attribute_type=ATTRIBUTE_TYPE_CODE.UNUSED)
    mock_index = Mock(root=mock_root)
    return IndexEntry(mock_index, io.BytesIO(data), 0)


def test_cmp_filename() -> None:
    entry = mock_filename_entry("bbbb")

    assert _cmp_filename(entry, "CCCC") == Match.Greater
    assert _cmp_filename(entry, "BBBB") == Match.Equal
    assert _cmp_filename(entry, "BBBA") == Match.Less
    assert _cmp_filename(entry, "BBBBA") == Match.Greater
    assert _cmp_filename(entry, "BBBBB") == Match.Greater

    entry = mock_filename_entry("C_20127.NLS")
    assert _cmp_filename(entry, "CONFIG") == Match.Less


def test_cmp_filename_upcase_table() -> None:
    table = UpcaseTable(make_upcase_table({"ä": "A", "Ä": "A"}))

    # Case-equivalent names with different original forms compare equal
    entry = mock_filename_entry("Äpfel")
    assert _cmp_filename(entry, "äPFEL", table) == Match.Equal

    # Ordering follows the volume's table, not Python's Unicode rules
    entry = mock_filename_entry("äpfel")
    assert _cmp_filename(entry, "alpha", table) == Match.Less
    assert _cmp_filename(entry, "beta", table) == Match.Greater

    other_table = UpcaseTable(make_upcase_table({"ä": "~", "Ä": "~"}))
    assert _cmp_filename(entry, "zulu", other_table) == Match.Less

    # The table does not expand ß to SS like Python does
    entry = mock_filename_entry("straße")
    assert _cmp_filename(entry, "STRAßE", table) == Match.Equal
    assert _cmp_filename(entry, "STRASSE", table) == Match.Less


def test_cmp_filename_fallback() -> None:
    # Without a table the comparison degrades to a length-preserving Unicode uppercase
    entry = mock_filename_entry("straße")
    assert _cmp_filename(entry, "STRAßE") == Match.Equal
    assert _cmp_filename(entry, "STRASSE") == Match.Less


def test_cmp_ulong() -> None:
    entry = mock_ulong_entry(100)

    assert _cmp_ulong(entry, 99) == Match.Less
    assert _cmp_ulong(entry, 100) == Match.Equal
    assert _cmp_ulong(entry, 101) == Match.Greater


def test_index_lookup(ntfs_bin: BinaryIO) -> None:
    fs = NTFS(ntfs_bin)

    root = fs.mft.get("Large Directory")
    assert len(root.listdir()) == 2048

    for i in range(2048):
        entry = root.get(f"Directory {i}")
        assert entry.filename == f"Directory {i}"


def test_index_lookup_case_insensitive(ntfs_bin: BinaryIO) -> None:
    fs = NTFS(ntfs_bin)

    root = fs.mft.get("Large Directory")
    entry = root.get("directory 1")
    assert entry.filename == "Directory 1"


def test_index_upcase_table_per_volume() -> None:
    # The same set of names on two volumes with different $UpCase mappings:
    # volume A sorts "ä" with the a's, volume B sorts it after "z"
    names = ["alpha", "Beta", "zulu", "äpfel"]

    table_a = UpcaseTable(make_upcase_table({"ä": "A", "Ä": "A"}))
    table_b = UpcaseTable(make_upcase_table({"ä": "~", "Ä": "~"}))

    names_a = sorted(names, key=table_a.uppercase)
    names_b = sorted(names, key=table_b.uppercase)
    assert names_a != names_b

    index_a = mock_index(names_a, table_a)
    index_b = mock_index(names_b, table_b)

    # Ordered traversal yields each volume's own collation order
    assert [entry.attribute.file_name for entry in index_a.entries()] == names_a
    assert [entry.attribute.file_name for entry in index_b.entries()] == names_b

    # Interleaved lookups on both volumes, including case-equivalent variants of the names
    for name in names:
        assert index_a.search(name).attribute.file_name == name
        assert index_b.search(name).attribute.file_name == name
        assert index_a.search(name.upper()).attribute.file_name == name
        assert index_b.search(name.upper()).attribute.file_name == name

    # Genuinely missing names are still reported as missing on both volumes
    for index in (index_a, index_b):
        with pytest.raises(KeyError):
            index.search("not-here")


def test_index_fallback_without_volume() -> None:
    names = ["alpha", "Beta", "straße", "zulu"]
    upcase = UpcaseTable(make_upcase_table()).uppercase
    ordered = sorted(names, key=upcase)

    # A standalone record without a volume has no $UpCase table: warn, but still find files
    with pytest.warns(UserWarning, match="No volume available for filename index"):
        index = mock_index(ordered, None, ntfs=None)

    assert [entry.attribute.file_name for entry in index.entries()] == ordered
    for name in names:
        assert index.search(name).attribute.file_name == name
    assert index.search("STRAßE").attribute.file_name == "straße"
    with pytest.raises(KeyError):
        index.search("not-here")
