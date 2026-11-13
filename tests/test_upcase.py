from __future__ import annotations

from typing import BinaryIO
from unittest.mock import Mock

import pytest

from dissect.ntfs.exceptions import FileNotFoundError
from dissect.ntfs.ntfs import NTFS
from dissect.ntfs.upcase import UpcaseTable, fallback_uppercase
from tests.conftest import make_upcase_table


def test_upcase_table() -> None:
    table = UpcaseTable(make_upcase_table({"ä": "A"}))

    assert table.uppercase("foo") == "FOO"
    assert table.uppercase("äpfel") == "APFEL"
    # The volume's own mapping is used, not Python's Unicode rules
    assert table.uppercase("straße") == "STRAßE"
    # Mapping never changes the number of characters
    assert len(table.uppercase("straße")) == len("straße")
    # Characters outside the BMP are not in the table and left unchanged
    assert table.uppercase("𐐷") == "𐐷"


def test_upcase_table_broken() -> None:
    with pytest.raises(ValueError, match="Invalid \\$UpCase table size"):
        UpcaseTable(b"\x00" * 0x100)


def test_fallback_uppercase() -> None:
    assert fallback_uppercase("foo") == "FOO"
    assert fallback_uppercase("straße") == "STRAßE"
    # Characters that would expand to multiple characters are left unchanged
    assert fallback_uppercase("ﬁle") == "ﬁLE"
    assert len(fallback_uppercase("ﬁle")) == len("ﬁle")


def test_ntfs_upcase_table(ntfs_bin: BinaryIO) -> None:
    fs = NTFS(ntfs_bin)

    table = fs.upcase_table
    assert table is not None
    assert table is fs.upcase_table
    assert table.uppercase("foo") == "FOO"
    # The real $UpCase table does not expand ß to SS like Python does
    assert table.uppercase("straße") == "STRAßE"


def test_ntfs_upcase_table_no_mft() -> None:
    fs = NTFS.__new__(NTFS)
    fs.mft = None

    with pytest.warns(UserWarning, match="No usable \\$UpCase table"):
        assert fs.upcase_table is None


def test_ntfs_upcase_table_missing() -> None:
    fs = NTFS.__new__(NTFS)
    fs.mft = Mock()
    fs.mft.get.side_effect = FileNotFoundError("no $UpCase")

    with pytest.warns(UserWarning, match="No usable \\$UpCase table"):
        assert fs.upcase_table is None


def test_ntfs_upcase_table_broken() -> None:
    fs = NTFS.__new__(NTFS)
    fs.mft = Mock()
    fs.mft.get.return_value.open.return_value.read.return_value = b"\x00" * 0x100

    with pytest.warns(UserWarning, match="No usable \\$UpCase table"):
        assert fs.upcase_table is None


def test_ntfs_upcase_table_not_shared_between_volumes(ntfs_bin: BinaryIO) -> None:
    good_fs = NTFS(ntfs_bin)

    broken_fs = NTFS.__new__(NTFS)
    broken_fs.mft = Mock()
    broken_fs.mft.get.side_effect = FileNotFoundError("no $UpCase")

    with pytest.warns(UserWarning, match="No usable \\$UpCase table"):
        assert broken_fs.upcase_table is None

    # Interleave lookups on both volumes: the broken volume's failure must not leak into
    # the good volume, and the good volume's table must not be used for the broken one
    assert good_fs.upcase_table is not None
    assert good_fs.upcase_table.uppercase("foo") == "FOO"
    assert broken_fs.upcase_table is None
    assert good_fs.upcase_table is not None
