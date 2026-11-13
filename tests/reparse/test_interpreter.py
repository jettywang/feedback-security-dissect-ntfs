from __future__ import annotations

import pytest

from dissect.ntfs.attr import Attribute
from dissect.ntfs.c_ntfs import IO_REPARSE_TAG
from dissect.ntfs.reparse import (
    Certainty,
    PathKind,
    Severity,
    TagFamily,
    ValueStatus,
    classify_path,
    interpret_attribute,
    interpret_reparse_buffer,
)
from dissect.ntfs.reparse.samples import all_samples

SAMPLES = all_samples()


def test_symlink_absolute_drive() -> None:
    result = interpret_reparse_buffer(SAMPLES["symlink_absolute_drive"], "mem:symlink_absolute_drive")
    assert result.tag == int(IO_REPARSE_TAG.SYMLINK)
    assert result.family is TagFamily.NAME_SURROGATE
    assert result.symlink_relative is False
    assert result.substitute.text == r"\??\C:\Windows\Fonts"
    assert result.print_name.text == r"C:\Windows\Fonts"
    assert result.name_consistent is True
    assert result.classification.kind is PathKind.DOS_DRIVE
    assert result.classification.drive_letter == "C"
    assert result.classification.namespace_prefix == "\\??\\"
    # Display prefers PrintName when present and consistent.
    assert result.display_value is result.print_name
    labels = {candidate.label for candidate in result.candidates}
    assert "raw_substitute_name" in labels and "dos_drive_binding" in labels
    binding = next(c for c in result.candidates if c.label == "dos_drive_binding")
    assert binding.certainty is Certainty.UNRESOLVED


def test_relative_symlink() -> None:
    result = interpret_reparse_buffer(SAMPLES["symlink_relative"])
    assert result.symlink_relative is True
    assert result.classification.kind is PathKind.RELATIVE
    assert result.classification.uncertainty is not None
    candidate = next(c for c in result.candidates if c.label == "relative_join")
    assert candidate.certainty is Certainty.CONDITIONAL


def test_volume_guid_mount_point() -> None:
    result = interpret_reparse_buffer(SAMPLES["mount_point_volume_guid"])
    assert result.tag == int(IO_REPARSE_TAG.MOUNT_POINT)
    assert result.classification.kind is PathKind.VOLUME_GUID
    assert result.classification.volume_guid == "Volume{12345678-1234-1234-1234-123456789abc}"
    candidate = next(c for c in result.candidates if c.label == "volume_guid_binding")
    assert candidate.certainty is Certainty.UNRESOLVED
    assert "Mount Manager" in candidate.requires[0]


def test_unc_target() -> None:
    result = interpret_reparse_buffer(SAMPLES["symlink_unc"])
    assert result.classification.kind is PathKind.UNC
    stripped = next(c for c in result.candidates if c.label == "substitute_without_namespace_prefix")
    assert stripped.value == r"\\server\share\folder"


def test_print_substitute_mismatch_counterexample() -> None:
    result = interpret_reparse_buffer(SAMPLES["print_substitute_mismatch"])
    assert result.name_consistent is False
    mismatch = [notice for notice in result.notices if notice.code == "print_substitute_mismatch"]
    assert mismatch and mismatch[0].severity is Severity.WARNING
    # The substitute points to a volume GUID secret, the print name lies about it.
    assert result.classification.kind is PathKind.VOLUME_GUID
    assert result.print_name.text == r"C:\Users\Public\Readme.txt"
    assert "Secret" in result.substitute.text


def test_empty_print_name_falls_back_to_substitute() -> None:
    result = interpret_reparse_buffer(SAMPLES["empty_print_name"])
    assert result.print_name.status is ValueStatus.EMPTY
    assert result.display_value is result.substitute


def test_declared_length_overflow_is_flagged() -> None:
    result = interpret_reparse_buffer(SAMPLES["declared_length_overflow"])
    overflow = [notice for notice in result.notices if notice.code == "reparse_data_length_overflow"]
    assert overflow and overflow[0].severity is Severity.ERROR
    # Evidence still extracted for the in-bounds portion.
    assert result.substitute is not None


def test_substitute_offset_out_of_bounds() -> None:
    result = interpret_reparse_buffer(SAMPLES["substitute_offset_oob"])
    assert result.substitute.status is ValueStatus.OUT_OF_BOUNDS
    assert result.substitute.text is None
    notice = next(n for n in result.notices if n.code == "name_offset_out_of_bounds")
    assert notice.severity is Severity.ERROR
    # Byte-level evidence is retained even though the value is unreadable.
    assert result.substitute.evidence.range.offset == 512


def test_unknown_tag_classified_by_flag_bits() -> None:
    result = interpret_reparse_buffer(SAMPLES["unknown_name_surrogate"])
    assert result.tag_name is None
    assert result.family is TagFamily.NAME_SURROGATE
    # Best-effort generic name-pair parsing is explicitly labelled as inference.
    assert result.substitute.text == r"\??\C:\Mystery"
    assert result.symlink_relative is None
    inferred = [notice for notice in result.notices if notice.code == "inferred_name_layout"]
    assert inferred and inferred[0].severity is Severity.WARNING
    assert result.substitute.evidence.attribute_type == "INFERRED_NAME_SURROGATE_BUFFER"


def test_filter_managed_tag_has_no_name_pair() -> None:
    result = interpret_reparse_buffer(SAMPLES["filter_managed_opaque"])
    assert result.family is TagFamily.FILTER_MANAGED
    assert result.substitute is None and result.print_name is None
    assert any(notice.code == "tag_not_name_surrogate" for notice in result.notices)


def test_lx_symlink_family() -> None:
    result = interpret_reparse_buffer(SAMPLES["lx_symlink"])
    assert result.family is TagFamily.LX_SYMLINK
    assert result.substitute is None


def test_classify_path_object_rooted() -> None:
    classification = classify_path(r"\Windows\WinSxS", False)
    assert classification.kind is PathKind.OBJECT_ROOTED
    assert classification.uncertainty is not None


def test_short_buffer_rejected() -> None:
    with pytest.raises(ValueError, match="8-byte"):
        interpret_reparse_buffer(b"\x00\x01")


def test_interpret_attribute_adapter_matches_library() -> None:
    data = bytes.fromhex(
        "c000000058000000000000000000040040000000180000000c0000a038000000"
        "12001a00000012000000000043003a005c005400610072006700650074005c00"
        "3f003f005c0043003a005c00540061007200670065007400"
    )
    attribute = Attribute.from_bytes(data)
    result = interpret_attribute(attribute, source="tests:test_attr_symlink")
    assert result.substitute.text == attribute.substitute_name
    assert result.print_name.text == attribute.print_name
    assert result.tag == int(IO_REPARSE_TAG.SYMLINK)
    assert result.evidence_lines()[0].startswith("tests:test_attr_symlink")
