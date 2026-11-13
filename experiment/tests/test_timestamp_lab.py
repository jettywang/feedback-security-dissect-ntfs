from __future__ import annotations

from io import BytesIO

import pytest

from dissect.ntfs.mft import Mft
from dissect.ntfs.usnjrnl import UsnJrnl
from dissect.ntfs.util import segment_reference, ts_to_ns

from experiment.ntfs_timestamp_lab.build_dataset import build
from experiment.ntfs_timestamp_lab.ntfs_builder import add_ticks, filetime
from experiment.ntfs_timestamp_lab.report import run_analysis


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    out = tmp_path_factory.mktemp("lab")
    build(out)
    full = run_analysis(out / "synthetic_mft.bin", out / "usnjrnl_full.bin")
    gap = run_analysis(out / "synthetic_mft.bin", out / "usnjrnl_gap.bin")
    return out, full, gap


def _by_segment(analysis):
    return {record["segment"]: record for record in analysis["records"]}


def test_synthetic_records_parse_through_real_dissect_parser(built):
    out, _, _ = built
    mft = Mft(BytesIO((out / "synthetic_mft.bin").read_bytes()))
    # Fixup must be applied successfully at every populated segment.
    for segment in (5, 40, 41, 50, 60, 70, 80):
        record = mft.get(segment)
        assert record.attributes.STANDARD_INFORMATION
        assert record.attributes.FILE_NAME


def test_raw_100ns_ticks_survive_roundtrip(built):
    out, _, _ = built
    mft = Mft(BytesIO((out / "synthetic_mft.bin").read_bytes()))
    copied = mft.get(41)
    si = copied.attributes.STANDARD_INFORMATION[0]
    fn = copied.attributes.FILE_NAME[0]
    # Exact tick integers, including the sub-microsecond tail, survive parsing.
    assert si.attr.CreationTime == filetime(2017, 11, 13, 9, 0, 0, 12345)
    assert ts_to_ns(si.attr.CreationTime) == si.creation_time_ns
    # FN was stamped 120 s + a 100ns-granular offset later; compare on raw ticks.
    assert fn.attr.CreationTime == add_ticks(si.attr.CreationTime,
                                             seconds=120, hundred_ns=657656)


def test_legitimate_copy_is_divergent_not_tampering(built):
    _, full, _ = built
    copied = _by_segment(full)[41]
    assert set(copied["divergent_fields"]) == {
        "creation", "modification", "change", "access"}
    labels = " ".join(h["hypothesis"] for h in copied["assessment"]["hypotheses"])
    assert "inherited SI metadata" in labels
    assert copied["assessment"]["definitive_history_claimable"] is False


def test_hard_link_is_structurally_confirmed(built):
    _, full, _ = built
    linked = _by_segment(full)[60]
    assert linked["reference_count"] == 2
    assert linked["hard_link_evidence"] is True
    assert len(linked["file_name_attributes"]) == 2
    assert any(h["confidence"] == "confirmed" and "hard link" in h["hypothesis"]
               for h in linked["assessment"]["hypotheses"])


def test_generation_mismatch_is_detected(built):
    _, full, _ = built
    reused = _by_segment(full)[80]
    assert reused["generation"] == 2
    assert len(reused["stale_generation_alerts"]) == 2
    assert any("generation 1" in alert and "generation 2" in alert
               for alert in reused["stale_generation_alerts"])
    assert reused["assessment"]["definitive_history_claimable"] is True


def test_missing_journal_keeps_timestomp_inconclusive(built):
    _, _, gap = built
    stomped = _by_segment(gap)[70]
    assert stomped["divergent_fields"]
    assert stomped["usn_events"] == []
    confidences = {h["confidence"] for h in stomped["assessment"]["hypotheses"]}
    assert confidences == {"inconclusive"}
    assert stomped["assessment"]["definitive_history_claimable"] is False


def test_full_journal_corroborates_basic_info_change_but_not_intent(built):
    _, full, _ = built
    stomped = _by_segment(full)[70]
    joined = " ".join(h["hypothesis"] for h in stomped["assessment"]["hypotheses"])
    basis = " ".join(h["basis"] for h in stomped["assessment"]["hypotheses"])
    assert "SetFileInformationByHandle" in joined
    assert "BASIC_INFO_CHANGE" in basis
    assert "intent is not proven" in basis
    assert stomped["assessment"]["definitive_history_claimable"] is False


def test_rename_keeps_si_and_fn_identical(built):
    _, full, _ = built
    renamed = _by_segment(full)[50]
    assert renamed["divergent_fields"] == []
    view = renamed["file_name_attributes"][0]
    assert all(delta == 0 for delta in view["delta_vs_si_ticks"].values())


def test_usn_journal_bytes_parse_with_matching_references(built):
    out, _, _ = built
    records = list(UsnJrnl(BytesIO((out / "usnjrnl_full.bin").read_bytes())).records())
    assert len(records) == 10
    for record in records:
        assert segment_reference(record.record.FileReferenceNumber) in (
            41, 50, 60, 70, 80)


def test_gap_journal_drops_only_the_timestomp_events(built):
    out, _, _ = built
    full = list(UsnJrnl(BytesIO((out / "usnjrnl_full.bin").read_bytes())).records())
    gap = list(UsnJrnl(BytesIO((out / "usnjrnl_gap.bin").read_bytes())).records())
    assert len(full) - len(gap) == 3
    assert all(segment_reference(r.record.FileReferenceNumber) != 70 for r in gap)
