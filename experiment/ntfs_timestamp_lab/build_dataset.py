"""Serialize the declarative scenarios into synthetic on-disk artifacts.

Outputs (all deterministic, no real disk involved):
  * synthetic_mft.bin   - 1024-byte FILE records at segment * record_size
  * usnjrnl_full.bin    - every USN v2 event, concatenated as on $J
  * usnjrnl_gap.bin     - same, but every event for the timestomp target is
                          removed, modelling an unavailable/purged journal span
  * manifest.json       - machine-readable scenario + layout description
"""

from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path

from dissect.ntfs.c_ntfs import FILE_RECORD_SEGMENT_IN_USE
from dissect.ntfs.mft import Mft

from .ntfs_builder import (
    RECORD_SIZE,
    build_file_record,
    file_name,
    standard_information,
    ticks_to_iso,
    usn_record_v2,
)
from .scenarios import ROOT_SEGMENT, T0, build_scenarios

STOMP_SEGMENT = 70
MAX_SEGMENT = 96


def _root_record() -> bytes:
    si = standard_information(T0, T0, T0, T0, file_attributes=0x30)
    fn = file_name(ROOT_SEGMENT, 5, ".", T0, T0, T0, T0,
                   file_attributes=0x30, is_directory=True)
    return build_file_record(ROOT_SEGMENT, sequence=5, reference_count=1,
                             is_directory=True, attributes=[si, fn])


def _record_bytes(spec) -> bytes:
    si_kwargs = spec.si
    si = standard_information(
        si_kwargs["creation"], si_kwargs["modification"],
        si_kwargs["change"], si_kwargs["access"])
    fn_attrs = []
    for entry in spec.fn:
        s = entry["stamps"]
        fn_attrs.append(file_name(
            entry["parent"], entry["parent_seq"], entry["name"],
            s["creation"], s["modification"], s["change"], s["access"],
            is_directory=spec.is_directory))
    return build_file_record(
        spec.segment, spec.sequence, spec.reference_count,
        spec.is_directory, [si, *fn_attrs])


def build(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    scenarios = build_scenarios()

    mft = bytearray(MAX_SEGMENT * RECORD_SIZE)
    mft[ROOT_SEGMENT * RECORD_SIZE:(ROOT_SEGMENT + 1) * RECORD_SIZE] = _root_record()

    manifest = {"anchor_iso": ticks_to_iso(T0), "record_size": RECORD_SIZE,
                "segments": {}, "scenarios": []}

    for scenario in scenarios:
        sc = {"key": scenario.key, "title": scenario.title, "segments": [],
              "events": []}
        for spec in scenario.records:
            mft[spec.segment * RECORD_SIZE:(spec.segment + 1) * RECORD_SIZE] = \
                _record_bytes(spec)
            sc["segments"].append(spec.segment)
            manifest["segments"][str(spec.segment)] = {
                "sequence": spec.sequence,
                "reference_count": spec.reference_count,
                "name": spec.name,
                "note": spec.note,
            }
        for event in scenario.events:
            sc["events"].append({
                "usn": event.usn, "segment": event.segment,
                "sequence": event.sequence, "reason": int(event.reason),
                "timestamp_iso": ticks_to_iso(event.timestamp),
                "name": event.name,
            })
        manifest["scenarios"].append(sc)

    full_journal = bytearray()
    gap_journal = bytearray()
    for scenario in scenarios:
        for event in scenario.events:
            raw = usn_record_v2(event)
            full_journal += raw
            if event.segment != STOMP_SEGMENT:
                gap_journal += raw

    (output_dir / "synthetic_mft.bin").write_bytes(mft)
    (output_dir / "usnjrnl_full.bin").write_bytes(full_journal)
    (output_dir / "usnjrnl_gap.bin").write_bytes(gap_journal)
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False))

    # Self-check immediately: the bytes we just wrote must parse cleanly via
    # the genuine dissect.ntfs MFT parser at every populated segment.
    mft_parser = Mft(BytesIO(bytes(mft)))
    populated = [ROOT_SEGMENT] + [s.segment for sc in scenarios for s in sc.records]
    for segment in populated:
        record = mft_parser.get(segment)
        assert record.header.Flags & FILE_RECORD_SEGMENT_IN_USE
        assert record.attributes.STANDARD_INFORMATION
        assert record.attributes.FILE_NAME
    return manifest
