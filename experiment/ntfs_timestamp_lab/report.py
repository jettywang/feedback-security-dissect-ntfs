"""Parse the synthetic artifacts back through dissect.ntfs and reason about them.

The analysis deliberately works from raw 100ns ticks. Any non-zero SI/FN
difference is reported as an exact tick count; display formatting is separate
and never feeds a decision, so sub-microsecond rounding can never be mistaken
for tampering.

Conclusions are framed as competing hypotheses. When the USN journal lacks the
relevant event, the code refuses to promote a hypothesis to a confirmed cause.
"""

from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path

from dissect.ntfs.c_ntfs import c_ntfs
USN_REASON = c_ntfs.USN_REASON
from dissect.ntfs.mft import Mft
from dissect.ntfs.usnjrnl import UsnJrnl
from dissect.ntfs.util import segment_reference

from .ntfs_builder import ticks_to_iso

TIME_FIELDS = ("creation", "modification", "change", "access")
SI_GET = {
    "creation": lambda a: a.attr.CreationTime,
    "modification": lambda a: a.attr.LastModificationTime,
    "change": lambda a: a.attr.LastChangeTime,
    "access": lambda a: a.attr.LastAccessTime,
}
FN_GET = SI_GET


def reason_names(reason: int) -> list[str]:
    names = []
    for member in USN_REASON:
        if reason & member.value:
            names.append(member.name)
    return names


def load_usn(path: Path) -> dict[tuple[int, int], list[dict]]:
    if not path.exists():
        return {}
    journal = UsnJrnl(BytesIO(path.read_bytes()))
    grouped: dict[tuple[int, int], list[dict]] = {}
    for record in journal.records():
        ref = record.record.FileReferenceNumber
        key = (segment_reference(ref), ref.SequenceNumber)
        grouped.setdefault(key, []).append({
            "usn": record.record.Usn,
            "ticks": record.record.TimeStamp,
            "iso": ticks_to_iso(record.record.TimeStamp),
            "reasons": reason_names(int(record.record.Reason)),
            "reason_mask": int(record.record.Reason),
            "name": record.filename,
            "journal_generation": ref.SequenceNumber,
            "parent_segment": segment_reference(record.record.ParentFileReferenceNumber),
            "parent_generation": record.record.ParentFileReferenceNumber.SequenceNumber,
        })
    return grouped


def analyze_record(record, events: list[dict], journal_present: bool) -> dict:
    header = record.header
    segment = record.segment
    si = record.attributes.STANDARD_INFORMATION[0]
    fn_attrs = list(record.attributes.FILE_NAME)

    si_ticks = {field: getter(si) for field, getter in SI_GET.items()}
    fn_views = []
    for fn in fn_attrs:
        fn_ticks = {field: FN_GET[field](fn) for field in TIME_FIELDS}
        deltas = {field: fn_ticks[field] - si_ticks[field] for field in TIME_FIELDS}
        fn_views.append({
            "name": fn.file_name,
            "flags": fn.flags,
            "parent_segment": segment_reference(fn.attr.ParentDirectory),
            "parent_generation": fn.attr.ParentDirectory.SequenceNumber,
            "ticks": fn_ticks,
            "iso": {f: ticks_to_iso(fn_ticks[f]) for f in TIME_FIELDS},
            "delta_vs_si_ticks": deltas,
        })

    # Generation check: every USN event naming this segment must match the
    # generation currently living in the MFT slot.
    generation_alerts = []
    matching_events, stale_events = [], []
    for event in events:
        if event["journal_generation"] == header.SequenceNumber:
            matching_events.append(event)
        else:
            stale_events.append(event)
            generation_alerts.append(
                f"USN {event['usn']} names generation {event['journal_generation']} "
                f"but segment now holds generation {header.SequenceNumber} "
                f"(name in journal: {event['name']}; reasons: {'|'.join(event['reasons'])})")

    divergent = sorted({
        field for view in fn_views for field, delta in view["delta_vs_si_ticks"].items()
        if delta != 0
    })

    finding = _classify(header, divergent, fn_views, matching_events,
                        stale_events, bool(events))

    return {
        "segment": segment,
        "generation": header.SequenceNumber,
        "reference_count": header.ReferenceCount,
        "is_directory": record.is_dir(),
        "filenames": [attr.file_name for attr in fn_attrs],
        "si": {
            "ticks": si_ticks,
            "iso": {f: ticks_to_iso(si_ticks[f]) for f in TIME_FIELDS},
            "usn_field": si.attr.Usn,
        },
        "file_name_attributes": fn_views,
        "divergent_fields": divergent,
        "hard_link_evidence": header.ReferenceCount > 1 or len(fn_attrs) > 1,
        "usn_events": matching_events + stale_events,
        "stale_generation_alerts": generation_alerts,
        "stale_generation_events": stale_events,
        "journal_available_for_record": journal_present and bool(events),
        "assessment": finding,
    }


def _classify(header, divergent, fn_views, matching, stale,
              has_any_events) -> dict:
    reasons = {name for event in matching for name in event["reasons"]}
    basic_info = "BASIC_INFO_CHANGE" in reasons
    data_write = "DATA_OVERWRITE" in reasons or "DATA_EXTEND" in reasons
    hard_link_event = "HARD_LINK_CHANGE" in reasons
    rename_event = {"RENAME_OLD_NAME", "RENAME_NEW_NAME"} & reasons
    create_event = "FILE_CREATE" in reasons
    hypotheses = []

    if stale:
        hypotheses.append({
            "hypothesis": "MFT slot was deleted and reused; stale journal events predate the current file",
            "confidence": "confirmed",
            "basis": "hard generation mismatch on the same segment",
        })

    if header.ReferenceCount > 1 or len(fn_views) > 1:
        hypotheses.append({
            "hypothesis": "Multiple directory names reference one MFT record (hard link set)",
            "confidence": "confirmed",
            "basis": f"ReferenceCount={header.ReferenceCount}, "
                     f"{len(fn_views)} $FILE_NAME attributes",
        })

    if hard_link_event:
        hypotheses.append({
            "hypothesis": "A hard link was added while the journal was recording",
            "confidence": "corroborated",
            "basis": "USN HARD_LINK_CHANGE present for the current generation",
        })

    if rename_event:
        hypotheses.append({
            "hypothesis": "Same-volume rename (same segment/generation, only the name changed)",
            "confidence": "corroborated",
            "basis": "USN RENAME_OLD_NAME / RENAME_NEW_NAME pair",
        })

    if basic_info and divergent:
        hypotheses.append({
            "hypothesis": "SI time fields changed via SetFileInformationByHandle "
                          "(manual timestomp or a legitimate metadata edit)",
            "confidence": "corroborated",
            "basis": "USN BASIC_INFO_CHANGE for the current generation plus SI/FN divergence; "
                     "the journal does not record the requested timestamp value, so intent is not proven",
        })
    elif create_event and divergent and not data_write:
        hypotheses.append({
            "hypothesis": "Newly created file that inherited SI metadata "
                          "(e.g. metadata-preserving copy or restore)",
            "confidence": "corroborated",
            "basis": "FILE_CREATE at the FN timestamp with SI carried over from a source",
        })

    if divergent and not has_any_events:
        hypotheses.append({
            "hypothesis": "SI/FN divergence present, but no journal evidence is available",
            "confidence": "inconclusive",
            "basis": "Copy/restore, hard-link bookkeeping and manual timestamp edits all produce "
                     "divergence; the on-disk record alone cannot separate them",
        })

    if not divergent and not hypotheses:
        hypotheses.append({
            "hypothesis": "SI and FN agree; no timestamp anomaly",
            "confidence": "confirmed",
            "basis": "all four field deltas are exactly 0 ticks",
        })

    # A definitive operation history is only claimable from structural evidence
    # (generation mismatch, hard-link topology) or an explicitly non-divergent
    # record. Journal-backed timestamp scenarios stay corroborated, not proven.
    structural = bool(stale) or header.ReferenceCount > 1 or len(fn_views) > 1
    definitive = structural or not divergent
    if divergent and not has_any_events:
        definitive = False

    return {
        "hypotheses": hypotheses,
        "definitive_history_claimable": definitive,
        "note": ("Divergence is not, by itself, evidence of tampering." if divergent
                 else "No SI/FN divergence."),
    }


def run_analysis(mft_path: Path, journal_path: Path) -> dict:
    mft_bytes = mft_path.read_bytes()
    mft = Mft(BytesIO(mft_bytes))
    events = load_usn(journal_path)
    journal_present = journal_path.exists()

    record_size = 1024
    results = []
    populated = [seg for seg in range(len(mft_bytes) // record_size)
                 if mft_bytes[seg * record_size:seg * record_size + 4] == b"FILE"]
    for segment in populated:
        record = mft.get(segment)
        current_gen = record.header.SequenceNumber
        # Current-generation events plus any stale events for the same slot.
        segment_events = list(events.get((segment, current_gen), []))
        for (seg, gen), evs in events.items():
            if seg == segment and gen != current_gen:
                segment_events.extend(evs)
        results.append(analyze_record(record, segment_events, journal_present))
    return {"journal": journal_path.name, "records": results}


def _markdown(analysis: dict) -> str:
    lines = [f"# Analysis against `{analysis['journal']}`", ""]
    for result in analysis["records"]:
        lines.append(f"## Segment {result['segment']} (gen {result['generation']}) "
                     f"- {', '.join(result['filenames'])}")
        lines.append("")
        lines.append(f"- ReferenceCount: {result['reference_count']} | "
                     f"hard-link evidence: {result['hard_link_evidence']} | "
                     f"journal records for file: {result['journal_available_for_record']}")
        if result["divergent_fields"]:
            lines.append(f"- SI/FN divergent fields (exact ticks): "
                         f"{', '.join(result['divergent_fields'])}")
        else:
            lines.append("- SI/FN deltas: all exactly 0 ticks")
        for view in result["file_name_attributes"]:
            delta = ", ".join(f"{k}={v:+d}" for k, v in
                              view["delta_vs_si_ticks"].items())
            lines.append(f"  - FN `{view['name']}` delta vs SI (ticks): {delta}")
        if result["usn_events"]:
            lines.append("- USN events:")
            for event in result["usn_events"]:
                lines.append(
                    f"  - usn={event['usn']} gen={event['journal_generation']} "
                    f"{event['iso']} [{'|'.join(event['reasons'])}] `{event['name']}`")
        else:
            lines.append("- USN events: none available for this record")
        for alert in result["stale_generation_alerts"]:
            lines.append(f"- GENERATION ALERT: {alert}")
        for hypothesis in result["assessment"]["hypotheses"]:
            lines.append(f"- [{hypothesis['confidence']}] {hypothesis['hypothesis']} "
                         f"— {hypothesis['basis']}")
        lines.append(f"- Definitive operation history claimable: "
                     f"{result['assessment']['definitive_history_claimable']}")
        lines.append("")
    return "\n".join(lines)


def write_reports(output_dir: Path) -> None:
    full = run_analysis(output_dir / "synthetic_mft.bin",
                        output_dir / "usnjrnl_full.bin")
    gap = run_analysis(output_dir / "synthetic_mft.bin",
                       output_dir / "usnjrnl_gap.bin")

    (output_dir / "analysis_full.json").write_text(
        json.dumps(full, indent=2, ensure_ascii=False))
    (output_dir / "analysis_gap.json").write_text(
        json.dumps(gap, indent=2, ensure_ascii=False))
    (output_dir / "analysis_full.md").write_text(_markdown(full))
    (output_dir / "analysis_gap.md").write_text(_markdown(gap))
    _write_timeline(output_dir, full)


def _write_timeline(output_dir: Path, analysis: dict) -> None:
    rows = []
    for result in analysis["records"]:
        label = f"seg{result['segment']} {'/'.join(result['filenames'])}"
        for field in TIME_FIELDS:
            rows.append((result["si"]["ticks"][field], label, f"SI.{field}",
                         result["si"]["iso"][field]))
        for view in result["file_name_attributes"]:
            for field in TIME_FIELDS:
                rows.append((view["ticks"][field], label,
                             f"FN[{view['name']}].{field}", view["iso"][field]))
        for event in result["usn_events"]:
            rows.append((event["ticks"], label,
                         f"USN {'|'.join(event['reasons'])}", event["iso"]))
    rows.sort(key=lambda row: row[0])
    out = ["# Unified timeline (sorted by raw FILETIME tick)", "",
           "| tick (100ns since 1601) | UTC (100ns precision) | record | source |",
           "| --- | --- | --- | --- |"]
    for tick, label, source, iso in rows:
        out.append(f"| {tick} | {iso} | {label} | {source} |")
    (output_dir / "timeline.md").write_text("\n".join(out))
