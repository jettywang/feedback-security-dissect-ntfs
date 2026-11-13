"""Declarative synthetic evidence set.

Five controlled scenarios are laid out on fixed MFT segment numbers under a
single root directory (segment 5). Each scenario pins exact FILETIME ticks and
the matching USN v2 events. Two journal variants are produced: one complete
(``journal_full``) and one with every USN record removed for the timestomp
target (``journal_gap``), so the same on-disk record can be analysed with and
without journal corroboration.

The numbers model documented Windows behaviour but are hand-constructed; they
do not come from a live machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dissect.ntfs.c_ntfs import c_ntfs
USN_REASON = c_ntfs.USN_REASON

from .ntfs_builder import UsnEvent, add_ticks, filetime

ROOT_SEGMENT = 5

# Fixed anchor so the whole experiment is byte-reproducible run to run.
T0 = filetime(2017, 11, 13, 9, 0, 0, ticks100=0)


def t(**kwargs):
    return add_ticks(T0, **kwargs)


@dataclass
class RecordSpec:
    segment: int
    sequence: int
    reference_count: int
    name: str
    is_directory: bool
    si: dict
    fn: list[dict]
    note: str = ""


@dataclass
class Scenario:
    key: str
    title: str
    records: list[RecordSpec]
    events: list[UsnEvent] = field(default_factory=list)


def _stamp(creation, modification, change, access):
    return dict(creation=creation, modification=modification, change=change, access=access)


def build_scenarios() -> list[Scenario]:
    scenarios: list[Scenario] = []

    # ------------------------------------------------------------------ #
    # 1. Copy: Explorer-style metadata-preserving copy.
    #    SI timestamps are inherited from the source, FN timestamps are
    #    stamped at copy time -> a fully legitimate SI/FN divergence.
    # ------------------------------------------------------------------ #
    src_create = t(seconds=0, hundred_ns=12345)
    src_modify = t(seconds=30, hundred_ns=277)
    src_change = t(seconds=30, hundred_ns=277)
    src_access = t(seconds=30, hundred_ns=277)
    copy_moment = t(seconds=120, hundred_ns=670001)

    source = RecordSpec(
        segment=40, sequence=1, reference_count=1, name="source.docx",
        is_directory=False,
        si=_stamp(src_create, src_modify, src_change, src_access),
        fn=[dict(parent=ROOT_SEGMENT, parent_seq=1, name="source.docx",
                 stamps=_stamp(src_create, src_modify, src_change, src_access))],
        note="Original file; SI and FN agree.",
    )
    copied = RecordSpec(
        segment=41, sequence=1, reference_count=1, name="copied.docx",
        is_directory=False,
        # SI inherited verbatim from source, including sub-microsecond tail.
        si=_stamp(src_create, src_modify, src_change, src_access),
        fn=[dict(parent=ROOT_SEGMENT, parent_seq=1, name="copied.docx",
                 # FN stamped by the filesystem at the moment the copy was made.
                 stamps=_stamp(copy_moment, copy_moment, copy_moment, copy_moment))],
        note="Metadata-preserving copy: SI inherited, FN re-stamped -> benign divergence.",
    )
    scenarios.append(Scenario(
        "copy", "Legitimate metadata-preserving copy",
        [source, copied],
        [
            UsnEvent(100, copy_moment, USN_REASON.FILE_CREATE | USN_REASON.CLOSE,
                     41, 1, ROOT_SEGMENT, 1, "copied.docx"),
        ],
    ))

    # ------------------------------------------------------------------ #
    # 2. Rename: same segment and generation, only the name changes.
    #    SI never moves; the single FN entry keeps its timestamps.
    # ------------------------------------------------------------------ #
    rename_moment = t(seconds=200, hundred_ns=31337)
    renamed = RecordSpec(
        segment=50, sequence=1, reference_count=1, name="renamed_final.txt",
        is_directory=False,
        si=_stamp(t(seconds=150), t(seconds=160), t(seconds=160), t(seconds=160)),
        fn=[dict(parent=ROOT_SEGMENT, parent_seq=1, name="renamed_final.txt",
                 stamps=_stamp(t(seconds=150), t(seconds=160), t(seconds=160), t(seconds=160)))],
        note="Rename leaves SI and FN timestamps untouched; only the name component changes.",
    )
    scenarios.append(Scenario(
        "rename", "Same-volume rename",
        [renamed],
        [
            UsnEvent(200, rename_moment, USN_REASON.RENAME_OLD_NAME | USN_REASON.CLOSE,
                     50, 1, ROOT_SEGMENT, 1, "renamed_old.txt"),
            UsnEvent(208, rename_moment, USN_REASON.RENAME_NEW_NAME | USN_REASON.CLOSE,
                     50, 1, ROOT_SEGMENT, 1, "renamed_final.txt"),
        ],
    ))

    # ------------------------------------------------------------------ #
    # 3. Hard link: one MFT record gains a second directory entry.
    #    ReferenceCount rises to 2 and a second FN is added; SI is shared.
    # ------------------------------------------------------------------ #
    link_moment = t(seconds=300, hundred_ns=9009)
    link_create = t(seconds=250, hundred_ns=555)
    linked = RecordSpec(
        segment=60, sequence=1, reference_count=2, name="link_two.dat",
        is_directory=False,
        si=_stamp(link_create, t(seconds=260), t(seconds=260), t(seconds=260)),
        fn=[
            dict(parent=ROOT_SEGMENT, parent_seq=1, name="link_one.dat",
                 stamps=_stamp(link_create, t(seconds=260), t(seconds=260), t(seconds=260))),
            dict(parent=ROOT_SEGMENT, parent_seq=1, name="link_two.dat",
                 # New FN entry timestamped when the second link was created.
                 stamps=_stamp(link_moment, t(seconds=260), t(seconds=260), t(seconds=260))),
        ],
        note="Hard link: shared SI, two FN entries, ReferenceCount=2.",
    )
    scenarios.append(Scenario(
        "hardlink", "Hard link creation",
        [linked],
        [
            UsnEvent(300, link_moment, USN_REASON.HARD_LINK_CHANGE | USN_REASON.CLOSE,
                     60, 1, ROOT_SEGMENT, 1, "link_two.dat"),
        ],
    ))

    # ------------------------------------------------------------------ #
    # 4. Timestomp: SI times deliberately backdated; FN times not updated.
    #    The SI LastChangeTime still records the real edit moment.
    # ------------------------------------------------------------------ #
    real_create = t(seconds=400, hundred_ns=4242)
    real_modify = t(seconds=410)
    real_change = t(seconds=410)
    stomp_moment = t(seconds=500, hundred_ns=808080)
    fake_create = filetime(2014, 1, 1, 0, 0, 0)
    fake_modify = filetime(2014, 1, 2, 0, 0, 0)
    fake_access = filetime(2014, 1, 3, 0, 0, 0)
    stomped = RecordSpec(
        segment=70, sequence=1, reference_count=1, name="stomped.xlsx",
        is_directory=False,
        si=dict(creation=fake_create, modification=fake_modify,
                change=stomp_moment, access=fake_access),
        fn=[dict(parent=ROOT_SEGMENT, parent_seq=1, name="stomped.xlsx",
                 stamps=_stamp(real_create, real_modify, real_change, real_modify))],
        note="SI backdated manually; FN retains the genuine creation time; SI ChangeTime is still real.",
    )
    scenarios.append(Scenario(
        "timestomp", "Manual SI timestamp manipulation",
        [stomped],
        [
            UsnEvent(400, real_create, USN_REASON.FILE_CREATE | USN_REASON.CLOSE,
                     70, 1, ROOT_SEGMENT, 1, "stomped.xlsx"),
            UsnEvent(410, real_modify, USN_REASON.DATA_OVERWRITE | USN_REASON.CLOSE,
                     70, 1, ROOT_SEGMENT, 1, "stomped.xlsx"),
            UsnEvent(500, stomp_moment, USN_REASON.BASIC_INFO_CHANGE | USN_REASON.CLOSE,
                     70, 1, ROOT_SEGMENT, 1, "stomped.xlsx"),
        ],
    ))

    # ------------------------------------------------------------------ #
    # 5. Stale generation: segment 80 was deleted (generation 1) and the
    #    slot reused (generation 2). The journal still carries an event that
    #    names generation 1 -> a broken file reference.
    # ------------------------------------------------------------------ #
    old_create = t(seconds=600)
    delete_moment = t(seconds=700, hundred_ns=11)
    reuse_create = t(seconds=800, hundred_ns=77)
    reused = RecordSpec(
        segment=80, sequence=2, reference_count=1, name="reused_now.csv",
        is_directory=False,
        si=_stamp(reuse_create, reuse_create, reuse_create, reuse_create),
        fn=[dict(parent=ROOT_SEGMENT, parent_seq=1, name="reused_now.csv",
                 stamps=_stamp(reuse_create, reuse_create, reuse_create, reuse_create))],
        note="Segment reused; current generation is 2, journal event references the dead generation 1.",
    )
    scenarios.append(Scenario(
        "stale_generation", "Deleted then reused MFT segment (generation mismatch)",
        [reused],
        [
            UsnEvent(600, old_create, USN_REASON.FILE_CREATE | USN_REASON.CLOSE,
                     80, 1, ROOT_SEGMENT, 1, "deleted_then.csv"),
            UsnEvent(700, delete_moment, USN_REASON.FILE_DELETE | USN_REASON.CLOSE,
                     80, 1, ROOT_SEGMENT, 1, "deleted_then.csv"),
            UsnEvent(800, reuse_create, USN_REASON.FILE_CREATE | USN_REASON.CLOSE,
                     80, 2, ROOT_SEGMENT, 1, "reused_now.csv"),
        ],
    ))

    return scenarios
