# Analysis against `usnjrnl_gap.bin`

## Segment 5 (gen 5) - .

- ReferenceCount: 1 | hard-link evidence: False | journal records for file: False
- SI/FN deltas: all exactly 0 ticks
  - FN `.` delta vs SI (ticks): creation=+0, modification=+0, change=+0, access=+0
- USN events: none available for this record
- [confirmed] SI and FN agree; no timestamp anomaly — all four field deltas are exactly 0 ticks
- Definitive operation history claimable: True

## Segment 40 (gen 1) - source.docx

- ReferenceCount: 1 | hard-link evidence: False | journal records for file: False
- SI/FN deltas: all exactly 0 ticks
  - FN `source.docx` delta vs SI (ticks): creation=+0, modification=+0, change=+0, access=+0
- USN events: none available for this record
- [confirmed] SI and FN agree; no timestamp anomaly — all four field deltas are exactly 0 ticks
- Definitive operation history claimable: True

## Segment 41 (gen 1) - copied.docx

- ReferenceCount: 1 | hard-link evidence: False | journal records for file: True
- SI/FN divergent fields (exact ticks): access, change, creation, modification
  - FN `copied.docx` delta vs SI (ticks): creation=+1200657656, modification=+900669724, change=+900669724, access=+900669724
- USN events:
  - usn=100 gen=1 2017-11-13T09:02:00.067000100Z [FILE_CREATE|CLOSE] `copied.docx`
- [corroborated] Newly created file that inherited SI metadata (e.g. metadata-preserving copy or restore) — FILE_CREATE at the FN timestamp with SI carried over from a source
- Definitive operation history claimable: False

## Segment 50 (gen 1) - renamed_final.txt

- ReferenceCount: 1 | hard-link evidence: False | journal records for file: True
- SI/FN deltas: all exactly 0 ticks
  - FN `renamed_final.txt` delta vs SI (ticks): creation=+0, modification=+0, change=+0, access=+0
- USN events:
  - usn=200 gen=1 2017-11-13T09:03:20.003133700Z [RENAME_OLD_NAME|CLOSE] `renamed_old.txt`
  - usn=208 gen=1 2017-11-13T09:03:20.003133700Z [RENAME_NEW_NAME|CLOSE] `renamed_final.txt`
- [corroborated] Same-volume rename (same segment/generation, only the name changed) — USN RENAME_OLD_NAME / RENAME_NEW_NAME pair
- Definitive operation history claimable: True

## Segment 60 (gen 1) - link_one.dat, link_two.dat

- ReferenceCount: 2 | hard-link evidence: True | journal records for file: True
- SI/FN divergent fields (exact ticks): creation
  - FN `link_one.dat` delta vs SI (ticks): creation=+0, modification=+0, change=+0, access=+0
  - FN `link_two.dat` delta vs SI (ticks): creation=+500008454, modification=+0, change=+0, access=+0
- USN events:
  - usn=300 gen=1 2017-11-13T09:05:00.000900900Z [HARD_LINK_CHANGE|CLOSE] `link_two.dat`
- [confirmed] Multiple directory names reference one MFT record (hard link set) — ReferenceCount=2, 2 $FILE_NAME attributes
- [corroborated] A hard link was added while the journal was recording — USN HARD_LINK_CHANGE present for the current generation
- Definitive operation history claimable: True

## Segment 70 (gen 1) - stomped.xlsx

- ReferenceCount: 1 | hard-link evidence: False | journal records for file: False
- SI/FN divergent fields (exact ticks): access, change, creation, modification
  - FN `stomped.xlsx` delta vs SI (ticks): creation=+1220296000004242, modification=+1219432100000000, change=-900808080, access=+1218568100000000
- USN events: none available for this record
- [inconclusive] SI/FN divergence present, but no journal evidence is available — Copy/restore, hard-link bookkeeping and manual timestamp edits all produce divergence; the on-disk record alone cannot separate them
- Definitive operation history claimable: False

## Segment 80 (gen 2) - reused_now.csv

- ReferenceCount: 1 | hard-link evidence: False | journal records for file: True
- SI/FN deltas: all exactly 0 ticks
  - FN `reused_now.csv` delta vs SI (ticks): creation=+0, modification=+0, change=+0, access=+0
- USN events:
  - usn=800 gen=2 2017-11-13T09:13:20.000007700Z [FILE_CREATE|CLOSE] `reused_now.csv`
  - usn=600 gen=1 2017-11-13T09:10:00.000000000Z [FILE_CREATE|CLOSE] `deleted_then.csv`
  - usn=700 gen=1 2017-11-13T09:11:40.000001100Z [FILE_DELETE|CLOSE] `deleted_then.csv`
- GENERATION ALERT: USN 600 names generation 1 but segment now holds generation 2 (name in journal: deleted_then.csv; reasons: FILE_CREATE|CLOSE)
- GENERATION ALERT: USN 700 names generation 1 but segment now holds generation 2 (name in journal: deleted_then.csv; reasons: FILE_DELETE|CLOSE)
- [confirmed] MFT slot was deleted and reused; stale journal events predate the current file — hard generation mismatch on the same segment
- Definitive operation history claimable: True
