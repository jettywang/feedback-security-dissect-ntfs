# NTFS 时间戳诊断实验（基于 dissect.ntfs，可复算）

本实验**不接触任何真实磁盘**。它用 `dissect.ntfs.c_ntfs` 的同一套 cstruct 定义，
手工构造出与磁盘布局一致的合成 `$MFT` 文件记录（含多扇区 fixup）和 USN v2 日志记录，
然后用 dissect.ntfs 的**真实解析器**（`Mft` / `MftRecord` / `UsnJrnl`）把字节读回，
再做时间戳、引用世代与 USN 事件的交叉诊断。

## 核心立场

- `$STANDARD_INFORMATION`（SI）与 `$FILE_NAME`（FN）时间不一致，**本身不是篡改证据**。
  复制/还原、硬链接、重命名、卷内移动、手工改时间等都会造成不同形态的差异。
- 全程保留 Windows FILETIME 的原始 **100ns tick 整数**。所有比较都在整数 tick 上进行；
  格式化成 ISO 字符串仅用于展示，**绝不参与判定**，因此格式化丢精度不会被当成异常。
- USN 日志缺失或不含相关事件时，只输出**竞争性假设**，不推断确定的操作历史。
- 文件引用 = 段号（segment）+ 世代号（sequence/generation）。同一段号世代不同，
  说明该 MFT 槽位被删除后重用，旧日志事件不能归属到当前文件。

## 目录结构

- `ntfs_timestamp_lab/ntfs_builder.py` — 底层字节构造（tick 时钟、文件引用、驻留属性、fixup、USN v2）
- `ntfs_timestamp_lab/scenarios.py` — 五个受控场景的确定性声明（固定 tick 与 USN 事件）
- `ntfs_timestamp_lab/build_dataset.py` — 序列化成合成 `$MFT` 与两版 `$J`，并自检可被 dissect 解析
- `ntfs_timestamp_lab/report.py` — 用 dissect 解析回字节，做 SI/FN/世代/USN 交叉分析与时间线
- `tests/test_timestamp_lab.py` — 锁定关键不变量的 pytest 用例
- `ntfs_timestamp_lab/output/` — 生成的合成记录、日志、JSON/Markdown 报告与统一时间线

## 复算方法

```bash
# 生成全部产物与报告（输出到 ntfs_timestamp_lab/output/）
.venv/bin/python -m experiment.ntfs_timestamp_lab

# 自定义输出目录
.venv/bin/python -m experiment.ntfs_timestamp_lab --output /path/to/out

# 跑测试
.venv/bin/python -m pytest experiment/tests/ -q
```

所有输入常量固定（锚点时间 `2017-11-13T09:00:00Z`），重复运行产出**字节完全一致**的文件。

## 五个场景与预期证据

| 段号 | 场景 | SI/FN 关系 | 结构性证据 | USN 事件 | 结论强度 |
| --- | --- | --- | --- | --- | --- |
| 40 | 原始文件 | 完全一致 | 单 FN，ReferenceCount=1 | 无 | 无异常 |
| 41 | **合法复制** | SI 继承源文件、FN 在复制时刻重打 → 四项全差异 | 单 FN | `FILE_CREATE\|CLOSE` | 佐证（非篡改） |
| 50 | 重命名 | SI/FN 仍完全一致 | 同段同世代，仅名字变 | `RENAME_OLD_NAME` + `RENAME_NEW_NAME` | 佐证 |
| 60 | 硬链接 | 共享 SI，第二个 FN 的 creation 更新 | **ReferenceCount=2、两个 FN** | `HARD_LINK_CHANGE` | **结构确认** |
| 70 | 手工改 SI（timestomp） | SI 被回溯到 2014，FN 保留真实 2017；SI.ChangeTime 仍是真实时刻 | 单 FN | 完整日志含 `BASIC_INFO_CHANGE`；缺失日志则无事件 | 完整=佐证且**不证明意图**；缺日志=**不可定论** |
| 80 | 段删除后重用 | 当前记录 SI/FN 一致 | 当前世代=2 | 旧事件命名世代 1（`FILE_DELETE`） | **世代错配，结构确认** |

### 至少一种合法操作造成差异
场景 41（复制）：资源管理器风格的“保留元数据复制”会把源文件的 SI 原样带到新文件，
而新 MFT 记录的 FN 由文件系统在复制时刻重新生成。四项时间出现大到数天/数年、
小到亚微秒的差异，但这是**预期行为**，不是篡改。

### 一种只有额外证据才能缩小解释范围的情况
场景 70 在 `usnjrnl_gap.bin` 下：与该文件相关的 USN 事件被整体移除。
此时磁盘记录只呈现“SI 被回溯、FN 较新”的差异，而复制/还原、硬链接簿记、
手工改时间都能产生类似形态。分析器据此**拒绝**给出确定操作历史，只列竞争性假设。
只有补回 USN（看到当前世代的 `BASIC_INFO_CHANGE`）等额外证据，才能把范围收敛到
“通过 `SetFileInformationByHandle` 改过 SI”，但 USN 不记录写入的目标时间值，
因此即便如此也**不能证明主观篡改意图**。

## 证据边界（何时能下确定结论）

- **可结构确认**：硬链接（ReferenceCount / 多 FN）、世代错配（段号相同但 sequence 不同）、SI/FN 完全一致。
- **仅能佐证**：依赖 USN reason 的复制、重命名、BASIC_INFO_CHANGE——日志给出“发生过某类操作”，
  不给出参数值与意图。
- **不可定论**：存在 SI/FN 差异但缺少该文件当前世代的任何日志事件。

## 产物清单（`output/`）

- `synthetic_mft.bin` — 1024 字节/记录的合成 MFT，记录位于 `段号 * 1024`
- `usnjrnl_full.bin` / `usnjrnl_gap.bin` — 完整日志 / 移除 timestomp 事件的日志
- `analysis_full.md`、`analysis_gap.md` — 两版人类可读分析（含精确 tick 差值与世代告警）
- `analysis_full.json`、`analysis_gap.json` — 机器可读结果
- `timeline.md` — 按原始 tick 排序的 SI/FN/USN 统一时间线（保留 100ns 小数位）
- `manifest.json` — 场景与段号布局说明
