# NTFS 重解析点离线解释设计（取证展示层）

本设计基于 `dissect.ntfs` 已有的结构定义（`c_ntfs.IO_REPARSE_TAG`、
`REPARSE_DATA_BUFFER`、`SYMBOLIC_LINK_REPARSE_BUFFER`、
`MOUNT_POINT_REPARSE_BUFFER`）与 `attr.ReparsePoint` 属性解析器，新增一个
**纯离线、不跳转、不访问宿主文件系统** 的解释子包 `dissect.ntfs.reparse`。

## 1. 设计目标与硬边界

- 只解释调用方传入的字节或已解析的 `ReparsePoint` 属性，不接收宿主路径。
- 不调用任何 `open`/`stat`/`os.path` 真实解析，不实现文件跳转或同步工具。
- 所有从镜像读出的字符串都携带字节区间证据，可回溯到 `$REPARSE_POINT` 属性值。
- 损坏不抛异常中断：长度/偏移越界、UTF-16 异常等降级为 `Notice`，保留部分证据。
- 任何需要镜像外部上下文才能确定的结论，标记为 `CONDITIONAL` 或 `UNRESOLVED`。

## 2. SubstituteName 还是 PrintName

二者语义不同，不能二选一后丢弃另一个：

- `SubstituteName`（替代名称）是对象管理器真正使用的目标，通常带 NT 命名空间前缀
  （`\??\`、`\\?\`、`\\.\`），是**解析权威字段**。
- `PrintName`（打印名称）是创建者写入的人类可读显示串，可能为空、可能与真实目标
  不一致，**不可作为解析依据，也不可默认信任**。

展示规则（见 `ReparseInterpretation.display_value`）：

1. `PrintName` 存在且非空时优先展示，但同时给出 `name_consistent` 与候选列表。
2. `PrintName` 为空或不可读时回退展示 `SubstituteName`。
3. 两者不一致时产生 `print_substitute_mismatch` 警告，界面须显式提示展示名可能误导。

## 3. 离线结构分类规则

`classify_path` 仅依据文本结构判定 `PathKind`，不做任何 I/O：

| 形态 | PathKind | 离线结论 |
| --- | --- | --- |
| 符号链接 `Flags=RELATIVE` 且无前缀 | `RELATIVE` | 锚定镜像内链接父目录，给条件候选 |
| `\??\C:\...` / `\\?\C:\...` | `DOS_DRIVE` | 盘符属客户机，绑定关系离线不可知 |
| `\??\Volume{GUID}\...` | `VOLUME_GUID` | GUID 无法在离线状态绑定卷/盘符 |
| `\??\UNC\srv\share`、`\\srv` | `UNC` | 归一为 `\\srv\share`，跨网络不解析 |
| 带 NT 前缀但非盘符/GUID | `NT_NAMESPACE` | 剥离前缀仅作展示，保留原始候选 |
| 以 `\` 开头的对象路径 | `OBJECT_ROOTED` | 需要镜像 NT 命名空间而非宿主 |
| 空串 | `EMPTY` | 无法定位 |
| 其它 | `OTHER` | 原样保留 |

NT 前缀剥离只产生一个额外的“去前缀”候选，**绝不**把结果交给宿主打点。

## 4. 三类 reparse tag 的处理

### 4.1 符号链接（`IO_REPARSE_TAG.SYMLINK = 0xA000000C`）

- 头部 12 字节：4×`USHORT`（Substitute/Print 的 offset、length）+ `ULONG Flags`。
- `Flags & 1` 决定相对/绝对；相对目标给 `relative_join` 条件候选。

### 4.2 挂载点 / 目录联接（`MOUNT_POINT = 0xA0000003`）

- 头部 8 字节：仅 4×`USHORT`，无 Flags，恒为绝对。
- 常见目标为卷 GUID 或盘符，二者绑定均标记为 `UNRESOLVED`。

### 4.3 未知 reparse tag

- 不依赖固定枚举：用高 32 位标志位分类（`classify_tag`）。
- 置位 name-surrogate 位（`0x20000000`）的未知 tag，按通用四 `USHORT` 布局
  **尽力而为**解析名字对，证据属性标记为 `INFERRED_NAME_SURROGATE_BUFFER`，
  并发 `inferred_name_layout` 警告；`relative` 保持 `None`。
- 非 name-surrogate（如 `FILTER_MANAGER`、`CLOUD`、`LX_SYMLINK` 等）不臆造名字对，
  仅保留标签分类与原始载荷，发 `tag_not_name_surrogate` 提示。

## 5. 不确定性场景的保留策略

- **嵌套链接**：`plan_chain` 只在调用方提供的内存节点表上逐步规划，记录每一跳
  （`ChainStep`），不做真实跳转。
- **目标跨卷**：卷 GUID / 盘符 / UNC 目标的目标卷与当前卷不同即停止，
  `terminal_reason=CROSS_VOLUME`，保留目标文本与不确定性说明。
- **循环**：用已访问引用集合检测，命中即 `CYCLE`，不无限跟随。
- **深度上限**：默认 `max_depth=8`，超出为 `DEPTH_LIMIT`。
- **元数据长度损坏**：
  - `ReparseDataLength` 超过实际字节 → `reparse_data_length_overflow`，按可用字节解析；
  - 名字 offset 越界 → `OUT_OF_BOUNDS`，文本置空但保留字节区间证据；
  - 名字 length 越界 → `TRUNCATED`，仅解码可读部分；
  - 奇数长度、UTF-16 非法 → 警告并以替换字符解码，状态 `UNDECODABLE`。
- 链路中任一跳出现 error 级通知即 `DAMAGED` 停止，不凭猜测继续。

## 6. 接口方案：展示值 / 解析候选 / 证据来源

核心入口：

- `interpret_reparse_buffer(data: bytes, source: str) -> ReparseInterpretation`
- `interpret_attribute(attr: ReparsePoint, source: str | None) -> ReparseInterpretation`
- `plan_chain(start: ReparseNode, lookup: Callable, max_depth: int) -> ChainReport`

`ReparseInterpretation` 把三类信息显式分离：

1. **展示值**：`display_value`（`DecodedName`），含角色、文本、状态、一致性标记。
2. **解析候选**：`candidates: tuple[ResolutionCandidate, ...]`，每个候选带
   `certainty`（`STRUCTURAL` / `CONDITIONAL` / `UNRESOLVED`）、`requires` 前置条件、
   `uncertainty` 说明；候选是“可如何理解”，不是“去访问哪里”。
3. **证据来源**：每个 `DecodedName` 与头部都带 `Evidence`（source、tag、
   `ByteRange`、属性类型），`evidence_lines()` 输出可审计定位串。

后端渲染建议：默认展示 `display_value`；同屏列出候选及其确定性等级；
对所有 warning/error 通知给出显著标识；提供证据字节区间供下钻。

## 7. 反例：显示名称与真实替代名称不一致

样本 `print_substitute_mismatch`：

- `SubstituteName = \??\Volume{...}\Secret`（真实目标，跨卷 GUID）
- `PrintName = C:\Users\Public\Readme.txt`（看似无害的本地文件）

解释结果：`name_consistent=False`，发出 `print_substitute_mismatch` 警告；
解析权威仍为 SubstituteName（分类 `VOLUME_GUID`、绑定 `UNRESOLVED`），
PrintName 仅作为一个 `CONDITIONAL` 展示候选保留。该反例用于证明
“只显示 PrintName”会掩盖真实跨卷指向。

## 8. 本地结构样本

`samples.all_samples()` 提供 12 个内存字节样本，覆盖：绝对盘符符号链接、
相对符号链接、卷 GUID 挂载点、盘符挂载点、UNC、显示/替代不一致、空 PrintName、
声明长度溢出、名字偏移越界、未知 name-surrogate、过滤管理器不透明载荷、LX 符号链接。

- 演示：`python examples/reparse_overview.py`
- 测试：`pytest tests/reparse/`

## 9. 明确不做的事

- 不把镜像内路径提交给宿主操作系统解析。
- 不自动跟随嵌套链接、不解析卷 GUID/盘符到宿主设备。
- 不提供文件读取、拷贝、同步或任何写操作能力。
- 对无法证明的绑定只输出 `UNRESOLVED` 候选与所需前置证据，由人工研判。
